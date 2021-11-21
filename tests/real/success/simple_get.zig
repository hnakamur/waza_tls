const std = @import("std");
const os = std.os;
const time = std.time;

const datetime = @import("datetime");
const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

test "real / simple get" {
    const content = "Hello from http.Server\n";

    const Handler = struct {
        const Self = @This();
        pub const Svr = http.Server(Self);

        conn: *Svr.Conn = undefined,

        pub fn handleRequestHeaders(self: *Self, req: *http.RecvRequest) !void {}

        pub fn handleRequestBodyFragment(self: *Self, body_fragment: []const u8, is_last_fragment: bool) !void {
            if (!is_last_fragment) {
                return;
            }

            var fbs = std.io.fixedBufferStream(self.conn.send_buf);
            var w = fbs.writer();
            std.fmt.format(w, "{s} {d} {s}\r\n", .{
                http.Version.http1_1.toText(),
                http.StatusCode.ok.code(),
                http.StatusCode.ok.toText(),
            }) catch unreachable;
            http.writeDatetimeHeader(w, "Date", datetime.datetime.Datetime.now()) catch unreachable;

            switch (self.conn.request.version) {
                .http1_1 => if (!self.conn.keep_alive) {
                    try std.fmt.format(w, "Connection: {s}\r\n", .{"close"});
                },
                .http1_0 => if (self.conn.keep_alive) {
                    try std.fmt.format(w, "Connection: {s}\r\n", .{"keep-alive"});
                },
                else => {},
            }
            const content_length = content.len;
            try std.fmt.format(w, "Content-Length: {d}\r\n", .{content_length});
            try std.fmt.format(w, "\r\n", .{});
            try std.fmt.format(w, "{s}", .{content});
            self.conn.sendFullWithTimeout(
                sendFullWithTimeoutCallback,
                fbs.getWritten(),
                5 * time.ms_per_s,
            );
        }

        fn sendFullWithTimeoutCallback(self: *Self, comp: *Svr.Completion, last_result: IO.SendError!usize) void {
            if (last_result) |_| {} else |err| {
                std.debug.print("Handler.sendFullWithTimeoutCallback err={s}\n", .{@errorName(err)});
            }
        }
    };

    try struct {
        const Context = @This();
        const response_header_max_len = 4096;

        client: http.Client,
        buffer: http.DynamicByteBuffer,
        completion: http.Client.Completion = undefined,
        content_read_so_far: u64 = undefined,
        recv_timeout_ns: u63 = 5 * time.ns_per_s,
        server: Handler.Svr = undefined,
        received_content_length: u64 = undefined,
        received_content: []const u8 = undefined,
        test_error: ?anyerror = null,

        fn connectCallback(
            self: *Context,
            completion: *http.Client.Completion,
            result: IO.ConnectError!void,
        ) void {
            var w = self.buffer.writer();
            std.fmt.format(w, "{s} {s} {s}\r\n", .{
                (http.Method{ .get = undefined }).toText(),
                "/",
                // "/" ++ "a" ** 8192,
                http.Version.http1_1.toText(),
            }) catch unreachable;
            std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;
            self.client.sendFullWithTimeout(
                *Context,
                self,
                sendCallback,
                &self.completion,
                &self.buffer,
                500 * time.ns_per_ms,
            );
        }
        fn sendCallback(
            self: *Context,
            completion: *http.Client.Completion,
            result: IO.SendError!usize,
        ) void {
            if (result) |_| {
                self.buffer.head = 0;
                self.buffer.count = 0;
                self.buffer.ensureCapacity(1024) catch unreachable;
                self.client.recvResponseHeader(
                    *Context,
                    self,
                    recvResponseHeaderCallback,
                    &self.completion,
                    &self.buffer,
                    response_header_max_len,
                    self.recv_timeout_ns,
                );
            } else |_| {}
        }
        fn recvResponseHeaderCallback(
            self: *Context,
            completion: *http.Client.Completion,
            result: http.Client.RecvResponseHeaderError!usize,
        ) void {
            if (result) |received| {
                const resp = completion.response;
                if (resp.headers.getContentLength()) |len| {
                    if (len) |l| {
                        self.received_content_length = l;
                    } else {
                        std.debug.print("expected content-length header in response, found none\n", .{});
                        self.client.close();
                        self.exitTestWithError(error.TestUnexpectedError);
                        return;
                    }
                } else |err| {
                    std.debug.print("failed to get content-length header in response, err={s}\n", .{@errorName(err)});
                    self.client.close();
                    self.exitTestWithError(error.TestUnexpectedError);
                    return;
                }

                const chunk = completion.buffer.readableSlice(0);
                self.received_content = chunk;
                if (chunk.len < self.received_content_length) {
                    self.content_read_so_far = chunk.len;
                    self.buffer.head = 0;
                    self.buffer.count = 0;
                    self.client.recvWithTimeout(
                        *Context,
                        self,
                        recvCallback,
                        &self.completion,
                        &self.buffer,
                        self.recv_timeout_ns,
                    );
                    return;
                }

                self.client.close();
                self.exitTest();
            } else |err| {
                std.debug.print("recvResponseHeaderCallback err={s}\n", .{@errorName(err)});
            }
        }
        fn recvCallback(
            self: *Context,
            completion: *http.Client.Completion,
            result: IO.RecvError!usize,
        ) void {
            if (result) |received| {
                self.content_read_so_far += received;
                if (self.content_read_so_far < self.received_content_length) {
                    self.buffer.head = 0;
                    self.buffer.count = 0;
                    self.client.recvWithTimeout(
                        *Context,
                        self,
                        recvCallback,
                        &self.completion,
                        &self.buffer,
                        self.recv_timeout_ns,
                    );
                    return;
                }

                self.client.close();
                self.exitTest();
            } else |err| {
                std.debug.print("recvCallback err={s}\n", .{@errorName(err)});
                self.exitTestWithError(error.TestUnexpectedError);
            }
        }

        fn exitTest(self: *Context) void {
            self.server.requestShutdown();
        }

        fn exitTestWithError(self: *Context, test_error: anyerror) void {
            self.test_error = test_error;
            self.server.requestShutdown();
        }

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const allocator = testing.allocator;
            // Use a random port
            const address = try std.net.Address.parseIp4("127.0.0.1", 0);

            var self: Context = .{
                .client = http.Client.init(&io),
                .buffer = http.DynamicByteBuffer.init(allocator),
                .server = try Handler.Svr.init(allocator, &io, address, .{}),
            };
            defer self.buffer.deinit();
            defer self.server.deinit();

            try self.server.start();

            try self.client.connectWithTimeout(
                *Context,
                &self,
                connectCallback,
                &self.completion,
                self.server.bound_address,
                500 * time.ns_per_ms,
            );

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            if (self.test_error) |err| {
                return err;
            }
            try testing.expectEqual(content.len, self.received_content_length);
            try testing.expectEqualStrings(content, self.received_content);
        }
    }.runTest();
}
