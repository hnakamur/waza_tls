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
        pub const Server = http.Server(Self);

        conn: *Server.Conn = undefined,

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

        fn sendFullWithTimeoutCallback(self: *Self, comp: *Server.Completion, last_result: IO.SendError!usize) void {
            if (last_result) |_| {} else |err| {
                std.debug.print("Handler.sendFullWithTimeoutCallback err={s}\n", .{@errorName(err)});
            }
        }
    };

    try struct {
        const Context = @This();
        const Client = http.Client(Context);

        client: Client = undefined,
        buffer: std.fifo.LinearFifo(u8, .Dynamic),
        content_read_so_far: u64 = undefined,
        server: Handler.Server = undefined,
        received_content_length: u64 = undefined,
        received_content: ?[]const u8 = undefined,
        test_error: ?anyerror = null,

        fn connectCallback(
            self: *Context,
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
            self.client.sendFull(self.buffer.readableSlice(0), sendFullCallback);
        }
        fn sendFullCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            if (result) |_| {
                self.buffer.head = 0;
                self.buffer.count = 0;
                self.buffer.ensureCapacity(1024) catch unreachable;
                self.client.recvResponseHeader(recvResponseHeaderCallback);
            } else |_| {}
        }
        fn recvResponseHeaderCallback(
            self: *Context,
            result: Client.RecvResponseHeaderError!usize,
        ) void {
            if (result) |received| {
                if (self.client.response.headers.getContentLength()) |len| {
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

                self.received_content = self.client.response_body_fragment_buf;
                if (self.received_content) |received_content| {
                    self.content_read_so_far = received_content.len;
                    if (received_content.len < self.received_content_length) {
                        self.client.recvResponseBodyFragment(recvResponseBodyFragmentCallback);
                        return;
                    }
                }

                self.client.close();
                self.exitTest();
            } else |err| {
                std.debug.print("recvResponseHeaderCallback err={s}\n", .{@errorName(err)});
            }
        }
        fn recvResponseBodyFragmentCallback(
            self: *Context,
            result: Client.RecvResponseBodyFragmentError!usize,
        ) void {
            if (result) |received| {
                self.content_read_so_far += received;
                if (self.content_read_so_far < self.received_content_length) {
                    self.client.recvResponseBodyFragment(recvResponseBodyFragmentCallback);
                    return;
                }

                self.client.close();
                self.exitTest();
            } else |err| {
                std.debug.print("recvResponseBodyFragmentCallback err={s}\n", .{@errorName(err)});
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
                .buffer = std.fifo.LinearFifo(u8, .Dynamic).init(allocator),
                .server = try Handler.Server.init(allocator, &io, address, &.{}),
            };
            defer self.buffer.deinit();
            defer self.server.deinit();

            self.client = try Client.init(allocator, &io, &self, &.{});
            defer self.client.deinit();

            try self.server.start();
            try self.client.connect(self.server.bound_address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            if (self.test_error) |err| {
                return err;
            }
            try testing.expectEqual(content.len, self.received_content_length);
            try testing.expectEqualStrings(content, self.received_content.?);
        }
    }.runTest();
}
