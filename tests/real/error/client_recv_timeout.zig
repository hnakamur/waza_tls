const std = @import("std");
const os = std.os;
const time = std.time;

const datetime = @import("datetime");
const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

test "real / error / client recv timeout" {
    // testing.log_level = .debug;
    const content = "Hello from http.Server\n";

    try struct {
        const Context = @This();
        const Client = http.Client(Context);
        const Server = http.Server(Context, Handler);

        const Handler = struct {
            const send_delay: u63 = 100 * time.ns_per_ms;

            conn: *Server.Conn = undefined,

            pub fn start(self: *Handler) void {
                self.conn.recvRequestHeader(recvRequestHeaderCallback);
            }

            pub fn recvRequestHeaderCallback(self: *Handler, result: Server.RecvRequestHeaderError!usize) void {
                if (result) |_| {
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponseAfterDelay();
                } else |err| {
                    std.log.err("Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                }
            }

            pub fn recvRequestContentFragmentCallback(self: *Handler, result: Server.RecvRequestContentFragmentError!usize) void {
                if (result) |_| {
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponseAfterDelay();
                } else |err| {
                    std.log.err("Handler.recvRequestContentFragmentCallback err={s}", .{@errorName(err)});
                }
            }

            fn sendResponseAfterDelay(self: *Handler) void {
                self.conn.server.io.timeout(
                    *Handler,
                    self,
                    timeoutCallback,
                    &self.conn.completion.linked_completion.main_completion,
                    send_delay,
                );
            }
            fn timeoutCallback(
                self: *Handler,
                completion: *IO.Completion,
                result: IO.TimeoutError!void,
            ) void {
                if (result) |_| {
                    self.sendResponse();
                } else |err| {
                    std.log.err("Handler.timeoutCallback err={s}", .{@errorName(err)});
                }
            }

            pub fn sendResponse(self: *Handler) void {
                var fbs = std.io.fixedBufferStream(self.conn.send_buf);
                var w = fbs.writer();
                std.fmt.format(w, "{s} {d} {s}\r\n", .{
                    http.Version.http1_1.toBytes(),
                    http.StatusCode.ok.code(),
                    http.StatusCode.ok.toText(),
                }) catch unreachable;
                http.writeDatetimeHeader(w, "Date", datetime.datetime.Datetime.now()) catch unreachable;

                switch (self.conn.request.version) {
                    .http1_1 => if (!self.conn.keep_alive) {
                        std.fmt.format(w, "Connection: {s}\r\n", .{"close"}) catch unreachable;
                    },
                    .http1_0 => if (self.conn.keep_alive) {
                        std.fmt.format(w, "Connection: {s}\r\n", .{"keep-alive"}) catch unreachable;
                    },
                    else => {},
                }
                const content_length = content.len;
                std.fmt.format(w, "Content-Length: {d}\r\n", .{content_length}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
                std.fmt.format(w, "{s}", .{content}) catch unreachable;
                self.conn.sendFull(fbs.getWritten(), sendFullCallback);
            }

            fn sendFullCallback(self: *Handler, last_result: IO.SendError!usize) void {
                if (last_result) |_| {
                    self.conn.finishSend();
                } else |err| {
                    std.log.err("Handler.sendFullCallback err={s}", .{@errorName(err)});
                }
            }
        };

        server: Server = undefined,
        client: Client = undefined,
        buffer: std.fifo.LinearFifo(u8, .Dynamic),
        connect_result: IO.ConnectError!void = undefined,
        send_len: usize = undefined,
        sent_len: usize = undefined,
        recv_resp_header_result: Client.RecvResponseHeaderError!usize = undefined,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            self.connect_result = result;
            if (result) |_| {
                var w = self.buffer.writer();
                std.fmt.format(w, "{s} {s} {s}\r\n", .{
                    (http.Method{ .get = undefined }).toBytes(),
                    "/",
                    http.Version.http1_1.toBytes(),
                }) catch unreachable;
                std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;
                self.send_len = self.buffer.readableSlice(0).len;
                self.client.sendFull(self.buffer.readableSlice(0), sendFullCallback);
            } else |_| {
                self.exitTest();
            }
        }
        fn sendFullCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            self.sent_len = self.client.completion.processed_len;
            if (result) |_| {
                self.client.recvResponseHeader(recvResponseHeaderCallback);
            } else |_| {
                self.exitTest();
            }
        }
        fn recvResponseHeaderCallback(
            self: *Context,
            result: Client.RecvResponseHeaderError!usize,
        ) void {
            self.recv_resp_header_result = result;
            if (result) |_| {
                self.client.close();
                self.exitTest();
            } else |_| {
                self.exitTest();
            }
        }

        fn exitTest(self: *Context) void {
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
            };
            defer self.buffer.deinit();

            self.server = try Server.init(allocator, &io, &self, address, .{});
            defer self.server.deinit();

            self.client = try Client.init(allocator, &io, &self, &.{
                .recv_timeout_ns = 50 * time.ns_per_ms,
            });
            defer self.client.deinit();

            try self.server.start();

            try self.client.connect(self.server.bound_address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            try testing.expectEqual(@as(IO.ConnectError!void, {}), self.connect_result);
            try testing.expectEqual(self.send_len, self.sent_len);
            try testing.expectError(error.Canceled, self.recv_resp_header_result);
        }
    }.runTest();
}
