const std = @import("std");
const os = std.os;
const time = std.time;

const datetime = @import("datetime");
const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;
// const iptables = @import("iptables.zig");

test "real / error / client recv timeout" {
    // testing.log_level = .debug;
    const content = "Hello from http.Server\n";

    const Handler = struct {
        const Self = @This();
        pub const Server = http.Server(Self);

        const send_delay: u63 = 100 * time.ns_per_ms;

        conn: *Server.Conn = undefined,

        pub fn start(self: *Self) void {
            std.log.debug("Handler.start", .{});
            self.conn.recvRequestHeader(recvRequestHeaderCallback);
        }

        pub fn recvRequestHeaderCallback(self: *Self, result: Server.RecvRequestHeaderError!usize) void {
            std.log.debug("Handler.recvRequestHeaderCallback start, result={}", .{result});
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

        pub fn recvRequestContentFragmentCallback(self: *Self, result: Server.RecvRequestContentFragmentError!usize) void {
            std.log.debug("Handler.recvRequestContentFragmentCallback start, result={}", .{result});
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

        fn sendResponseAfterDelay(self: *Self) void {
            self.conn.server.io.timeout(
                *Self,
                self,
                timeoutCallback,
                &self.conn.completion.linked_completion.main_completion,
                send_delay,
            );
        }
        fn timeoutCallback(
            self: *Self,
            completion: *IO.Completion,
            result: IO.TimeoutError!void,
        ) void {
            if (result) |_| {
                std.log.debug("timeoutCallback result ok", .{});
                self.sendResponse();
            } else |err| {
                std.log.err("Handler.timeoutCallback err={s}", .{@errorName(err)});
            }
        }

        pub fn sendResponse(self: *Self) void {
            std.log.debug("Handler.sendResponse start", .{});
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

        fn sendFullCallback(self: *Self, last_result: IO.SendError!usize) void {
            std.log.debug("Handler.sendFullCallback start, last_result={}", .{last_result});
            if (last_result) |_| {
                self.conn.finishSend();
            } else |err| {
                std.log.err("Handler.sendFullCallback err={s}", .{@errorName(err)});
            }
        }
    };

    try struct {
        const Context = @This();
        const Client = http.Client(Context);

        client: Client = undefined,
        buffer: std.fifo.LinearFifo(u8, .Dynamic),
        server: Handler.Server = undefined,
        connect_result: IO.ConnectError!void = undefined,
        send_result: IO.SendError!usize = undefined,
        recv_resp_header_result: Client.RecvResponseHeaderError!usize = undefined,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            self.connect_result = result;
            if (result) |_| {
                var w = self.buffer.writer();
                std.fmt.format(w, "{s} {s} {s}\r\n", .{
                    (http.Method{ .get = undefined }).toText(),
                    "/",
                    // "/" ++ "a" ** 8192,
                    http.Version.http1_1.toText(),
                }) catch unreachable;
                std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;
                self.client.sendFull(self.buffer.readableSlice(0), sendFullCallback);
            } else |_| {
                self.exitTest();
            }
        }
        fn sendFullCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            self.send_result = result;
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
                .server = try Handler.Server.init(allocator, &io, address, .{}),
            };
            defer self.buffer.deinit();
            defer self.server.deinit();

            self.client = try Client.init(allocator, &io, &self, &.{
                .recv_timeout_ns = 50 * time.ns_per_ms,
            });
            defer self.client.deinit();

            try self.server.start();

            // const dest_port = self.server.bound_address.getPort();
            // const dest_addr = "127.0.0.1";
            // try iptables.appendRule(allocator, dest_addr, dest_port, .reject);
            // defer iptables.deleteRule(allocator, dest_addr, dest_port, .reject) catch @panic("delete iptables rule");

            try self.client.connect(self.server.bound_address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            try http.testing.expectNoError(self.connect_result);
            try http.testing.expectNoError(self.send_result);
            try testing.expectError(error.Canceled, self.recv_resp_header_result);
        }
    }.runTest();
}
