const std = @import("std");
const os = std.os;
const math = std.math;
const mem = std.mem;
const rand = std.rand;
const time = std.time;

const datetime = @import("datetime");
const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

test "real / error / req content timeout" {
    // testing.log_level = .info;

    const Handler = struct {
        const Self = @This();
        pub const Server = http.Server(Self);

        conn: *Server.Conn = undefined,

        pub fn start(self: *Self) void {
            std.log.debug("Handler.start", .{});
            self.conn.recvRequestHeader(recvRequestHeaderCallback);
        }

        pub fn recvRequestHeaderCallback(self: *Self, result: Server.RecvRequestHeaderError!usize) void {
            std.log.info("Handler.recvRequestHeaderCallback start, result={}", .{result});
            if (result) |_| {
                if (!self.conn.fullyReadRequestContent()) {
                    self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                    return;
                }

                self.sendResponse();
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

                self.sendResponse();
            } else |err| {
                if (err != error.Canceled) {
                    std.log.err("Handler.recvRequestContentFragmentCallback should get error.Canceled, found={s}", .{@errorName(err)});
                }
            }
        }

        pub fn sendResponse(self: *Self) void {
            std.log.debug("Handler.sendResponse start", .{});
            var fbs = std.io.fixedBufferStream(self.conn.send_buf);
            var w = fbs.writer();
            std.fmt.format(w, "{s} {d} {s}\r\n", .{
                http.Version.http1_1.toBytes(),
                http.StatusCode.no_content.code(),
                http.StatusCode.no_content.toText(),
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
            std.fmt.format(w, "\r\n", .{}) catch unreachable;
            self.conn.sendFull(fbs.getWritten(), sendHeaderCallback);
        }

        fn sendHeaderCallback(self: *Self, last_result: IO.SendError!usize) void {
            std.log.debug("Handler.sendHeaderCallback start, last_result={}", .{last_result});
            if (last_result) |_| {
                self.conn.finishSend();
            } else |err| {
                std.log.err("Handler.sendHeaderCallback err={s}", .{@errorName(err)});
            }
        }
    };

    try struct {
        const Context = @This();
        const Client = http.Client(Context);

        server: Handler.Server = undefined,
        client: Client = undefined,
        allocator: *mem.Allocator = undefined,
        send_header_buf: []u8 = undefined,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            std.log.debug("Context.connectCallback start, result={}", .{result});
            if (result) |_| {
                var fbs = std.io.fixedBufferStream(self.send_header_buf);
                var w = fbs.writer();
                std.fmt.format(w, "{s} {s} {s}\r\n", .{
                    (http.Method{ .get = undefined }).toBytes(),
                    "/",
                    http.Version.http1_1.toBytes(),
                }) catch unreachable;
                std.fmt.format(w, "Host: {s}\r\n", .{"example.com"}) catch unreachable;
                std.fmt.format(w, "Content-Length: {d}\r\n", .{100}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
                std.fmt.format(w, "{s}", .{"a" ** 5}) catch unreachable;
                self.client.sendFull(fbs.getWritten(), sendHeaderCallback);
            } else |err| {
                std.log.err("Context.connectCallback err={s}", .{@errorName(err)});
                self.exitTest();
            }
        }
        fn sendHeaderCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            std.log.info("Context.sendHeaderCallback start, result={}", .{result});
            if (result) |_| {
                self.client.io.timeout(
                    *Context,
                    self,
                    timeoutCallback,
                    &self.client.completion.linked_completion.main_completion,
                    200 * time.ns_per_ms,
                );
            } else |err| {
                std.log.err("Context.sendFullCallback err={s}", .{@errorName(err)});
                self.exitTest();
            }
        }

        fn timeoutCallback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.TimeoutError!void,
        ) void {
            if (result) |_| {
                self.client.close();
                self.exitTest();
            } else |err| {
                std.log.err("Context.timeoutCallback err={s}", .{@errorName(err)});
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
                .allocator = allocator,
                .send_header_buf = try allocator.alloc(u8, 8192 * 4),
                .server = try Handler.Server.init(allocator, &io, address, .{
                    .recv_timeout_ns = 100 * time.ns_per_ms,
                }),
            };
            defer allocator.free(self.send_header_buf);
            defer self.server.deinit();

            self.client = try Client.init(allocator, &io, &self, &.{});
            defer self.client.deinit();

            try self.server.start();
            try self.client.connect(self.server.bound_address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }
        }
    }.runTest();
}
