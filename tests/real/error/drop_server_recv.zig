const std = @import("std");
const os = std.os;
const time = std.time;

const datetime = @import("datetime");
const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;
const iptables = @import("iptables.zig");

test "real / error / drop server recv" {
    const dest_addr = "127.0.0.1";
    const dest_port = 3131;
    const content = "Hello from http.Server\n";

    const Handler = struct {
        const Self = @This();
        pub const Server = http.Server(Self);

        conn: *Server.Conn = undefined,

        pub fn start(self: *Self) void {
            const allocator = testing.allocator;
            iptables.appendRule(allocator, dest_addr, dest_port, .drop) catch @panic("append iptables rule");

            self.conn.recvRequestHeader(recvRequestHeaderCallback);
        }

        pub fn recvRequestHeaderCallback(self: *Self, result: Server.RecvRequestHeaderError!usize) void {
            if (result) |_| {
                if (!self.conn.fullyReadRequestContent()) {
                    self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                    return;
                }

                self.sendResponse();
            } else |err| {
                std.debug.print("Handler.recvRequestHeaderCallback err={s}\n", .{@errorName(err)});
            }
        }

        pub fn recvRequestContentFragmentCallback(self: *Self, result: Server.RecvRequestContentFragmentError!usize) void {
            if (result) |_| {
                if (!self.conn.fullyReadRequestContent()) {
                    self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                    return;
                }

                self.sendResponse();
            } else |err| {
                std.debug.print("Handler.recvRequestContentFragmentCallback err={s}\n", .{@errorName(err)});
            }
        }

        pub fn sendResponse(self: *Self) void {
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
            if (last_result) |_| {
                self.conn.finishSend();
            } else |err| {
                std.debug.print("Handler.sendFullCallback err={s}\n", .{@errorName(err)});
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
        connect_result: IO.ConnectError!void = undefined,
        response_content_length: ?u64 = null,
        received_content: ?[]const u8 = null,
        test_error: ?anyerror = null,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            std.debug.print("Context.connectCallback result={}\n", .{result});
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
            } else |err| {
                std.debug.print("Context.connectCallback err={s}\n", .{@errorName(err)});
                self.exitTest();
                std.debug.print("Context.connectCallback exit\n", .{});
            }
        }
        fn sendFullCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            if (result) |sent| {
                std.debug.print("Context.sendFullCallback sent={}\n", .{sent});
                self.client.close();
                self.exitTest();
            } else |err| {
                std.debug.print("Context.sendFullCallback err={s}\n", .{@errorName(err)});
                self.exitTest();
                std.debug.print("Context.sendFullCallback exit\n", .{});
            }
        }

        fn exitTest(self: *Context) void {
            self.server.requestShutdown();
        }

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const allocator = testing.allocator;

            defer iptables.deleteRule(allocator, dest_addr, dest_port, .drop) catch @panic("delete iptables rule");

            const address = try std.net.Address.parseIp4(dest_addr, dest_port);

            var self: Context = .{
                .buffer = std.fifo.LinearFifo(u8, .Dynamic).init(allocator),
                .server = try Handler.Server.init(allocator, &io, address, .{}),
            };
            defer self.buffer.deinit();
            defer self.server.deinit();

            self.client = try Client.init(allocator, &io, &self, &.{
                .connect_timeout_ns = 100 * time.ns_per_ms,
                .recv_timeout_ns = 100 * time.ns_per_ms,
                .send_timeout_ns = 100 * time.ns_per_ms,
            });
            defer self.client.deinit();
            std.debug.print("server=0x{x}, completion=0x{x}\n", .{
                @ptrToInt(&self.server),
                @ptrToInt(&self.server.completion),
            });
            std.debug.print("client=0x{x}, main_completion=0x{x}, linked_completion=0x{x}\n", .{
                @ptrToInt(&self.client),
                @ptrToInt(&self.client.completion.linked_completion.main_completion),
                @ptrToInt(&self.client.completion.linked_completion.linked_completion),
            });

            try self.server.start();
            try self.client.connect(address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            std.debug.print("after io.tick loop\n", .{});
            try testing.expectError(error.Canceled, self.connect_result);
        }
    }.runTest();
}
