const std = @import("std");
const os = std.os;
const time = std.time;

const datetime = @import("datetime");
const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;
const iptables = @import("iptables.zig");

test "real / error / drop server recv" {
    // testing.log_level = .debug;

    const dest_addr = "127.0.0.1";
    const dest_port = 3131;
    const content = "Hello from http.Server\n";

    try struct {
        const Context = @This();
        const Client = http.Client(Context);
        const Server = http.Server(Context, Handler);

        const Handler = struct {
            conn: *Server.Conn = undefined,
            recv_req_header_result: Server.RecvRequestHeaderError!usize = undefined,

            pub fn start(self: *Handler) void {
                std.log.debug("Handler.start start", .{});
                defer std.log.debug("Handler.start exit", .{});

                const allocator = testing.allocator;
                iptables.appendRule(allocator, dest_addr, dest_port, .drop) catch @panic("append iptables rule");
                std.log.debug("Handler.start appended iptables rule", .{});

                self.conn.recvRequestHeader(recvRequestHeaderCallback);
            }

            pub fn recvRequestHeaderCallback(self: *Handler, result: Server.RecvRequestHeaderError!usize) void {
                testing.expectError(error.Canceled, result) catch |err| {
                    std.log.err("Handler.recvRequestHeaderCallback result should be error.Canceled, but got {}", .{result});
                };
                if (result) |received| {
                    std.log.debug("Handler.recvRequestHeaderCallback received={}", .{received});
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponse();
                } else |err| {
                    if (err != error.Canceled) {
                        std.log.err("Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                    } else {
                        std.log.debug("Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                    }
                }
            }

            pub fn recvRequestContentFragmentCallback(self: *Handler, result: Server.RecvRequestContentFragmentError!usize) void {
                if (result) |received| {
                    std.log.debug("Handler.recvRequestContentFragmentCallback received={}", .{received});
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponse();
                } else |err| {
                    std.log.err("Handler.recvRequestContentFragmentCallback err={s}", .{@errorName(err)});
                }
            }

            pub fn sendResponse(self: *Handler) void {
                std.log.debug("Handler.sendResponse start", .{});
                defer std.log.debug("Handler.sendResponse exit", .{});

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
                std.log.debug("Handler.sendFullCallback start, last_result={}", .{last_result});
                defer std.log.debug("Handler.sendFullCallback exit", .{});

                if (last_result) |_| {
                    self.conn.finishSend();
                } else |err| {
                    std.log.err("Handler.sendFullCallback err={s}", .{@errorName(err)});
                }
            }
        };

        client: Client = undefined,
        buffer: std.fifo.LinearFifo(u8, .Dynamic),
        content_read_so_far: u64 = undefined,
        server: Server = undefined,
        connect_result: IO.ConnectError!void = undefined,
        sent_len: usize = undefined,
        send_result: IO.SendError!usize = undefined,
        response_content_length: ?u64 = null,
        received_content: ?[]const u8 = null,
        test_error: ?anyerror = null,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            std.log.debug("Context.connectCallback result={}", .{result});
            self.connect_result = result;
            if (result) |_| {
                var w = self.buffer.writer();
                std.fmt.format(w, "{s} {s} {s}\r\n", .{
                    (http.Method{ .get = undefined }).toBytes(),
                    "/",
                    http.Version.http1_1.toBytes(),
                }) catch unreachable;
                std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;
                self.sent_len = self.buffer.readableSlice(0).len;
                self.client.sendFull(self.buffer.readableSlice(0), sendFullCallback);
                std.log.debug("Context.connectCallback after sendFull", .{});
            } else |err| {
                std.log.err("Context.connectCallback err={s}", .{@errorName(err)});
                self.exitTest();
                std.log.debug("Context.connectCallback exit", .{});
            }
        }
        fn sendFullCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            self.send_result = result;
            if (result) |sent| {
                std.log.debug("Context.sendFullCallback sent={}", .{sent});
                self.client.close();
                self.exitTest();
            } else |err| {
                std.log.err("Context.sendFullCallback err={s}", .{@errorName(err)});
                self.exitTest();
                std.log.debug("Context.sendFullCallback exit", .{});
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
            };
            defer self.buffer.deinit();

            self.server = try Server.init(allocator, &io, &self, address, .{
                .recv_timeout_ns = time.ns_per_s,
                .send_timeout_ns = time.ns_per_s,
            });
            defer self.server.deinit();

            self.client = try Client.init(allocator, &io, &self, &.{
                .connect_timeout_ns = 100 * time.ns_per_ms,
                .recv_timeout_ns = 100 * time.ns_per_ms,
                .send_timeout_ns = 100 * time.ns_per_ms,
            });
            defer self.client.deinit();
            std.log.debug("server=0x{x}, completion=0x{x}", .{
                @ptrToInt(&self.server),
                @ptrToInt(&self.server.completion),
            });
            std.log.debug("client=0x{x}, main_completion=0x{x}, linked_completion=0x{x}", .{
                @ptrToInt(&self.client),
                @ptrToInt(&self.client.completion.linked_completion.main_completion),
                @ptrToInt(&self.client.completion.linked_completion.linked_completion),
            });

            try self.server.start();
            try self.client.connect(address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            if (self.connect_result) |_| {} else |err| {
                std.debug.print("connect_result should be void, but got error: {s}\n", .{@errorName(err)});
                return error.TestExpectedError;
            }
            try testing.expectEqual(@as(IO.SendError!usize, self.sent_len), self.send_result);
        }
    }.runTest();
}
