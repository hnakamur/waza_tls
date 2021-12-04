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

test "real / error / server alloc fail case2" {
    testing.log_level = .warn;

    try struct {
        const Context = @This();
        const Client = http.Client(Context);
        const Server = http.Server(Context, Handler);

        const Handler = struct {
            conn: *Server.Conn = undefined,

            pub fn start(self: *Handler) void {
                std.log.debug("Handler.start", .{});
                self.conn.recvRequestHeader(recvRequestHeaderCallback);
            }

            pub fn recvRequestHeaderCallback(self: *Handler, result: Server.RecvRequestHeaderError!usize) void {
                std.log.info("Handler.recvRequestHeaderCallback start, result={}", .{result});
                if (result) |_| {
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponse();
                } else |err| {
                    if (err != error.OutOfMemory) {
                        std.log.err("Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                    }
                }
            }

            pub fn recvRequestContentFragmentCallback(self: *Handler, result: Server.RecvRequestContentFragmentError!usize) void {
                std.log.debug("Handler.recvRequestContentFragmentCallback start, result={}", .{result});
                if (result) |_| {
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponse();
                } else |err| {
                    if (err != error.OutOfMemory) {
                        std.log.err("Handler.recvRequestContentFragmentCallback expected OutOfMemory, found err={s}", .{@errorName(err)});
                    }
                }
            }

            pub fn sendResponse(self: *Handler) void {
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

            fn sendHeaderCallback(self: *Handler, last_result: IO.SendError!usize) void {
                std.log.debug("Handler.sendHeaderCallback start, last_result={}", .{last_result});
                if (last_result) |_| {
                    self.conn.finishSend();
                } else |err| {
                    std.log.err("Handler.sendHeaderCallback err={s}", .{@errorName(err)});
                }
            }
        };

        const req_content_repeat = 2;
        const req_content = "Hello";

        server: Server = undefined,
        client: Client = undefined,
        allocator: *mem.Allocator = undefined,
        send_buf: []u8 = undefined,
        send_content_count: usize = 0,
        send_content_result: ?IO.SendError!usize = null,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            std.log.debug("Context.connectCallback start, result={}", .{result});
            if (result) |_| {
                var fbs = std.io.fixedBufferStream(self.send_buf);
                var w = fbs.writer();
                std.fmt.format(w, "{s} {s} {s}\r\n", .{
                    (http.Method{ .get = undefined }).toBytes(),
                    "/",
                    http.Version.http1_1.toBytes(),
                }) catch unreachable;
                std.fmt.format(w, "Host: example.com\r\n", .{}) catch unreachable;
                std.fmt.format(w, "Content-Length: {}\r\n", .{req_content.len * req_content_repeat}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
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
                self.sendContent();
            } else |err| {
                std.log.err("Context.sendFullCallback err={s}", .{@errorName(err)});
                self.exitTest();
            }
        }
        fn sendContent(
            self: *Context,
        ) void {
            var fbs = std.io.fixedBufferStream(self.send_buf);
            var w = fbs.writer();
            std.fmt.format(w, "{s}", .{req_content}) catch unreachable;
            self.client.sendFull(fbs.getWritten(), sendContentCallback);
        }
        fn sendContentCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            std.log.info("Context.sendContentCallback start, result={}", .{result});
            self.send_content_result = result;
            if (result) |_| {
                self.send_content_count += 1;
                if (self.send_content_count == req_content_repeat) {
                    self.client.recvResponseHeader(recvResponseHeaderCallback);
                } else {
                    self.sendContent();
                }
            } else |err| {
                if (err == error.ConnectionResetByPeer) {
                    // We use std.log.warn here for running all tests for test coverage.
                    // If we use std.log.err, not all tests are run and we got very low coverage.
                    std.log.warn("Context.sendFullCallback got error.ConnectionResetByPeer, maybe we should improve server error handling.", .{});
                } else {
                    std.log.err("Context.sendContentCallback err={s}", .{@errorName(err)});
                }
                self.exitTest();
            }
        }
        fn recvResponseHeaderCallback(
            self: *Context,
            result: Client.RecvResponseHeaderError!usize,
        ) void {
            std.log.info("Context.recvResponseHeaderCallback start, result={}", .{result});
            if (result) |_| {
                if (!self.client.fullyReadResponseContent()) {
                    self.client.recvResponseContentFragment(recvResponseContentFragmentCallback);
                    return;
                }

                std.log.info("Context.recvResponseHeaderCallback before calling self.client.close", .{});
                self.client.close();
                self.exitTest();
            } else |err| {
                std.log.err("recvResponseHeaderCallback err={s}", .{@errorName(err)});
                self.exitTest();
            }
        }
        fn recvResponseContentFragmentCallback(
            self: *Context,
            result: Client.RecvResponseContentFragmentError!usize,
        ) void {
            std.log.debug("Context.recvResponseContentFragmentCallback start, result={}", .{result});
            if (result) |_| {
                if (!self.client.fullyReadResponseContent()) {
                    self.client.recvResponseContentFragment(recvResponseContentFragmentCallback);
                    return;
                }

                std.log.info("Context.recvResponseContentFragmentCallback before calling self.client.close", .{});
                self.client.close();
                self.exitTest();
            } else |err| {
                std.log.err("recvResponseContentFragmentCallback err={s}", .{@errorName(err)});
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

            const failing_allocator = &testing.FailingAllocator.init(allocator, 4).allocator;

            var self: Context = .{
                .allocator = allocator,
                .send_buf = try allocator.alloc(u8, 4096),
            };
            defer allocator.free(self.send_buf);

            self.server = try Server.init(failing_allocator, &io, &self, address, .{
                .response_buf_len = 4096,
            });
            defer self.server.deinit();

            self.client = try Client.init(allocator, &io, &self, &.{
                .response_content_fragment_buf_len = 4096,
            });
            defer self.client.deinit();

            try self.server.start();
            try self.client.connect(self.server.bound_address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            try testing.expectError(error.ConnectionResetByPeer, self.send_content_result.?);
        }
    }.runTest();
}
