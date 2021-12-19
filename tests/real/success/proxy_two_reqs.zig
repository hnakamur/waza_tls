const std = @import("std");
const os = std.os;
const time = std.time;

const datetime = @import("datetime");
const http = @import("hutaback");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

test "real / success / proxy two reqs" {
    // testing.log_level = .info;
    const content = "Hello from http.OriginServer\n";

    try struct {
        const Context = @This();
        const Client = http.Client(Context);
        const Proxy = http.Proxy(Context);
        const OriginServer = http.Server(Context, Handler);

        const Handler = struct {
            conn: *OriginServer.Conn = undefined,

            pub fn start(self: *Handler) void {
                std.log.debug("OriginServer.Handler.start", .{});
                self.conn.recvRequestHeader(recvRequestHeaderCallback);
            }

            pub fn recvRequestHeaderCallback(self: *Handler, result: OriginServer.RecvRequestHeaderError!usize) void {
                std.log.debug("Handler.recvRequestHeaderCallback start, result={}", .{result});
                if (result) |_| {
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponse();
                } else |err| {
                    if (err == error.Canceled) {
                        std.log.warn("Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                    } else {
                        std.log.err("Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                    }
                }
            }

            pub fn recvRequestContentFragmentCallback(self: *Handler, result: OriginServer.RecvRequestContentFragmentError!usize) void {
                std.log.debug("Handler.recvRequestContentFragmentCallback start, result={}", .{result});
                if (result) |_| {
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
                self.conn.sendFull(fbs.getWritten(), sendResponseCallback);
            }

            fn sendResponseCallback(self: *Handler, last_result: IO.SendError!usize) void {
                std.log.debug("Handler.sendResponseCallback start, last_result={}", .{last_result});
                if (last_result) |_| {
                    self.conn.finishSend();
                    self.conn.server.context.handler_finished = true;
                } else |err| {
                    std.log.err("Handler.sendResponseCallback err={s}", .{@errorName(err)});
                }
            }
        };

        server: OriginServer = undefined,
        proxy: *Proxy = undefined,
        client: Client = undefined,
        buffer: std.fifo.LinearFifo(u8, .Dynamic),
        content_read_so_far: u64 = undefined,
        response_content_length: ?u64 = null,
        received_content: ?[]const u8 = null,
        test_error: ?anyerror = null,
        handler_finished: ?bool = null,
        req_id: usize = 0,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            std.log.debug("Context.connectCallback start, result={}", .{result});
            if (result) |_| {
                self.sendRequest();
            } else |err| {
                std.log.err("Connect.connectCallback err={s}", .{@errorName(err)});
                self.exitTestWithError(err);
            }
        }
        fn sendRequest(
            self: *Context,
        ) void {
            std.log.info("sendRequest", .{});
            var w = self.buffer.writer();
            std.fmt.format(w, "{s} {s} {s}\r\n", .{
                (http.Method{ .get = undefined }).toBytes(),
                "/",
                http.Version.http1_1.toBytes(),
            }) catch unreachable;
            std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;
            self.client.sendFull(self.buffer.readableSlice(0), sendFullCallback);
        }
        fn sendFullCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            std.log.debug("Context.sendFullCallback start, result={}", .{result});
            if (result) |_| {
                self.client.recvResponseHeader(recvResponseHeaderCallback);
            } else |err| {
                std.log.err("Connect.sendFullCallback err={s}", .{@errorName(err)});
                self.exitTestWithError(err);
            }
        }
        fn recvResponseHeaderCallback(
            self: *Context,
            result: Client.RecvResponseHeaderError!usize,
        ) void {
            std.log.debug("Context.recvResponseHeaderCallback start, result={}", .{result});
            if (result) |_| {
                if (self.client.response_content_length) |len| {
                    self.response_content_length = len;
                    if (self.client.resp_hdr_buf_content_fragment) |frag| {
                        self.received_content = frag;
                    }
                }

                if (!self.client.fullyReadResponseContent()) {
                    self.client.recvResponseContentFragment(recvResponseContentFragmentCallback);
                    return;
                }

                if (self.req_id < 1) {
                    self.req_id += 1;
                    self.sendRequest();
                    return;
                }

                std.log.debug("Context.recvResponseHeaderCallback before calling self.client.close", .{});
                self.client.close();
                self.exitTest();
            } else |err| {
                std.log.err("recvResponseHeaderCallback err={s}", .{@errorName(err)});
                self.exitTestWithError(err);
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

                if (self.req_id < 1) {
                    self.req_id += 1;
                    self.sendRequest();
                    return;
                }

                std.log.debug("Context.recvResponseContentFragmentCallback before calling self.client.close", .{});
                self.client.close();
                self.exitTest();
            } else |err| {
                std.log.err("recvResponseContentFragmentCallback err={s}", .{@errorName(err)});
                self.exitTestWithError(err);
            }
        }

        fn exitTest(self: *Context) void {
            std.log.debug("exitTest", .{});
            self.server.requestShutdown();
            self.proxy.server.requestShutdown();
        }

        fn exitTestWithError(self: *Context, test_error: anyerror) void {
            std.log.debug("exitTestexitTestWithError test_error={}", .{test_error});
            self.test_error = test_error;
            self.server.requestShutdown();
            self.proxy.server.requestShutdown();
        }

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const allocator = testing.allocator;
            // Use a random port
            const origin_address = try std.net.Address.parseIp4("127.0.0.1", 0);
            // Use a random port
            const proxy_address = try std.net.Address.parseIp4("127.0.0.1", 0);

            var self: Context = .{
                .buffer = std.fifo.LinearFifo(u8, .Dynamic).init(allocator),
            };
            defer self.buffer.deinit();

            self.server = try OriginServer.init(allocator, &io, &self, origin_address, .{});
            defer self.server.deinit();

            try self.server.start();

            std.log.debug("origin_address={}", .{self.server.bound_address});
            self.proxy = try Proxy.init(
                allocator,
                &io,
                &self,
                proxy_address,
                self.server.bound_address,
                .{},
                .{},
            );
            defer self.proxy.deinit();

            try self.proxy.server.start();

            std.log.debug("proxy_address={}", .{self.proxy.server.bound_address});
            self.client = try Client.init(allocator, &io, &self, &.{});
            defer self.client.deinit();

            try self.client.connect(self.proxy.server.bound_address, connectCallback);

            while (!self.client.done or !self.proxy.server.done or !self.server.done) {
                try io.tick();
            }

            // if (self.test_error) |err| {
            //     return err;
            // }
            try testing.expectEqual(content.len, self.response_content_length.?);
            try testing.expectEqualStrings(content, self.received_content.?);
            try testing.expect(self.handler_finished.?);
        }
    }.runTest();
}
