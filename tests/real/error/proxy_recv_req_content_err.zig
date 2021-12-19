const std = @import("std");
const mem = std.mem;
const os = std.os;
const rand = std.rand;
const time = std.time;

const datetime = @import("datetime");
const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

const root = @import("root");

test "real / error / recv req content error" {
    // testing.log_level = .debug;

    try struct {
        const Context = @This();
        const Client = http.Client(Context);
        const Proxy = http.Proxy(Context);
        const OriginServer = http.Server(Context, Handler);

        const Handler = struct {
            conn: *OriginServer.Conn = undefined,
            received_content: ?[]u8 = null,
            received_len_so_far: usize = 0,
            content_sent_so_far: usize = 0,

            pub fn start(self: *Handler) void {
                std.log.debug("OriginServer.Handler.start", .{});
                self.conn.recvRequestHeader(recvRequestHeaderCallback);
            }

            pub fn recvRequestHeaderCallback(self: *Handler, result: OriginServer.RecvRequestHeaderError!usize) void {
                std.log.debug("OriginServer.Handler.recvRequestHeaderCallback start, result={}", .{result});
                if (result) |_| {
                    if (self.conn.request_content_length) |len| {
                        if (self.conn.server.allocator.alloc(u8, len)) |buf| {
                            self.received_content = buf;
                            if (self.conn.req_hdr_buf_content_fragment) |frag| {
                                mem.copy(u8, self.received_content.?, frag);
                                self.received_len_so_far = frag.len;
                                std.log.debug("OriginServer.Handler.recvRequestHeaderCallback copied frag in header len={}", .{frag.len});
                            }
                        } else |err| {
                            std.log.err("OriginServer.Handler.recvRequestHeaderCallback allocator buf for received_content, err={s}", .{@errorName(err)});
                            return;
                        }
                    }

                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponseHeader();
                } else |err| {
                    if (err == error.Canceled) {
                        std.log.warn("OriginServer.Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                    } else {
                        std.log.err("OriginServer.Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                    }
                }
            }

            pub fn recvRequestContentFragmentCallback(self: *Handler, result: OriginServer.RecvRequestContentFragmentError!usize) void {
                std.log.debug("OriginServer.Handler.recvRequestContentFragmentCallback start, result={}", .{result});
                if (result) |received| {
                    mem.copy(
                        u8,
                        self.received_content.?[self.received_len_so_far..],
                        self.conn.request_content_fragment_buf.?[0..received],
                    );
                    self.received_len_so_far += received;

                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponseHeader();
                } else |err| {
                    std.log.err("OriginServer.Handler.recvRequestContentFragmentCallback err={s}", .{@errorName(err)});
                }
            }

            pub fn sendResponseHeader(self: *Handler) void {
                std.log.debug("OriginServer.Handler.sendResponseHeader start", .{});
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
                const content_length = self.conn.request_content_length.?;
                std.log.debug("OriginServer.Handler request_content_len={}", .{self.conn.request_content_length.?});
                std.fmt.format(w, "Content-Length: {d}\r\n", .{content_length}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
                self.conn.sendFull(fbs.getWritten(), sendResponseHeaderCallback);
            }

            fn sendResponseHeaderCallback(self: *Handler, last_result: IO.SendError!usize) void {
                std.log.debug("OriginServer.Handler.sendResponseHeaderCallback start, last_result={}", .{last_result});
                if (last_result) |_| {
                    const content_length = self.conn.request_content_length.?;
                    self.conn.sendFull(
                        self.received_content.?[0 .. content_length / 2],
                        sendResponseContentCallback,
                    );
                } else |err| {
                    std.log.err("OriginServer.Handler.sendResponseHeaderCallback err={s}", .{@errorName(err)});
                }
            }
            fn sendResponseContentCallback(self: *Handler, last_result: IO.SendError!usize) void {
                std.log.debug("OriginServer.Handler.sendResponseContentCallback start, last_result={}", .{last_result});
                if (last_result) |_| {
                    self.content_sent_so_far += self.conn.completion.processed_len;
                    const len = self.conn.request_content_length.?;
                    if (self.content_sent_so_far < len) {
                        self.conn.sendFull(
                            self.received_content.?[self.content_sent_so_far..len],
                            sendResponseContentCallback,
                        );
                        return;
                    }

                    self.conn.server.allocator.free(self.received_content.?);
                    self.received_content = null;
                    self.conn.finishSend();
                    self.conn.server.context.handler_finished = true;
                } else |err| {
                    std.log.err("OriginServer.Handler.sendResponseContentCallback err={s}", .{@errorName(err)});
                }
            }
        };

        allocator: mem.Allocator,
        server: OriginServer = undefined,
        proxy: *Proxy = undefined,
        client: Client = undefined,
        buffer: std.fifo.LinearFifo(u8, .Dynamic),
        content: []const u8,
        content_sent_so_far: u64 = 0,
        content_read_so_far: u64 = undefined,
        response_content_length: ?u64 = null,
        received_content_len: usize = 0,
        received_content: ?[]u8 = null,
        test_error: ?anyerror = null,
        handler_finished: ?bool = null,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            std.log.debug("Context.connectCallback start, result={}", .{result});
            if (result) |_| {
                var w = self.buffer.writer();
                std.fmt.format(w, "{s} {s} {s}\r\n", .{
                    (http.Method{ .post = undefined }).toBytes(),
                    "/",
                    http.Version.http1_1.toBytes(),
                }) catch unreachable;
                std.fmt.format(w, "Host: example.com\r\n", .{}) catch unreachable;
                std.fmt.format(w, "Content-Length: {}\r\n\r\n", .{self.content.len}) catch unreachable;
                self.client.sendFull(self.buffer.readableSlice(0), sendRequestHeaderCallback);
            } else |err| {
                std.log.err("Connect.connectCallback err={s}", .{@errorName(err)});
                self.exitTestWithError(err);
            }
        }
        fn sendRequestHeaderCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            std.log.debug("Context.sendRequestHeaderCallback start, result={}", .{result});
            if (result) |_| {
                self.client.sendFull(
                    self.content[0 .. self.content.len / 2],
                    sendRequestContentCallback,
                );
            } else |err| {
                std.log.err("Connect.sendRequestHeaderCallback err={s}", .{@errorName(err)});
                self.exitTestWithError(err);
            }
        }
        fn sendRequestContentCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            std.log.debug("Context.sendRequestContentCallback start, result={}", .{result});
            if (result) |_| {
                self.content_sent_so_far += self.client.completion.processed_len;
                if (self.content_sent_so_far < self.content.len) {
                    // self.client.sendFull(
                    //     self.content[self.content_sent_so_far..],
                    //     sendRequestContentCallback,
                    // );
                    self.client.close();
                    self.exitTest();
                    return;
                }
                self.client.recvResponseHeader(recvResponseHeaderCallback);
            } else |err| {
                std.log.err("Connect.sendRequestContentCallback err={s}", .{@errorName(err)});
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
                    std.log.debug("Context.recvResponseHeaderCallback set response_content_length to {}", .{len});
                    if (self.allocator.alloc(u8, len)) |buf| {
                        self.received_content = buf;
                        if (self.client.resp_hdr_buf_content_fragment) |frag| {
                            mem.copy(u8, self.received_content.?, frag);
                            self.received_content_len = frag.len;
                            std.log.debug("Context.recvResponseHeaderCallback copied frag in header len={}", .{frag.len});
                        }
                    } else |err| {
                        std.log.err("allocator buf for received_content, err={s}", .{@errorName(err)});
                        self.client.close();
                        self.exitTestWithError(err);
                        return;
                    }
                }

                if (!self.client.fullyReadResponseContent()) {
                    self.client.recvResponseContentFragment(recvResponseContentFragmentCallback);
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
            if (result) |received| {
                std.log.debug("Context.recvResponseContentFragmentCallback received_content.len={}, received_content_len={}", .{
                    self.received_content.?.len, self.received_content_len,
                });
                mem.copy(
                    u8,
                    self.received_content.?[self.received_content_len..],
                    self.client.response_content_fragment_buf.?[0..received],
                );
                self.received_content_len += received;

                if (!self.client.fullyReadResponseContent()) {
                    self.client.recvResponseContentFragment(recvResponseContentFragmentCallback);
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

        fn generateRandomText(allocator: mem.Allocator) ![]const u8 {
            var bin_buf: [2048]u8 = undefined;
            var encoded_buf: [4096]u8 = undefined;

            var r = rand.DefaultPrng.init(@intCast(u64, time.nanoTimestamp())).random();
            r.bytes(&bin_buf);

            const encoder = std.base64.url_safe_no_pad.Encoder;
            const encoded = encoder.encode(&encoded_buf, &bin_buf);
            return try allocator.dupe(u8, encoded);
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
                .allocator = allocator,
                .buffer = std.fifo.LinearFifo(u8, .Dynamic).init(allocator),
                .content = try generateRandomText(allocator),
            };
            defer self.buffer.deinit();
            defer allocator.free(self.content);
            defer if (self.received_content) |c| self.allocator.free(c);

            std.log.debug("content.len={}", .{self.content.len});

            self.server = try OriginServer.init(allocator, &io, &self, origin_address, .{
                .response_buf_len = 8192,
            });
            defer self.server.deinit();
            std.log.debug("origin_server=0x{x}", .{@ptrToInt(&self.server)});

            try self.server.start();

            std.log.debug("origin_address={}", .{self.server.bound_address});
            self.proxy = try Proxy.init(
                allocator,
                &io,
                &self,
                proxy_address,
                self.server.bound_address,
                .{
                    .request_content_fragment_buf_len = 1024,
                },
                .{
                    .response_content_fragment_buf_len = 1024,
                },
            );
            defer self.proxy.deinit();
            std.log.debug("proxy.server=0x{x}", .{@ptrToInt(&self.proxy.server)});

            try self.proxy.server.start();

            std.log.debug("proxy_address={}", .{self.proxy.server.bound_address});
            self.client = try Client.init(allocator, &io, &self, &.{});
            defer self.client.deinit();

            try self.client.connect(self.proxy.server.bound_address, connectCallback);

            while (!self.client.done or !self.proxy.server.done or !self.server.done) {
                try io.tick();
            }

            try testing.expectEqual(@as(?u64, null), self.response_content_length);
            try testing.expectEqual(@as(?[]u8, null), self.received_content);
            try testing.expectEqual(@as(?bool, null), self.handler_finished);
        }
    }.runTest();
}
