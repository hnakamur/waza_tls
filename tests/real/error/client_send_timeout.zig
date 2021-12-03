const std = @import("std");
const os = std.os;
const rand = std.rand;
const time = std.time;

const datetime = @import("datetime");
const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

test "real / error / client send timeout" {
    // testing.log_level = .debug;

    const Handler = struct {
        const Self = @This();
        pub const Server = http.Server(Self);

        conn: *Server.Conn = undefined,
        recv_content_buf: std.fifo.LinearFifo(u8, .Dynamic) = undefined,

        pub fn init(self: *Self) !void {
            const allocator = self.conn.server.allocator;
            self.recv_content_buf = std.fifo.LinearFifo(u8, .Dynamic).init(allocator);
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.conn.server.allocator;
            self.recv_content_buf.deinit();
        }

        pub fn start(self: *Self) void {
            std.log.debug("Handler.start", .{});
            self.recv_content_buf.discard(self.recv_content_buf.count);
            self.conn.recvRequestHeader(recvRequestHeaderCallback);
        }

        pub fn recvRequestHeaderCallback(self: *Self, result: Server.RecvRequestHeaderError!usize) void {
            std.log.debug("Handler.recvRequestHeaderCallback start, result={}", .{result});
            if (result) |_| {
                if (self.conn.request_content_fragment_buf) |src_buf| {
                    std.log.info("Server.Conn.recvRequestHeaderCallback src_buf.len={}", .{src_buf.len});
                    if (self.recv_content_buf.writer().write(src_buf)) |_| {} else |err| {
                        std.log.err("failed to write to recv_content_buf, err={s}", .{@errorName(err)});
                    }
                }
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
            if (result) |received| {
                const src_buf = self.conn.request_content_fragment_buf.?[0..received];
                if (self.recv_content_buf.writer().write(src_buf)) |_| {} else |err| {
                    std.log.err("failed to write to recv_content_buf, err={s}", .{@errorName(err)});
                }
                if (!self.conn.fullyReadRequestContent()) {
                    self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                    return;
                }

                self.sendResponse();
            } else |err| {
                std.log.err("Handler.recvRequestContentFragmentCallback err={s}", .{@errorName(err)});
            }
        }

        pub fn sendResponse(self: *Self) void {
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
            if (self.conn.request_content_length) |content_length| {
                std.fmt.format(w, "Content-Type: {s}\r\n", .{"application/octet-stream"}) catch unreachable;
                std.fmt.format(w, "Content-Length: {d}\r\n", .{content_length}) catch unreachable;
            }
            std.fmt.format(w, "\r\n", .{}) catch unreachable;
            self.conn.sendFull(fbs.getWritten(), sendHeaderCallback);
        }

        fn sendHeaderCallback(self: *Self, last_result: IO.SendError!usize) void {
            std.log.debug("Handler.sendHeaderCallback start, last_result={}", .{last_result});
            if (last_result) |_| {
                std.log.info("Server.Conn.sendHeaderCallback send_len={}", .{self.recv_content_buf.readableSlice(0).len});
                self.conn.sendFull(self.recv_content_buf.readableSlice(0), sendContentCallback);
            } else |err| {
                std.log.err("Handler.sendHeaderCallback err={s}", .{@errorName(err)});
            }
        }

        fn sendContentCallback(self: *Self, last_result: IO.SendError!usize) void {
            std.log.info("Handler.sendContentCallback start, last_result={}", .{last_result});
            if (last_result) |_| {
                self.conn.finishSend();
            } else |err| {
                std.log.err("Handler.sendContentCallback err={s}", .{@errorName(err)});
            }
        }
    };

    try struct {
        const Context = @This();
        const Client = http.Client(Context);

        const State = enum {
            send_header,
            send_content,
            recv_header,
            recv_content,
        };

        server: Handler.Server = undefined,
        client: Client = undefined,
        header_buf: std.fifo.LinearFifo(u8, .Dynamic),
        send_content_buf: []u8 = undefined,
        recv_content_buf: std.fifo.LinearFifo(u8, .Dynamic),
        response_content_length: ?u64 = null,
        state: State = .send_header,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            std.log.debug("Context.connectCallback start, result={}", .{result});
            if (result) |_| {
                var w = self.header_buf.writer();
                std.fmt.format(w, "{s} {s} {s}\r\n", .{
                    (http.Method{ .get = undefined }).toBytes(),
                    "/",
                    http.Version.http1_1.toBytes(),
                }) catch unreachable;
                std.fmt.format(w, "Host: example.com\r\n", .{}) catch unreachable;
                std.fmt.format(w, "Content-Type: application/octet-stream\r\n", .{}) catch unreachable;
                std.fmt.format(w, "Content-Length: {}\r\n", .{self.send_content_buf.len}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
                self.client.sendFull(self.header_buf.readableSlice(0), sendFullCallback);
            } else |err| {
                std.log.err("Context.connectCallback err={s}", .{@errorName(err)});
                self.exitTest();
            }
        }
        fn sendFullCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            std.log.debug("Context.sendFullCallback start, result={}", .{result});
            if (result) |_| {
                switch (self.state) {
                    .send_header => {
                        self.state = .send_content;
                        self.client.sendFull(self.send_content_buf, sendFullCallback);
                        std.log.info("Context.sendFullCallback after sendFull len={}", .{self.send_content_buf.len});
                    },
                    .send_content => {
                        self.state = .recv_header;
                        std.log.info("Context.sendFullCallback before recvResponseHeader, processed_len={}", .{
                            self.client.completion.processed_len,
                        });
                        self.client.recvResponseHeader(recvResponseHeaderCallback);
                    },
                    else => {
                        std.log.err("Context.sendFullCallback unexpected state={}\n", .{self.state});
                        @panic("unexpected state");
                    },
                }
            } else |err| {
                std.log.err("Context.sendFullCallback err={s}", .{@errorName(err)});
                self.exitTest();
            }
        }
        fn recvResponseHeaderCallback(
            self: *Context,
            result: Client.RecvResponseHeaderError!usize,
        ) void {
            std.log.debug("Context.recvResponseHeaderCallback start, result={}", .{result});
            if (result) |_| {
                self.response_content_length = self.client.response_content_length;
                if (self.client.response_content_fragment_buf) |src_buf| {
                    if (self.recv_content_buf.writer().write(src_buf)) |_| {} else |err| {
                        std.log.err("failed to write to recv_content_buf, err={s}", .{@errorName(err)});
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
                self.exitTest();
            }
        }
        fn recvResponseContentFragmentCallback(
            self: *Context,
            result: Client.RecvResponseContentFragmentError!usize,
        ) void {
            std.log.debug("Context.recvResponseContentFragmentCallback start, result={}", .{result});
            if (result) |received| {
                const src_buf = self.client.response_content_fragment_buf.?[0..received];
                if (self.recv_content_buf.writer().write(src_buf)) |_| {} else |err| {
                    std.log.err("failed to write to recv_content_buf, err={s}", .{@errorName(err)});
                }
                if (!self.client.fullyReadResponseContent()) {
                    self.client.recvResponseContentFragment(recvResponseContentFragmentCallback);
                    return;
                }

                std.log.debug("Context.recvResponseContentFragmentCallback before calling self.client.close", .{});
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
            var io = try IO.init(512, 0);
            defer io.deinit();

            const allocator = testing.allocator;
            // Use a random port
            const address = try std.net.Address.parseIp4("127.0.0.1", 0);

            var self: Context = .{
                .header_buf = std.fifo.LinearFifo(u8, .Dynamic).init(allocator),
                .send_content_buf = try allocator.alloc(u8, 3 * 1024 * 1024),
                .recv_content_buf = std.fifo.LinearFifo(u8, .Dynamic).init(allocator),
                .server = try Handler.Server.init(allocator, &io, address, .{
                    .request_content_fragment_buf_len = 3 * 1024 * 1024,
                    .response_buf_len = 4096,
                }),
            };
            defer self.recv_content_buf.deinit();
            defer allocator.free(self.send_content_buf);
            defer self.header_buf.deinit();
            defer self.server.deinit();

            var r = rand.DefaultPrng.init(@intCast(u64, time.nanoTimestamp()));
            rand.Random.bytes(&r.random, self.send_content_buf);

            self.client = try Client.init(allocator, &io, &self, &.{
                .response_content_fragment_buf_len = 4096,
                .send_timeout_ns = 10 * time.ns_per_ms,
            });
            defer self.client.deinit();

            try self.server.start();
            try self.client.connect(self.server.bound_address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            try testing.expectEqual(self.send_content_buf.len, self.response_content_length.?);
            try testing.expectEqualStrings(self.send_content_buf, self.recv_content_buf.readableSlice(0));
        }
    }.runTest();
}
