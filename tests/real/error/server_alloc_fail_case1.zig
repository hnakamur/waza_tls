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

test "real / error / server alloc fail case1" {
    testing.log_level = .warn;

    const long_header_name = "X-Long";
    const crlf_crlf = "\r\n\r\n";

    try struct {
        const Context = @This();
        const Client = http.Client(Context);
        const Server = http.Server(Context, Handler);

        const Handler = struct {
            conn: *Server.Conn = undefined,
            long_header_value: ?[]const u8 = null,
            long_header_send_len: usize = 0,
            long_header_sent_len: usize = 0,
            crlf_crlf_send_len: usize = 0,
            crlf_crlf_sent_len: usize = 0,

            pub fn start(self: *Handler) void {
                std.log.debug("Handler.start", .{});
                self.conn.recvRequestHeader(recvRequestHeaderCallback);
            }

            pub fn recvRequestHeaderCallback(self: *Handler, result: Server.RecvRequestHeaderError!usize) void {
                std.log.info("Handler.recvRequestHeaderCallback start, result={}", .{result});
                if (result) |_| {
                    var it = http.FieldNameLineIterator.init(self.conn.request.headers.fields, long_header_name);
                    if (it.next()) |field_line| {
                        if (self.conn.server.allocator.dupe(u8, field_line.value())) |value| {
                            self.long_header_value = value;
                        } else |err| {
                            std.log.err("recvResponseHeaderCallback err={s}", .{@errorName(err)});
                        }
                    }

                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }

                    self.sendResponse();
                } else |err| {
                    if (err != error.OutOfMemory) {
                        std.log.err("Handler.recvRequestHeaderCallback expected OutOfMemory, found err={s}", .{@errorName(err)});
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
                std.fmt.format(w, "{s}: ", .{long_header_name}) catch unreachable;
                self.long_header_send_len = math.min(
                    self.long_header_value.?.len,
                    self.conn.send_buf.len,
                ) - fbs.pos;
                std.fmt.format(w, "{s}", .{
                    self.long_header_value.?[0..self.long_header_send_len],
                }) catch unreachable;
                self.conn.sendFull(fbs.getWritten(), sendHeaderCallback);
            }

            fn sendHeaderCallback(self: *Handler, last_result: IO.SendError!usize) void {
                std.log.debug("Handler.sendHeaderCallback start, last_result={}", .{last_result});
                if (last_result) |_| {
                    self.long_header_sent_len += self.long_header_send_len;
                    self.crlf_crlf_sent_len += self.crlf_crlf_send_len;

                    var fbs = std.io.fixedBufferStream(self.conn.send_buf);
                    var w = fbs.writer();
                    if (self.long_header_sent_len < self.long_header_value.?.len) {
                        self.long_header_send_len = math.min(
                            self.long_header_value.?.len - self.long_header_sent_len,
                            self.conn.send_buf.len,
                        );
                        const start_pos = self.long_header_sent_len;
                        const end = start_pos + self.long_header_send_len;
                        std.fmt.format(w, "{s}", .{self.long_header_value.?[start_pos..end]}) catch unreachable;
                    }

                    if (self.crlf_crlf_sent_len < crlf_crlf.len) {
                        self.crlf_crlf_send_len = math.min(
                            fbs.pos + crlf_crlf.len - self.crlf_crlf_sent_len,
                            self.conn.send_buf.len,
                        ) - fbs.pos;
                        std.log.info("Handler.sendHeaderCallback self.crlf_crlf_send_len={}", .{self.crlf_crlf_send_len});
                        const start_pos = self.crlf_crlf_sent_len;
                        const end = start_pos + self.crlf_crlf_send_len;
                        std.fmt.format(w, "{s}", .{crlf_crlf[start_pos..end]}) catch unreachable;
                    }
                    std.log.info("Handler.sendHeaderCallback fbs.pos={}", .{fbs.pos});
                    if (fbs.pos > 0) {
                        self.conn.sendFull(fbs.getWritten(), sendHeaderCallback);
                        return;
                    }

                    if (self.long_header_value) |value| {
                        const allocator = self.conn.server.allocator;
                        allocator.free(value);
                        self.long_header_value = null;
                        std.log.info("Handler.sendHeaderCallback freed long_header_value", .{});
                    }

                    self.conn.finishSend();
                } else |err| {
                    std.log.err("Handler.sendHeaderCallback err={s}", .{@errorName(err)});
                }
            }
        };

        server: Server = undefined,
        client: Client = undefined,
        allocator: *mem.Allocator = undefined,
        long_header_value: []const u8 = undefined,
        send_header_buf: []u8 = undefined,
        long_header_send_len: usize = 0,
        long_header_sent_len: usize = 0,
        crlf_crlf_send_len: usize = 0,
        crlf_crlf_sent_len: usize = 0,
        recv_long_header_value: []const u8 = undefined,
        send_header_result: ?IO.SendError!usize = null,

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
                std.fmt.format(w, "Host: example.com\r\n", .{}) catch unreachable;
                std.fmt.format(w, "{s}: ", .{long_header_name}) catch unreachable;
                self.long_header_send_len = math.min(
                    self.long_header_value.len,
                    self.send_header_buf.len,
                ) - fbs.pos;
                std.fmt.format(w, "{s}", .{
                    self.long_header_value[0..self.long_header_send_len],
                }) catch unreachable;
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
            self.send_header_result = result;
            if (result) |_| {
                self.long_header_sent_len += self.long_header_send_len;
                self.crlf_crlf_sent_len += self.crlf_crlf_send_len;

                var fbs = std.io.fixedBufferStream(self.send_header_buf);
                var w = fbs.writer();
                if (self.long_header_sent_len < self.long_header_value.len) {
                    self.long_header_send_len = math.min(
                        self.long_header_value.len - self.long_header_sent_len,
                        self.send_header_buf.len,
                    );
                    const start = self.long_header_sent_len;
                    const end = start + self.long_header_send_len;
                    std.fmt.format(w, "{s}", .{self.long_header_value[start..end]}) catch unreachable;
                }

                if (self.crlf_crlf_sent_len < crlf_crlf.len) {
                    self.crlf_crlf_send_len = math.min(
                        fbs.pos + crlf_crlf.len - self.crlf_crlf_sent_len,
                        self.send_header_buf.len,
                    ) - fbs.pos;
                    std.log.info("Context.sendHeaderCallback self.crlf_crlf_send_len={}", .{self.crlf_crlf_send_len});
                    const start = self.crlf_crlf_sent_len;
                    const end = start + self.crlf_crlf_send_len;
                    std.fmt.format(w, "{s}", .{crlf_crlf[start..end]}) catch unreachable;
                }
                std.log.info("Context.sendHeaderCallback fbs.pos={}", .{fbs.pos});
                if (fbs.pos > 0) {
                    self.client.sendFull(fbs.getWritten(), sendHeaderCallback);
                    return;
                }

                self.client.recvResponseHeader(recvResponseHeaderCallback);
            } else |err| {
                if (err == error.ConnectionResetByPeer) {
                    // We use std.log.warn here for running all tests for test coverage.
                    // If we use std.log.err, not all tests are run and we got very low coverage.
                    std.log.warn("Context.sendFullCallback got error.ConnectionResetByPeer, maybe we should improve server error handling.", .{});
                } else {
                    std.log.err("Context.sendFullCallback err={s}", .{@errorName(err)});
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
                var it = http.FieldNameLineIterator.init(self.client.response.headers.fields, long_header_name);
                if (it.next()) |field_line| {
                    if (self.allocator.dupe(u8, field_line.value())) |value| {
                        self.recv_long_header_value = value;
                    } else |err| {
                        std.log.err("recvResponseHeaderCallback err={s}", .{@errorName(err)});
                    }
                }

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

        fn generateRandomHeader(allocator: *mem.Allocator) ![]const u8 {
            var bin_buf: [16384]u8 = undefined;
            var encoded_buf: [32768]u8 = undefined;

            var r = rand.DefaultPrng.init(@intCast(u64, time.nanoTimestamp()));
            rand.Random.bytes(&r.random, &bin_buf);

            const encoder = std.base64.url_safe_no_pad.Encoder;
            const encoded = encoder.encode(&encoded_buf, &bin_buf);
            return try allocator.dupe(u8, encoded);
        }

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const allocator = testing.allocator;
            // Use a random port
            const address = try std.net.Address.parseIp4("127.0.0.1", 0);

            const failing_allocator = &testing.FailingAllocator.init(allocator, 5).allocator;

            var self: Context = .{
                .allocator = allocator,
                .long_header_value = try generateRandomHeader(allocator),
                .send_header_buf = try allocator.alloc(u8, 4096),
            };
            defer allocator.free(self.send_header_buf);
            defer allocator.free(self.long_header_value);

            self.server = try Server.init(failing_allocator, &io, &self, address, .{
                .response_buf_len = 4096,
            });
            defer self.server.deinit();
            // defer allocator.free(self.recv_long_header_value);

            std.log.debug("long_header_value={s}", .{self.long_header_value});

            self.client = try Client.init(allocator, &io, &self, &.{
                .response_content_fragment_buf_len = 4096,
            });
            defer self.client.deinit();

            try self.server.start();
            try self.client.connect(self.server.bound_address, connectCallback);

            while (!self.client.done or !self.server.done) {
                try io.tick();
            }

            try testing.expectError(error.ConnectionResetByPeer, self.send_header_result.?);
        }
    }.runTest();
}
