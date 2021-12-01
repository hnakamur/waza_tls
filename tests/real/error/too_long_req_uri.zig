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

test "real / error / too long req uri" {
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
                if (err != error.UriTooLong) {
                    std.log.err("Handler.recvRequestHeaderCallback should get error.UriTooLong, found={s}", .{@errorName(err)});
                }
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
                std.log.err("Handler.recvRequestContentFragmentCallback err={s}", .{@errorName(err)});
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
                std.fmt.format(w, "{s} {s}{s} {s}\r\n", .{
                    (http.Method{ .get = undefined }).toBytes(),
                    "/",
                    &[_]u8{'a'} ** 8193,
                    http.Version.http1_1.toBytes(),
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
            if (result) |_| {
                self.client.recvResponseHeader(recvResponseHeaderCallback);
            } else |err| {
                std.log.err("Context.sendFullCallback err={s}", .{@errorName(err)});
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

            var self: Context = .{
                .allocator = allocator,
                .send_header_buf = try allocator.alloc(u8, 8192 * 4),
                .server = try Handler.Server.init(allocator, &io, address, .{
                    .request_header_buf_len = 1024,
                    .large_request_header_buf_len = 8192,
                    .large_request_header_buf_max_count = 4,
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

            try testing.expectEqual(
                http.StatusCode.uri_too_long,
                self.client.response.status_code,
            );
        }
    }.runTest();
}
