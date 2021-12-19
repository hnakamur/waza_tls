const std = @import("std");
const os = std.os;
const time = std.time;

const datetime = @import("datetime");
const http = @import("hutaback");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

test "real / error / proxy connect origin error" {
    try struct {
        const Context = @This();
        const Client = http.Client(Context);
        const Proxy = http.Proxy(Context);
        const OriginServer = http.Server(Context, Handler);

        const Handler = struct {
            conn: *OriginServer.Conn = undefined,

            pub fn start(_: *Handler) void {}
        };

        server: OriginServer = undefined,
        proxy: *Proxy = undefined,
        client: Client = undefined,
        buffer: std.fifo.LinearFifo(u8, .Dynamic),
        recv_resp_hdr_result: ?Client.RecvResponseHeaderError!usize = null,

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            if (result) |_| {
                var w = self.buffer.writer();
                std.fmt.format(w, "{s} {s} {s}\r\n", .{
                    (http.Method{ .get = undefined }).toBytes(),
                    "/",
                    http.Version.http1_1.toBytes(),
                }) catch unreachable;
                std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;
                self.client.sendFull(self.buffer.readableSlice(0), sendFullCallback);
            } else |err| {
                std.log.err("Context.connectCallback err={s}", .{@errorName(err)});
                self.exitTest();
            }
        }
        fn sendFullCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
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
            self.recv_resp_hdr_result = result;
            if (result) |_| {
                self.client.close();
            } else |_| {}
            self.exitTest();
        }

        fn exitTest(self: *Context) void {
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
            const origin_bound_address = self.server.bound_address;
            self.server.deinit();

            self.proxy = try Proxy.init(
                allocator,
                &io,
                &self,
                proxy_address,
                origin_bound_address,
                .{},
                .{},
            );
            defer self.proxy.deinit();

            try self.proxy.server.start();

            self.client = try Client.init(allocator, &io, &self, &.{
                .recv_timeout_ns = 20 * time.ns_per_ms,
            });
            defer self.client.deinit();

            try self.client.connect(self.proxy.server.bound_address, connectCallback);

            while (!self.client.done or !self.proxy.server.done) {
                try io.tick();
            }

            try testing.expectEqual(
                @as(?Client.RecvResponseHeaderError!usize, error.UnexpectedEof),
                self.recv_resp_hdr_result,
            );
        }
    }.runTest();
}
