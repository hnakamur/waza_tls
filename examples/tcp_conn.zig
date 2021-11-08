const std = @import("std");
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const TCPConn = @import("http").TCPConn;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const port = 3131;

    var io = try IO.init(32, 0);
    defer io.deinit();
    const address = try std.net.Address.parseIp4("127.0.0.1", port);

    var conn = try TCPConn.init(&io, address);
    defer conn.deinit();

    const MyContext = struct {
        conn: TCPConn,

        const Self = @This();

        fn connect(self: *Self) void {
            self.conn.connectWithTimeout(*Self, self, connectCallback);
        }
        fn connectCallback(
            self: *Self,
            result: TCPConn.ConnectWithTimeoutError!void,
        ) void {
            std.debug.print("MyContext.connectCallback, result={}\n", .{result});
        }
    };
    var ctx = MyContext{ .conn = conn };
    ctx.connect();

    try io.run_for_ns(time.ns_per_s);
}
