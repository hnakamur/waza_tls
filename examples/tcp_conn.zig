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
        completion: TCPConn.Completion = undefined,

        const Self = @This();

        fn connect(self: *Self) void {
            self.conn.connectWithTimeout(
                *Self,
                self,
                connectCallback,
                &self.completion,
                500 * time.ns_per_ms,
            );
        }
        fn connectCallback(
            self: *Self,
            comp: *TCPConn.Completion,
            result: TCPConn.ConnectError!void,
        ) void {
            std.debug.print("MyContext.connectCallback, result={}\n", .{result});
        }
    };
    var ctx = MyContext{ .conn = conn };
    ctx.connect();

    try io.run_for_ns(2 * time.ns_per_s);
}
