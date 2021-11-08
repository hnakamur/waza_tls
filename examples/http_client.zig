const std = @import("std");
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const http = @import("http");
const Client = http.Client;


const port_max = 65535;

const MyContext = struct {
    client: Client = undefined,

    const Self = @This();

    fn sendCallback(self: *Self, client: *Client, result: IO.SendError!usize) void {
        std.debug.print("Context.sendCallback, result={d}\n", .{result});
    }

    fn send(self: *Self) void {
        self.client.send(*Self, self, sendCallback);
    }
};

pub fn main() anyerror!void {
    const allocator = std.heap.page_allocator;

    var port: u16 = 3131;
    if (os.getenv("PORT")) |port_str| {
        if (std.fmt.parseInt(u16, port_str, 10)) |v| {
            if (v <= port_max) port = v;
        } else |err| {
            std.debug.print("bad port value={s}, err={s}\n", .{ port_str, @errorName(err) });
        }
    }
    std.debug.print("port={d}\n", .{port});
    const address = try std.net.Address.parseIp4("127.0.0.1", port);
    var client = try Client.init(allocator, address);
    defer client.deinit();

    var ctx = MyContext{.client = client};
    // ctx.send();

    try client.run();
}
