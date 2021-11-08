const std = @import("std");
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
// const http = @import("http");
const http = @import("http");
const Client = http.Client;

// const Client = struct {
//     io: IO,
//     sock: os.socket_t,
//     address: std.net.Address,
//     connect_timeout_ns: u63 = 5 * time.ns_per_s,
//     send_timeout_ns: u63 = 5 * time.ns_per_s,
//     recv_timeout_ns: u63 = 5 * time.ns_per_s,
//     send_buf: []u8,
//     recv_buf: []u8,
//     allocator: *mem.Allocator,
//     completions: [2]IO.Completion = undefined,
//     done: bool = false,

//     fn init(allocator: *mem.Allocator, address: std.net.Address) !Client {
//         const sock = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
//         const send_buf = try allocator.alloc(u8, 8192);
//         const recv_buf = try allocator.alloc(u8, 8192);

//         return Client{
//             .io = try IO.init(256, 0),
//             .sock = sock,
//             .address = address,
//             .send_buf = send_buf,
//             .recv_buf = recv_buf,
//             .allocator = allocator,
//         };
//     }

//     pub fn deinit(self: *Client) void {
//         self.allocator.free(self.send_buf);
//         self.allocator.free(self.recv_buf);
//         self.io.deinit();
//     }

//     pub fn run(self: *Client) !void {
//         self.connectWithTimeout();
//         while (!self.done) try self.io.tick();
//     }

//     fn connectWithTimeout(self: *Client) void {
//         self.io.connect(
//             *Client,
//             self,
//             connectCallback,
//             &self.completions[0],
//             self.sock,
//             self.address,
//         );
//         self.io.timeout(
//             *Client,
//             self,
//             connectTimeoutCallback,
//             &self.completions[1],
//             self.connect_timeout_ns,
//         );
//     }
//     fn connectCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.ConnectError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("connectCallback ok\n", .{});
//             self.io.cancelTimeout(
//                 *Client,
//                 self,
//                 connectTimeoutCancelCallback,
//                 &self.completions[0],
//                 &self.completions[1],
//             );
//         } else |err| {
//             std.debug.print("connectCallback err={s}\n", .{@errorName(err)});
//             self.close();
//         }
//     }
//     fn connectTimeoutCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.TimeoutError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("connectTimeoutCallback ok\n", .{});
//             completion.io.cancel(
//                 *Client,
//                 self,
//                 connectCancelCallback,
//                 &self.completions[1],
//                 &self.completions[0],
//             );
//         } else |err| {
//             std.debug.print("connectTimeoutCallback err={s}\n", .{@errorName(err)});
//         }
//     }
//     fn connectCancelCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.CancelError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("connectCancelCallback ok\n", .{});
//         } else |err| {
//             std.debug.print("connectCancelCallback err={s}\n", .{@errorName(err)});
//         }
//     }
//     fn connectTimeoutCancelCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.CancelTimeoutError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("connectTimeoutCancelCallback ok\n", .{});
//             self.sendWithTimeout();
//         } else |err| {
//             std.debug.print("connectTimeoutCancelCallback err={s}\n", .{@errorName(err)});
//         }
//     }

//     pub fn send(
//         self: *Client,
//         comptime Context: type,
//         context: Context,
//         callback: fn (
//             context: Context,
//             client: *Client,
//             result: IO.SendError!usize,
//         ) void,
//     ) void {
//         callback(context, self, 1);
//     }

//     fn sendWithTimeout(self: *Client) void {
//         var fbs = std.io.fixedBufferStream(self.send_buf);
//         var w = fbs.writer();
//         std.fmt.format(w, "{s} {s} {s}\r\n", .{
//             (http.Method{ .get = undefined }).toText(),
//             "/",
//             http.Version.http1_1.toText(),
//         }) catch unreachable;
//         std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;

//         self.io.send(
//             *Client,
//             self,
//             sendCallback,
//             &self.completions[0],
//             self.sock,
//             fbs.getWritten(),
//             if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
//         );
//         self.io.timeout(
//             *Client,
//             self,
//             sendTimeoutCallback,
//             &self.completions[1],
//             self.send_timeout_ns,
//         );
//     }
//     fn sendCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.SendError!usize,
//     ) void {
//         if (result) |sent| {
//             std.debug.print("sent request bytes={d}\n", .{sent});
//             self.io.cancelTimeout(
//                 *Client,
//                 self,
//                 sendTimeoutCancelCallback,
//                 &self.completions[0],
//                 &self.completions[1],
//             );
//         } else |err| {
//             std.debug.print("send error: {s}\n", .{@errorName(err)});
//             self.close();
//         }
//     }
//     fn sendTimeoutCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.TimeoutError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("sendTimeoutCallback ok\n", .{});
//             completion.io.cancel(
//                 *Client,
//                 self,
//                 sendCancelCallback,
//                 &self.completions[1],
//                 &self.completions[0],
//             );
//         } else |err| {
//             if (err != error.Canceled) {
//                 std.debug.print("sendTimeoutCallback err={s}\n", .{@errorName(err)});
//             }
//         }
//     }
//     fn sendCancelCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.CancelError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("sendCancelCallback ok\n", .{});
//         } else |err| {
//             std.debug.print("sendCancelCallback err={s}\n", .{@errorName(err)});
//         }
//     }
//     fn sendTimeoutCancelCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.CancelTimeoutError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("sendTimeoutCancelCallback ok\n", .{});
//             self.recvWithTimeout();
//         } else |err| {
//             std.debug.print("sendTimeoutCancelCallback err={s}\n", .{@errorName(err)});
//         }
//     }

//     fn recvWithTimeout(self: *Client) void {
//         self.io.recv(
//             *Client,
//             self,
//             recvCallback,
//             &self.completions[0],
//             self.sock,
//             self.recv_buf,
//             if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
//         );
//         self.io.timeout(
//             *Client,
//             self,
//             recvTimeoutCallback,
//             &self.completions[1],
//             self.recv_timeout_ns,
//         );
//     }
//     fn recvCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.RecvError!usize,
//     ) void {
//         if (result) |received| {
//             std.debug.print("response={s}", .{self.recv_buf[0..received]});
//             self.io.cancelTimeout(
//                 *Client,
//                 self,
//                 recvTimeoutCancelCallback,
//                 &self.completions[0],
//                 &self.completions[1],
//             );
//         } else |err| {
//             std.debug.print("recv error: {s}\n", .{@errorName(err)});
//         }
//     }
//     fn recvTimeoutCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.TimeoutError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("recvTimeoutCallback ok\n", .{});
//             completion.io.cancel(
//                 *Client,
//                 self,
//                 recvCancelCallback,
//                 &self.completions[1],
//                 &self.completions[0],
//             );
//         } else |err| {
//             std.debug.print("recvTimeoutCallback err={s}\n", .{@errorName(err)});
//         }
//     }
//     fn recvCancelCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.CancelError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("recvCancelCallback ok\n", .{});
//         } else |err| {
//             std.debug.print("recvCancelCallback err={s}\n", .{@errorName(err)});
//         }
//     }
//     fn recvTimeoutCancelCallback(
//         self: *Client,
//         completion: *IO.Completion,
//         result: IO.CancelTimeoutError!void,
//     ) void {
//         if (result) |_| {
//             std.debug.print("recvTimeoutCancelCallback ok\n", .{});
//         } else |err| {
//             std.debug.print("recvTimeoutCancelCallback error: {s}\n", .{@errorName(err)});
//         }
//         self.close();
//     }

//     fn close(self: *Client) void {
//         os.close(self.sock);
//         self.done = true;
//         std.debug.print("close and exit\n", .{});
//     }
// };

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
    ctx.send();

    // try client.run();
}
