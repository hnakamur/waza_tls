const std = @import("std");
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;

pub const TCPConn = struct {
    io: *IO,
    address: std.net.Address,
    socket: os.socket_t,
    context: ?*c_void = undefined,
    result: union(enum) {
        connect: ConnectWithTimeoutError!void,
    } = undefined,
    callback: fn (
        ctx: ?*c_void,
        res: *const c_void,
    ) void = undefined,
    completions: [2]IO.Completion = undefined,

    const Self = @This();

    pub fn init(io: *IO, address: std.net.Address) !TCPConn {
        const socket = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);

        return TCPConn{
            .io = io,
            .address = address,
            .socket = socket,
        };
    }

    pub fn deinit(self: *Self) void {
        os.closeSocket(self.socket);
    }

    pub const ConnectWithTimeoutError = error{} || IO.ConnectError || IO.TimeoutError;

    pub fn connectWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        timeout_ns: u63,
        comptime callback: fn (
            context: Context,
            result: ConnectWithTimeoutError!void,
        ) void,
    ) void {
        self.context = context;
        self.callback = struct {
            fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                callback(
                    @intToPtr(Context, @ptrToInt(ctx)),
                    @intToPtr(*const ConnectWithTimeoutError!void, @ptrToInt(res)).*,
                );
            }
        }.wrapper;
        self.io.connect(
            *Self,
            self,
            connectCallback,
            &self.completions[0],
            self.socket,
            self.address,
        );
        self.io.timeout(
            *Self,
            self,
            connectTimeoutCallback,
            &self.completions[1],
            timeout_ns,
        );
    }
    fn connectCallback(
        self: *Self,
        completion: *IO.Completion,
        result: IO.ConnectError!void,
    ) void {
        self.result = .{ .connect = result };
        std.debug.print("connectCallback set self.result={}\n", .{self.result});
        if (result) |_| {
            std.debug.print("connectCallback ok\n", .{});
            self.io.cancelTimeout(
                *Self,
                self,
                connectTimeoutCancelCallback,
                &self.completions[0],
                &self.completions[1],
            );
        } else |err| {
            std.debug.print("connectCallback err={s}\n", .{@errorName(err)});
            // self.close();
        }
    }
    fn connectTimeoutCallback(
        self: *Self,
        completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("connectTimeoutCallback ok\n", .{});
            completion.io.cancel(
                *Self,
                self,
                connectCancelCallback,
                &self.completions[1],
                &self.completions[0],
            );

            // self.callback(self.context, &result);
        } else |err| {
            std.debug.print("connectTimeoutCallback err={s}\n", .{@errorName(err)});
        }
    }
    fn connectCancelCallback(
        self: *Self,
        completion: *IO.Completion,
        result: IO.CancelError!void,
    ) void {
        if (result) |_| {
            std.debug.print("connectCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("connectCancelCallback err={s}\n", .{@errorName(err)});
        }
        std.debug.print("connectCancelCallback calling callback\n", .{});
        self.callback(self.context, &self.result);
        std.debug.print("connectCancelCallback called callback\n", .{});
    }
    fn connectTimeoutCancelCallback(
        self: *Self,
        completion: *IO.Completion,
        result: IO.CancelTimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("connectTimeoutCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("connectTimeoutCancelCallback err={s}\n", .{@errorName(err)});
        }
        std.debug.print("connectTimeoutCancelCallback calling callback\n", .{});
        self.callback(self.context, &self.result);
        std.debug.print("connectTimeoutCancelCallback called callback\n", .{});
    }

    // pub const SendError = IO.SendError || IO.TimeoutError;

    // pub fn send(
    //     self: *Self,
    //     comptime Context: type,
    //     context: Context,
    //     sock: os.socket_t,
    //     buf: []const u8,
    //     callback: fn (
    //         context: Context,
    //         client: *Self,
    //         result: SendError!usize,
    //     ) void,
    // ) void {
    //     std.debug.print("Self.send start\n", .{});
    //     callback(context, self, 1);
    //     std.debug.print("Self.send exit\n", .{});
    // }

    // fn _sendWithTimeout(self: *Self) void {
    //     var fbs = std.io.fixedBufferStream(self.send_buf);
    //     var w = fbs.writer();
    //     std.fmt.format(w, "{s} {s} {s}\r\n", .{
    //         (Method{ .get = undefined }).toText(),
    //         "/",
    //         Version.http1_1.toText(),
    //     }) catch unreachable;
    //     std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;

    //     self.io.send(
    //         *Self,
    //         self,
    //         sendCallback,
    //         &self.completions[0],
    //         self.sock,
    //         fbs.getWritten(),
    //         if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
    //     );
    //     self.io.timeout(
    //         *Self,
    //         self,
    //         sendTimeoutCallback,
    //         &self.completions[1],
    //         self.send_timeout_ns,
    //     );
    // }
    // fn sendCallback(
    //     self: *Self,
    //     completion: *IO.Completion,
    //     result: IO.SendError!usize,
    // ) void {
    //     if (result) |sent| {
    //         std.debug.print("sent request bytes={d}\n", .{sent});
    //         self.io.cancelTimeout(
    //             *Self,
    //             self,
    //             sendTimeoutCancelCallback,
    //             &self.completions[0],
    //             &self.completions[1],
    //         );
    //     } else |err| {
    //         std.debug.print("send error: {s}\n", .{@errorName(err)});
    //         self.close();
    //     }
    // }
    // fn sendTimeoutCallback(
    //     self: *Self,
    //     completion: *IO.Completion,
    //     result: IO.TimeoutError!void,
    // ) void {
    //     if (result) |_| {
    //         std.debug.print("sendTimeoutCallback ok\n", .{});
    //         completion.io.cancel(
    //             *Self,
    //             self,
    //             sendCancelCallback,
    //             &self.completions[1],
    //             &self.completions[0],
    //         );
    //     } else |err| {
    //         if (err != error.Canceled) {
    //             std.debug.print("sendTimeoutCallback err={s}\n", .{@errorName(err)});
    //         }
    //     }
    // }
    // fn sendCancelCallback(
    //     self: *Self,
    //     completion: *IO.Completion,
    //     result: IO.CancelError!void,
    // ) void {
    //     if (result) |_| {
    //         std.debug.print("sendCancelCallback ok\n", .{});
    //     } else |err| {
    //         std.debug.print("sendCancelCallback err={s}\n", .{@errorName(err)});
    //     }
    // }
    // fn sendTimeoutCancelCallback(
    //     self: *Self,
    //     completion: *IO.Completion,
    //     result: IO.CancelTimeoutError!void,
    // ) void {
    //     if (result) |_| {
    //         std.debug.print("sendTimeoutCancelCallback ok\n", .{});
    //         self.recvWithTimeout();
    //     } else |err| {
    //         std.debug.print("sendTimeoutCancelCallback err={s}\n", .{@errorName(err)});
    //     }
    // }

    // fn recvWithTimeout(self: *Self) void {
    //     self.io.recv(
    //         *Self,
    //         self,
    //         recvCallback,
    //         &self.completions[0],
    //         self.sock,
    //         self.recv_buf,
    //         if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
    //     );
    //     self.io.timeout(
    //         *Self,
    //         self,
    //         recvTimeoutCallback,
    //         &self.completions[1],
    //         self.recv_timeout_ns,
    //     );
    // }
    // fn recvCallback(
    //     self: *Self,
    //     completion: *IO.Completion,
    //     result: IO.RecvError!usize,
    // ) void {
    //     if (result) |received| {
    //         std.debug.print("response={s}", .{self.recv_buf[0..received]});
    //         self.io.cancelTimeout(
    //             *Self,
    //             self,
    //             recvTimeoutCancelCallback,
    //             &self.completions[0],
    //             &self.completions[1],
    //         );
    //     } else |err| {
    //         std.debug.print("recv error: {s}\n", .{@errorName(err)});
    //     }
    // }
    // fn recvTimeoutCallback(
    //     self: *Self,
    //     completion: *IO.Completion,
    //     result: IO.TimeoutError!void,
    // ) void {
    //     if (result) |_| {
    //         std.debug.print("recvTimeoutCallback ok\n", .{});
    //         completion.io.cancel(
    //             *Self,
    //             self,
    //             recvCancelCallback,
    //             &self.completions[1],
    //             &self.completions[0],
    //         );
    //     } else |err| {
    //         std.debug.print("recvTimeoutCallback err={s}\n", .{@errorName(err)});
    //     }
    // }
    // fn recvCancelCallback(
    //     self: *Self,
    //     completion: *IO.Completion,
    //     result: IO.CancelError!void,
    // ) void {
    //     if (result) |_| {
    //         std.debug.print("recvCancelCallback ok\n", .{});
    //     } else |err| {
    //         std.debug.print("recvCancelCallback err={s}\n", .{@errorName(err)});
    //     }
    // }
    // fn recvTimeoutCancelCallback(
    //     self: *Self,
    //     completion: *IO.Completion,
    //     result: IO.CancelTimeoutError!void,
    // ) void {
    //     if (result) |_| {
    //         std.debug.print("recvTimeoutCancelCallback ok\n", .{});
    //     } else |err| {
    //         std.debug.print("recvTimeoutCancelCallback error: {s}\n", .{@errorName(err)});
    //     }
    //     self.close();
    // }

    // fn close(self: *Self) void {
    //     os.close(self.sock);
    //     self.done = true;
    //     std.debug.print("close and exit\n", .{});
    // }
};

const testing = std.testing;

test "TCPConn" {
    const allocator = std.heap.page_allocator;
    const port = 3131;

    var io = try IO.init(512, 0);
    defer io.deinit();
    const address = try std.net.Address.parseIp4("127.0.0.1", port);

    var conn = try TCPConn.init(&io, address);
    defer conn.deinit();

    const MyContext = struct {
        conn: TCPConn,

        const Self = @This();

        fn connect(self: *Self) void {
            self.conn.connectWithTimeout(*Self, self, 500 * time.ns_per_ms, connectCallback);
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
