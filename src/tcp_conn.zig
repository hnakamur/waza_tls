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

    pub const Completion = struct {
        context: ?*c_void,
        callback: fn (ctx: ?*c_void, comp: *Completion, res: Result) void = undefined,
        result: Result = undefined,
        completion1: IO.Completion = undefined,
        completion2: IO.Completion = undefined,
    };

    const Result = union(enum) {
        connect: ConnectError!void,
        send: SendError!usize,
        recv: RecvError!usize,
    };

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

    pub const ConnectError = IO.ConnectError;

    pub fn connectWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: ConnectError!void,
        ) void,
        completion: *Completion,
        timeout_ns: u63,
    ) void {
        completion.context = context;
        completion.callback = struct {
            fn wrapper(ctx: ?*c_void, comp: *Completion, res: Result) void {
                callback(
                    @intToPtr(Context, @ptrToInt(ctx)),
                    comp,
                    res.connect,
                );
            }
        }.wrapper;
        self.io.connect(
            *Self,
            self,
            connectCallback,
            &completion.completion1,
            self.socket,
            self.address,
        );
        self.io.timeout(
            *Self,
            self,
            connectTimeoutCallback,
            &completion.completion2,
            timeout_ns,
        );
    }
    fn connectCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.ConnectError!void,
    ) void {
        std.debug.print("connectCallback self.result={}\n", .{result});
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        completion.result = .{ .connect = result };
        if (result) |_| {
            std.debug.print("connectCallback ok\n", .{});
            self.io.cancelTimeout(
                *Self,
                self,
                connectTimeoutCancelCallback,
                &completion.completion1,
                &completion.completion2,
            );
        } else |err| {
            std.debug.print("connectCallback err={s}\n", .{@errorName(err)});
        }
    }
    fn connectTimeoutCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("connectTimeoutCallback ok\n", .{});
            var completion = @fieldParentPtr(Completion, "completion2", io_completion);
            self.io.cancel(
                *Self,
                self,
                connectCancelCallback,
                &completion.completion2,
                &completion.completion1,
            );
        } else |err| {
            std.debug.print("connectTimeoutCallback err={s}\n", .{@errorName(err)});
        }
    }
    fn connectCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.CancelError!void,
    ) void {
        if (result) |_| {
            std.debug.print("connectCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("connectCancelCallback err={s}\n", .{@errorName(err)});
        }
        var completion = @fieldParentPtr(Completion, "completion2", io_completion);
        std.debug.print("connectCancelCallback calling callback, result={}\n", .{completion.result});
        completion.callback(completion.context, completion, completion.result);
        std.debug.print("connectCancelCallback called callback\n", .{});
    }
    fn connectTimeoutCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.CancelTimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("connectTimeoutCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("connectTimeoutCancelCallback err={s}\n", .{@errorName(err)});
        }
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        std.debug.print("connectTimeoutCancelCallback calling callback, result={}\n", .{completion.result});
        completion.callback(completion.context, completion, completion.result);
        std.debug.print("connectTimeoutCancelCallback called callback\n", .{});
    }

    pub const SendError = IO.SendError;

    pub fn sendWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: SendError!usize,
        ) void,
        completion: *Completion,
        buf: []const u8,
        timeout_ns: u63,
    ) void {
        completion.context = context;
        completion.callback = struct {
            fn wrapper(ctx: ?*c_void, comp: *Completion, res: Result) void {
                callback(
                    @intToPtr(Context, @ptrToInt(ctx)),
                    comp,
                    res.send,
                );
            }
        }.wrapper;
        self.io.send(
            *Self,
            self,
            sendCallback,
            &completion.completion1,
            self.socket,
            buf,
            if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
        );
        self.io.timeout(
            *Self,
            self,
            sendTimeoutCallback,
            &completion.completion2,
            timeout_ns,
        );
    }
    fn sendCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.SendError!usize,
    ) void {
        std.debug.print("TCPConn.sendCallback result={}\n", .{result});
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        completion.result = .{ .send = result };
        if (result) |sent| {
            self.io.cancelTimeout(
                *Self,
                self,
                sendTimeoutCancelCallback,
                &completion.completion1,
                &completion.completion2,
            );
        } else |err| {
            std.debug.print("send error: {s}\n", .{@errorName(err)});
        }
    }
    fn sendTimeoutCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("sendTimeoutCallback ok\n", .{});
            var completion = @fieldParentPtr(Completion, "completion2", io_completion);
            self.io.cancel(
                *Self,
                self,
                sendCancelCallback,
                &completion.completion2,
                &completion.completion1,
            );
        } else |err| {
            if (err != error.Canceled) {
                std.debug.print("sendTimeoutCallback err={s}\n", .{@errorName(err)});
            }
        }
    }
    fn sendCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.CancelError!void,
    ) void {
        if (result) |_| {
            std.debug.print("sendCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("sendCancelCallback err={s}\n", .{@errorName(err)});
        }
        var completion = @fieldParentPtr(Completion, "completion2", io_completion);
        std.debug.print("TCPConn.sendCancelCallback calling callback, result={}\n", .{completion.result});
        completion.callback(completion.context, completion, completion.result);
        std.debug.print("TCPConn.sendCancelCallback called callback\n", .{});
    }
    fn sendTimeoutCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.CancelTimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("sendTimeoutCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("sendTimeoutCancelCallback err={s}\n", .{@errorName(err)});
        }
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        std.debug.print("TCPConn.sendTimeoutCancelCallback calling callback, result={}\n", .{completion.result});
        completion.callback(completion.context, completion, completion.result);
        std.debug.print("TCPConn.sendTimeoutCancelCallback called callback\n", .{});
    }

    pub const RecvError = IO.RecvError;

    pub fn recvWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: RecvError!usize,
        ) void,
        completion: *Completion,
        buf: []u8,
        timeout_ns: u63,
    ) void {
        completion.context = context;
        completion.callback = struct {
            fn wrapper(ctx: ?*c_void, comp: *Completion, res: Result) void {
                callback(
                    @intToPtr(Context, @ptrToInt(ctx)),
                    comp,
                    res.recv,
                );
            }
        }.wrapper;
        self.io.recv(
            *Self,
            self,
            recvCallback,
            &completion.completion1,
            self.socket,
            buf,
            if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
        );
        self.io.timeout(
            *Self,
            self,
            recvTimeoutCallback,
            &completion.completion2,
            timeout_ns,
        );
    }
    fn recvCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.RecvError!usize,
    ) void {
        if (result) |received| {
            std.debug.print("TCPConn.recvCallback result={}", .{result});
            var completion = @fieldParentPtr(Completion, "completion1", io_completion);
            completion.result = .{ .recv = result };
            self.io.cancelTimeout(
                *Self,
                self,
                recvTimeoutCancelCallback,
                &completion.completion1,
                &completion.completion2,
            );
        } else |err| {
            std.debug.print("recv error: {s}\n", .{@errorName(err)});
        }
    }
    fn recvTimeoutCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("recvTimeoutCallback ok\n", .{});
            var completion = @fieldParentPtr(Completion, "completion2", io_completion);
            self.io.cancel(
                *Self,
                self,
                recvCancelCallback,
                &completion.completion2,
                &completion.completion1,
            );
        } else |err| {
            std.debug.print("recvTimeoutCallback err={s}\n", .{@errorName(err)});
        }
    }
    fn recvCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.CancelError!void,
    ) void {
        if (result) |_| {
            std.debug.print("recvCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("recvCancelCallback err={s}\n", .{@errorName(err)});
        }
        var completion = @fieldParentPtr(Completion, "completion2", io_completion);
        std.debug.print("TCPConn.recvCancelCallback calling callback, result={}\n", .{completion.result});
        completion.callback(completion.context, completion, completion.result);
        std.debug.print("TCPConn.recvCancelCallback called callback\n", .{});
    }
    fn recvTimeoutCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.CancelTimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("recvTimeoutCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("recvTimeoutCancelCallback error: {s}\n", .{@errorName(err)});
        }
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        std.debug.print("TCPConn.recvTimeoutCancelCallback calling callback, result={}\n", .{completion.result});
        completion.callback(completion.context, completion, completion.result);
        std.debug.print("TCPConn.recvTimeoutCancelCallback called callback\n", .{});
    }
};

const testing = std.testing;

// test "TCPConn" {
//     const allocator = std.heap.page_allocator;
//     const port = 3131;

//     var io = try IO.init(512, 0);
//     defer io.deinit();
//     const address = try std.net.Address.parseIp4("127.0.0.1", port);

//     var conn = try TCPConn.init(&io, address);
//     defer conn.deinit();

//     const MyContext = struct {
//         conn: TCPConn,

//         const Self = @This();

//         fn connect(self: *Self) void {
//             self.conn.connectWithTimeout(*Self, self, 500 * time.ns_per_ms, connectCallback);
//         }
//         fn connectCallback(
//             self: *Self,
//             result: TCPConn.ConnectWithTimeoutError!void,
//         ) void {
//             std.debug.print("MyContext.connectCallback, result={}\n", .{result});
//         }
//     };
//     var ctx = MyContext{ .conn = conn };
//     ctx.connect();

//     try io.run_for_ns(time.ns_per_s);
// }

// test "TCPConn Completion" {
//     var c = TCPConn.Completion{};
//     var ioc = &c.completions[1];
//     try testing.expectEqual(&c, @fieldParentPtr(TCPConn.Completion, "completions[1]", ioc));
// }
