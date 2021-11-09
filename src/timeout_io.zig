const std = @import("std");
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;

pub const TimeoutIo = struct {
    io: *IO,

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

    pub fn init(io: *IO) TimeoutIo {
        return .{ .io = io };
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
        sock: os.socket_t,
        address: std.net.Address,
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
            sock,
            address,
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
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        completion.result = .{ .connect = result };
        if (result) |_| {
            self.io.cancelTimeout(
                *Self,
                self,
                connectTimeoutCancelCallback,
                &completion.completion1,
                &completion.completion2,
            );
        } else |_| {}
    }
    fn connectTimeoutCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            var completion = @fieldParentPtr(Completion, "completion2", io_completion);
            self.io.cancel(
                *Self,
                self,
                connectCancelCallback,
                &completion.completion2,
                &completion.completion1,
            );
        } else |_| {}
    }
    fn connectCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        _: IO.CancelError!void,
    ) void {
        var completion = @fieldParentPtr(Completion, "completion2", io_completion);
        completion.callback(completion.context, completion, completion.result);
    }
    fn connectTimeoutCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        _: IO.CancelTimeoutError!void,
    ) void {
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        completion.callback(completion.context, completion, completion.result);
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
        sock: os.socket_t,
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
            sock,
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
        } else |_| {}
    }
    fn sendTimeoutCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            var completion = @fieldParentPtr(Completion, "completion2", io_completion);
            self.io.cancel(
                *Self,
                self,
                sendCancelCallback,
                &completion.completion2,
                &completion.completion1,
            );
        } else |_| {}
    }
    fn sendCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        _: IO.CancelError!void,
    ) void {
        var completion = @fieldParentPtr(Completion, "completion2", io_completion);
        completion.callback(completion.context, completion, completion.result);
    }
    fn sendTimeoutCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        _: IO.CancelTimeoutError!void,
    ) void {
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        completion.callback(completion.context, completion, completion.result);
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
        sock: os.socket_t,
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
            sock,
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
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        completion.result = .{ .recv = result };
        if (result) |received| {
            self.io.cancelTimeout(
                *Self,
                self,
                recvTimeoutCancelCallback,
                &completion.completion1,
                &completion.completion2,
            );
        } else |_| {}
    }
    fn recvTimeoutCallback(
        self: *Self,
        io_completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            var completion = @fieldParentPtr(Completion, "completion2", io_completion);
            self.io.cancel(
                *Self,
                self,
                recvCancelCallback,
                &completion.completion2,
                &completion.completion1,
            );
        } else |_| {}
    }
    fn recvCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        _: IO.CancelError!void,
    ) void {
        var completion = @fieldParentPtr(Completion, "completion2", io_completion);
        completion.callback(completion.context, completion, completion.result);
    }
    fn recvTimeoutCancelCallback(
        self: *Self,
        io_completion: *IO.Completion,
        _: IO.CancelTimeoutError!void,
    ) void {
        var completion = @fieldParentPtr(Completion, "completion1", io_completion);
        completion.callback(completion.context, completion, completion.result);
    }
};
