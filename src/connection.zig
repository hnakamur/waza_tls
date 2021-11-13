const std = @import("std");
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;

pub const Connection = struct {};

pub const SocketConnection = struct {
    io: *IO,
    sock: os.socket_t,

    const Completion = struct {
        linked_completion: IO.LinkedCompletion = undefined,
        ctx: ?*c_void = null,
        callback: fn (ctx: ?*c_void, res: *const c_void) void = undefined,
    };

    const Self = @This();

    pub fn init(io: *IO, sock: os.socket_t) SocketConnection {
        return .{ .io = io, .sock = sock };
    }

    pub fn recvWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            result: IO.RecvError!usize,
        ) void,
        completion: *Completion,
        buffer: []u8,
        recv_flags: u32,
        timeout_ns: u63,
    ) void {
        std.debug.print("recvWithTimeout self=0x{x}, context=0x{x}\n", .{ @ptrToInt(self), @ptrToInt(context) });
        completion.ctx = context;
        completion.callback = struct {
            fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                callback(
                    @intToPtr(Context, @ptrToInt(ctx)),
                    @intToPtr(*const IO.RecvError!usize, @ptrToInt(res)).*,
                );
            }
        }.wrapper;
        self.io.recvWithTimeout(
            *Self,
            self,
            recvWithTimeoutCallback,
            &completion.linked_completion,
            self.sock,
            buffer,
            recv_flags,
            timeout_ns,
        );
    }
    pub fn recvWithTimeoutCallback(
        self: *Self,
        linked_completion: *IO.LinkedCompletion,
        result: IO.RecvError!usize,
    ) void {
        const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
        std.debug.print("recvWithTimeoutCallback comp=0x{x}\n", .{ @ptrToInt(comp) });
        comp.callback(comp.ctx, &result);
    }

    pub fn sendWithTimeout(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            result: SendError!usize,
        ) void,
        buffer: []const u8,
        send_flags: u32,
        timeout_ns: u63,
    ) void {}
};

const testing = std.testing;

test "SocketConnection" {
    try struct {
        const Context = @This();

        io: *IO,
        recv_buf: [1024]u8 = [_]u8{0} ** 1024,
        send_buf: [1024]u8 = [_]u8{0} ** 1024,
        done: bool = false,
        server_sock: os.socket_t = undefined,
        client_sock: os.socket_t = undefined,
        accepted_sock: os.socket_t = undefined,
        accepted_conn: SocketConnection = undefined,
        server_completion: SocketConnection.Completion = undefined,

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            var self: Context = .{ .io = &io };

            const address = try std.net.Address.parseIp4("127.0.0.1", 3131);
            const kernel_backlog = 1;
            self.server_sock = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
            defer os.close(self.server_sock);

            self.client_sock = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
            defer os.close(self.client_sock);

            try os.setsockopt(
                self.server_sock,
                os.SOL_SOCKET,
                os.SO_REUSEADDR,
                &std.mem.toBytes(@as(c_int, 1)),
            );
            try os.bind(self.server_sock, &address.any, address.getOsSockLen());
            try os.listen(self.server_sock, kernel_backlog);

            var client_completion: IO.Completion = undefined;
            self.io.connect(
                *Context,
                &self,
                connectCallback,
                &client_completion,
                self.client_sock,
                address,
            );

            var server_completion: IO.Completion = undefined;
            self.io.accept(
                *Context,
                &self,
                acceptCallback,
                &server_completion,
                self.server_sock,
                0,
            );

            std.debug.print("main self=0x{x}\n", .{@ptrToInt(&self)});
            while (!self.done) {
                try self.io.tick();
                // std.debug.print("after tick, self.done={}\n", .{self.done});
            }
            std.debug.print("exiting runTest\n", .{});
        }

        fn acceptCallback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.AcceptError!os.socket_t,
        ) void {
            std.debug.print("acceptCallback, result={}\n", .{result});
            std.debug.print("acceptCallback, self=0x{x}\n", .{@ptrToInt(self)});
            self.accepted_conn = .{
                .io = completion.io,
                .sock = result catch @panic("accept error"),
            };
            std.debug.print("acceptCallback, self.accepted_conn=0x{x}\n", .{@ptrToInt(&self.accepted_conn)});
            self.accepted_conn.recvWithTimeout(
                *Context,
                self,
                recvWithTimeoutCallback,
                &self.server_completion,
                &self.recv_buf,
                if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
                time.ns_per_ms,
            );
        }
        fn recvWithTimeoutCallback(
            self: *Context,
            result: IO.RecvError!usize,
        ) void {
            std.debug.print("recvWithTimeoutCallback result={}\n", .{result});
            std.debug.print("recvWithTimeoutCallback self=0x{x}\n", .{@ptrToInt(self)});
            self.done = true;
            std.debug.print("set self.done to {}\n", .{self.done});
        }

        fn connectCallback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.ConnectError!void,
        ) void {
            std.debug.print("connectCallback result={}\n", .{result});
            result catch @panic("connect error");
            self.io.send(
                *Context,
                self,
                sendCallback,
                completion,
                self.client_sock,
                &self.send_buf,
                if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
            );
        }
        fn sendCallback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.SendError!usize,
        ) void {
            std.debug.print("sendCallback result={}\n", .{result});
            _ = result catch @panic("send error");
        }
    }.runTest();
    std.debug.print("exit SocketConnection test\n", .{});
}
