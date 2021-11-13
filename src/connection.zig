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
        timeout_ns: u63,
    ) void {
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
            if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
            timeout_ns,
        );
    }
    pub fn recvWithTimeoutCallback(
        self: *Self,
        linked_completion: *IO.LinkedCompletion,
        result: IO.RecvError!usize,
    ) void {
        const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
        comp.callback(comp.ctx, &result);
    }

    pub fn sendWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            result: IO.SendError!usize,
        ) void,
        completion: *Completion,
        buffer: []const u8,
        timeout_ns: u63,
    ) void {
        completion.ctx = context;
        completion.callback = struct {
            fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                callback(
                    @intToPtr(Context, @ptrToInt(ctx)),
                    @intToPtr(*const IO.SendError!usize, @ptrToInt(res)).*,
                );
            }
        }.wrapper;
        self.io.sendWithTimeout(
            *Self,
            self,
            sendWithTimeoutCallback,
            &completion.linked_completion,
            self.sock,
            buffer,
            if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
            timeout_ns,
        );
    }
    pub fn sendWithTimeoutCallback(
        self: *Self,
        linked_completion: *IO.LinkedCompletion,
        result: IO.SendError!usize,
    ) void {
        const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
        comp.callback(comp.ctx, &result);
    }
};

const testing = std.testing;

test "SocketConnection" {
    try struct {
        const Context = @This();

        io: *IO,
        recv_buf: [1024]u8 = [_]u8{1} ** 1024,
        send_buf: [1024]u8 = [_]u8{0} ** 1024,
        done: bool = false,
        accepted_conn: SocketConnection = undefined,
        server_completion: SocketConnection.Completion = undefined,
        client_conn: SocketConnection = undefined,
        client_completion: SocketConnection.Completion = undefined,
        received: usize = undefined,
        sent: usize = undefined,

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            var self: Context = .{ .io = &io };

            const address = try std.net.Address.parseIp4("127.0.0.1", 3131);
            const kernel_backlog = 1;
            const server_sock = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
            defer os.close(server_sock);

            const client_sock = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
            defer os.close(client_sock);
            self.client_conn = .{
                .io = &io,
                .sock = client_sock,
            };

            try os.setsockopt(
                server_sock,
                os.SOL_SOCKET,
                os.SO_REUSEADDR,
                &std.mem.toBytes(@as(c_int, 1)),
            );
            try os.bind(server_sock, &address.any, address.getOsSockLen());
            try os.listen(server_sock, kernel_backlog);

            var client_completion: IO.Completion = undefined;
            self.io.connect(
                *Context,
                &self,
                connectCallback,
                &client_completion,
                client_sock,
                address,
            );

            var server_completion: IO.Completion = undefined;
            self.io.accept(
                *Context,
                &self,
                acceptCallback,
                &server_completion,
                server_sock,
                0,
            );

            while (!self.done) {
                try self.io.tick();
            }
            try testing.expectEqual(self.send_buf.len, self.sent);
            try testing.expectEqual(self.recv_buf.len, self.received);
            try testing.expectEqualSlices(u8, self.send_buf[0..self.received], &self.recv_buf);
        }

        fn acceptCallback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.AcceptError!os.socket_t,
        ) void {
            self.accepted_conn = .{
                .io = completion.io,
                .sock = result catch @panic("accept error"),
            };
            self.accepted_conn.recvWithTimeout(
                *Context,
                self,
                recvWithTimeoutCallback,
                &self.server_completion,
                &self.recv_buf,
                time.ns_per_ms,
            );
        }
        fn recvWithTimeoutCallback(
            self: *Context,
            result: IO.RecvError!usize,
        ) void {
            self.received = result catch @panic("receive error");
            self.done = true;
        }

        fn connectCallback(
            self: *Context,
            completion: *IO.Completion,
            result: IO.ConnectError!void,
        ) void {
            result catch @panic("connect error");
            self.client_conn.sendWithTimeout(
                *Context,
                self,
                sendWithTimeoutCallback,
                &self.client_completion,
                &self.send_buf,
                time.ns_per_ms,
            );
        }
        fn sendWithTimeoutCallback(
            self: *Context,
            result: IO.SendError!usize,
        ) void {
            self.sent = result catch @panic("send error");
        }
    }.runTest();
}
