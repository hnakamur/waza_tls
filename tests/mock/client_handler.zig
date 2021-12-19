const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

test "mock / io" {
    try struct {
        const Context = @This();

        io: IO,
        buffer: [1024]u8 = [_]u8{0} ** 1024,
        received: usize = undefined,

        fn run() !void {
            var self: Context = .{ .io = try IO.init(1, 0) };
            defer self.io.deinit();

            var completion: IO.LinkedCompletion = undefined;
            const socket: os.socket_t = 0;
            const recv_flags: u32 = if (builtin.target.os.tag == .linux) os.MSG.NOSIGNAL else 0;
            const timeout_ns: u63 = time.ns_per_ms;

            self.io.recvWithTimeout(
                *Context,
                &self,
                recvWithTimeoutCallback,
                &completion,
                socket,
                &self.buffer,
                recv_flags,
                timeout_ns,
            );

            try self.io.tick(*Context, &self, setResult);

            try testing.expectEqual(self.buffer.len, self.received);
        }

        fn recvWithTimeoutCallback(
            self: *Context,
            _: *IO.LinkedCompletion,
            result: IO.RecvError!usize,
        ) void {
            self.received = result catch @panic("recv error");
        }

        fn setResult(
            self: *Context,
            completion: *IO.Completion,
        ) void {
            switch (completion.operation) {
                .recv => completion.result = self.buffer.len,
                .link_timeout => completion.result = -@as(i32, @enumToInt(os.E.CANCELED)),
                else => {},
            }
        }
    }.run();
}
