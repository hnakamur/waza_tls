const std = @import("std");
const fifo = std.fifo;
const mem = std.mem;
const CipherSuite = @import("cipher_suites.zig").CipherSuite;

pub const HalfConn = struct {
    cipher: ?CipherSuite = null,

    pub fn encrypt(
        self: *HalfConn,
        payload: []const u8,
        writer: anytype,
    ) !void {
        if (self.cipher) |_| {} else {
            try writer.writeAll(payload);
            return;
        }

        @panic("not implemented yet");
    }
};

const testing = std.testing;

test "HalfConn.encrypt" {
    const allocator = testing.allocator;

    var buf = fifo.LinearFifo(u8, .Dynamic).init(allocator);
    defer buf.deinit();
    var writer = buf.writer();
    try writer.writeAll("hello, ");

    var hc = HalfConn{};
    try hc.encrypt("world", writer);
    try testing.expectEqualStrings("hello, world", buf.readableSlice(0));
}
