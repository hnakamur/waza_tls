const std = @import("std");
const fifo = std.fifo;

pub fn BytesBuf(
    comptime buffer_type: fifo.LinearFifoBufferType,
) type {
    return fifo.LinearFifo(u8, buffer_type);
}

pub const BytesView = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) BytesView {
        return .{ .bytes = bytes };
    }

    pub fn readByte(self: *BytesView) ?u8 {
        if (self.pos >= self.bytes.len) {
            return null;
        }
        const b = self.bytes[self.pos];
        self.pos += 1;
        return b;
    }

    pub fn unreadByte(self: *BytesView) void {
        self.pos -= 1;
    }

    pub fn rest(self: *const BytesView) []const u8 {
        return self.bytes[self.pos..];
    }
};

const testing = std.testing;

test "BytesView" {
    var vw = BytesView.init("zig");

    try testing.expectEqual(@as(?u8, 'z'), vw.readByte());
    try testing.expectEqualStrings("ig", vw.rest());
    try testing.expectEqual(@as(?u8, 'i'), vw.readByte());
    try testing.expectEqual(@as(?u8, 'g'), vw.readByte());
    try testing.expectEqualStrings("", vw.rest());
    try testing.expectEqual(@as(?u8, null), vw.readByte());
}
