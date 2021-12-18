const std = @import("std");
const fifo = std.fifo;

pub fn BytesBuf(
    comptime buffer_type: fifo.LinearFifoBufferType,
) type {
    return fifo.LinearFifo(u8, buffer_type);
}

pub const BytesView = struct {
    bytes: []const u8,
    eof: bool,
    pos: usize = 0,

    pub fn init(bytes: []const u8, eof: bool) BytesView {
        return .{ .bytes = bytes, .eof = eof };
    }

    pub fn peekByte(self: *const BytesView) ?u8 {
        if (self.pos >= self.bytes.len) {
            return null;
        }
        return self.bytes[self.pos];
    }

    pub fn advance(self: *BytesView, len: usize) void {
        self.pos += len;
    }

    pub fn rest(self: *const BytesView) []const u8 {
        return self.bytes[self.pos..];
    }

    pub fn ensureLen(self: *const BytesView, len: usize) !void {
        if (self.pos + len > self.bytes.len) {
            return if (self.eof) error.UnexpecedEof else error.ShortInput;
        }
    }

    pub fn getBytes(self: *const BytesView, len: usize) []const u8 {
        return self.bytes[self.pos .. self.pos + len];
    }

    pub fn getBytesPos(self: *const BytesView, pos: usize, len: usize) []const u8 {
        return self.bytes[self.pos + pos .. self.pos + pos + len];
    }
};

const testing = std.testing;

test "BytesView" {
    var vw = BytesView.init("zig", true);

    try testing.expectEqual(@as(?u8, 'z'), vw.peekByte());
    vw.advance(1);
    try testing.expectEqualStrings("ig", vw.rest());
    try testing.expectEqual(@as(?u8, 'i'), vw.peekByte());
    vw.advance(1);
    try testing.expectEqual(@as(?u8, 'g'), vw.peekByte());
    vw.advance(1);
    try testing.expectEqualStrings("", vw.rest());
    try testing.expectEqual(@as(?u8, null), vw.peekByte());
}
