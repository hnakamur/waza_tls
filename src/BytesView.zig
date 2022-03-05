const std = @import("std");
const io = std.io;
const math = std.math;
const mem = std.mem;

pub const BytesView = @This();
pub const ReadError = error{};
pub const Reader = io.Reader(*BytesView, ReadError, read);
pub const Error = error{EndOfStream};

bytes: []const u8,
pos: usize = 0,

pub fn init(bytes: []const u8) BytesView {
    return .{ .bytes = bytes };
}

pub fn peekByte(self: *const BytesView) ?u8 {
    if (self.pos >= self.bytes.len) {
        return null;
    }
    return self.bytes[self.pos];
}

pub fn skip(self: *BytesView, len: usize) void {
    self.pos = math.min(self.pos + len, self.bytes.len);
}

pub fn sliceBytesNoEof(self: *BytesView, num_bytes: usize) Error![]const u8 {
    try self.ensureRestLen(num_bytes);
    const bytes = self.bytes[self.pos .. self.pos + num_bytes];
    self.skip(num_bytes);
    return bytes;
}

pub fn rest(self: *const BytesView) []const u8 {
    return self.bytes[self.pos..];
}

pub fn restLen(self: *const BytesView) usize {
    return self.bytes.len - self.pos;
}

pub fn ensureRestLen(self: *const BytesView, len: usize) Error!void {
    if (len > self.restLen()) {
        return error.EndOfStream;
    }
}

/// Returns the number of bytes read. It may be less than buffer.len.
/// If the number of bytes read is 0, it means end of stream.
/// End of stream is not an error condition.
fn read(self: *BytesView, buffer: []u8) ReadError!usize {
    const copy_len = math.min(buffer.len, self.restLen());
    mem.copy(u8, buffer, self.bytes[self.pos .. self.pos + copy_len]);
    self.skip(copy_len);
    return copy_len;
}

pub fn reader(self: *BytesView) Reader {
    return .{ .context = self };
}

/// Returns the number of bytes read. If the number read is smaller than `buffer.len`, it
/// means the stream reached the end. Reaching the end of a stream is not an error
/// condition.
fn readAll(self: *BytesView, buffer: []u8) ReadError!usize {
    return try self.read(buffer);
}

/// If the number read would be smaller than `buf.len`, `error.EndOfStream` is returned instead.
pub fn readNoEof(self: *BytesView, buf: []u8) !void {
    try self.ensureRestLen(buf.len);
    _ = try self.readAll(buf);
}

/// Reads 1 byte from the stream or returns `error.EndOfStream`.
pub fn readByte(self: *BytesView) !u8 {
    try self.ensureRestLen(1);
    const b = self.bytes[self.pos];
    self.skip(1);
    return b;
}

/// Reads exactly `num_bytes` bytes and returns as an array.
/// `num_bytes` must be comptime-known.
/// Note `self.pos` is not modified when `error.EndOfStream` is returned.
pub fn readBytesNoEof(self: *BytesView, comptime num_bytes: usize) ![num_bytes]u8 {
    var bytes: [num_bytes]u8 = undefined;
    try self.readNoEof(&bytes);
    return bytes;
}

/// Note `self.pos` is not modified when `error.EndOfStream` is returned.
pub fn readIntBig(self: *BytesView, comptime T: type) !T {
    const bytes = try self.readBytesNoEof((@typeInfo(T).Int.bits + 7) / 8);
    return mem.readIntBig(T, &bytes);
}

pub fn readInt(self: *BytesView, comptime T: type, endian: std.builtin.Endian) !T {
    const bytes = try self.readBytesNoEof((@typeInfo(T).Int.bits + 7) / 8);
    return mem.readInt(T, &bytes, endian);
}

/// Reads an integer with the same size as the given enum's tag type. If the integer matches
/// an enum tag, casts the integer to the enum tag and returns it. Otherwise, returns an error.
/// TODO optimization taking advantage of most fields being in order
pub fn readEnum(self: *BytesView, comptime Enum: type, endian: std.builtin.Endian) !Enum {
    const type_info = @typeInfo(Enum).Enum;
    const tag = try self.readInt(type_info.tag_type, endian);

    if (type_info.is_exhaustive) {
        const E = error{
            /// An integer was read, but it did not match any of the tags in the supplied enum.
            InvalidValue,
        };

        inline for (std.meta.fields(Enum)) |field| {
            if (tag == field.value) {
                return @field(Enum, field.name);
            }
        }
        return E.InvalidValue;
    } else {
        return @intToEnum(Enum, tag);
    }
}

/// `len` must be equal to or less than `self.restLen()` or panics.
pub fn getBytes(self: *const BytesView, len: usize) []const u8 {
    return self.bytes[self.pos .. self.pos + len];
}

/// `len` must be equal to or less than `self.restLen()` or panics.
pub fn getBytesPos(self: *const BytesView, pos: usize, len: usize) []const u8 {
    return self.bytes[self.pos + pos .. self.pos + pos + len];
}

/// Reads `slice.len` bytes from the stream and returns if they are the same as the passed slice
pub fn isBytes(self: *const BytesView, slice: []const u8) !bool {
    try self.ensureRestLen(slice.len);
    return mem.eql(u8, self.bytes[self.pos .. self.pos + slice.len], slice);
}

pub fn empty(self: *const BytesView) bool {
    return self.pos == self.bytes.len;
}

pub fn readLenPrefixedBytes(
    bv: *BytesView,
    comptime LenType: type,
    endian: std.builtin.Endian,
) ![]const u8 {
    const len = try bv.readInt(LenType, endian);
    return try bv.sliceBytesNoEof(len);
}

const testing = std.testing;
const assert = std.debug.assert;

test "BytesView bytes operations" {
    var vw = BytesView.init("zig is great");
    try testing.expectEqual(@as(?u8, 'z'), vw.peekByte());
    vw.skip(1);
    try testing.expectEqual(@as(usize, 11), vw.restLen());
    try testing.expectEqualStrings("ig is great", vw.rest());
    var r = vw.reader();
    try testing.expectEqual(@as(u8, 'i'), try r.readByte());
    try testing.expectEqualStrings("g ", &(try r.readBytesNoEof(2)));
    try testing.expectEqualStrings("is", vw.getBytes(2));
    try testing.expectEqualStrings("great", vw.getBytesPos(3, 5));
    try testing.expectError(error.EndOfStream, vw.sliceBytesNoEof(9));
    try testing.expectEqualStrings("is great", try vw.sliceBytesNoEof(8));
    try testing.expectEqualStrings("", vw.rest());
    try testing.expectEqual(@as(?u8, null), vw.peekByte());
}

test "BytesView.readNoEof" {
    var vw = BytesView.init("zig is great");
    var buf = [_]u8{0} ** 7;
    try vw.readNoEof(&buf);
    try testing.expectEqualStrings("zig is ", &buf);
    try testing.expectError(error.EndOfStream, vw.readNoEof(&buf));
    try testing.expectEqualStrings("zig is ", &buf);
    try vw.readNoEof(buf[0..5]);
    try testing.expectEqualStrings("great", buf[0..5]);
}

test "BytesView.read" {
    var vw = BytesView.init("zig is great");
    var buf = [_]u8{0} ** 7;
    try testing.expectEqual(@as(usize, 7), try vw.read(&buf));
    try testing.expectEqualStrings("zig is ", &buf);
    try testing.expectEqual(@as(usize, 5), try vw.read(&buf));
    try testing.expectEqualStrings("great", buf[0..5]);
}

test "BytesView.readByte" {
    var vw = BytesView.init("\x12\x34");
    try testing.expectEqual(@as(u8, 0x12), try vw.readByte());
}

test "BytesView.isBytes" {
    var vw = BytesView.init("zig is great");
    try testing.expect(try vw.isBytes("zig"));
    try testing.expect(!try vw.isBytes("zag"));
    try testing.expect(try vw.isBytes("zig"));
    try testing.expectError(error.EndOfStream, vw.isBytes("zig is great!"));
}

test "BytesView.readIntBig" {
    var vw = BytesView.init("\x12\x34");
    try testing.expectEqual(@as(u16, 0x1234), try vw.readIntBig(u16));
}

test "BytesView.reader.readIntBig" {
    var vw = BytesView.init("\x12\x34");
    try testing.expectEqual(@as(u16, 0x1234), try vw.reader().readIntBig(u16));
}

test "BytesView.readEnum exhaustive" {
    const ProtocolVersion = enum(u16) {
        v1_3 = 0x0304,
        v1_2 = 0x0303,
        v1_0 = 0x0301,
    };
    assert(@typeInfo(ProtocolVersion).Enum.is_exhaustive);

    var bv = BytesView.init("\x03\x04\x03\x01\x00\x00");
    try testing.expectEqual(ProtocolVersion.v1_3, try bv.readEnum(ProtocolVersion, .Big));
    try testing.expectEqual(ProtocolVersion.v1_0, try bv.readEnum(ProtocolVersion, .Big));
    try testing.expectError(error.InvalidValue, bv.readEnum(ProtocolVersion, .Big));
}

test "BytesView.readEnum non-exhaustive" {
    const NonExhaustiveEnum = enum(u8) {
        a = 1,
        _,
    };
    assert(!@typeInfo(NonExhaustiveEnum).Enum.is_exhaustive);

    var bv = BytesView.init("\x01\x02");
    try testing.expectEqual(NonExhaustiveEnum.a, try bv.readEnum(NonExhaustiveEnum, .Big));
    try testing.expectEqual(
        @intToEnum(NonExhaustiveEnum, 2),
        try bv.readEnum(NonExhaustiveEnum, .Big),
    );
}
