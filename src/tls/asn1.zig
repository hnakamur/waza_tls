const std = @import("std");
const mem = std.mem;

// Tag represents an ASN.1 identifier octet, consisting of a tag number
// (indicating a type) and class (such as context-specific or constructed).
//
// Methods in the cryptobyte package only support the low-tag-number form, i.e.
// a single identifier octet with bits 7-8 encoding the class and bits 1-6
// encoding the tag number.
pub const Tag = enum(u8) {
    const class_constructed = 0x20;
    const class_context_specific = 0x80;

    // The following is a list of standard tag and class combinations.
    boolean = 1,
    integer = 2,
    bit_string = 3,
    octet_string = 4,
    @"null" = 5,
    object_identifier = 6,
    @"enum" = 10,
    utf8_string = 12,
    sequence = 16 | class_constructed,
    set = 17 | class_constructed,
    printable_string = 19,
    t61_string = 20,
    ia5_string = 22,
    utc_time = 23,
    generalized_time = 24,
    general_string = 27,
    _,

    pub fn constructed(self: Tag) Tag {
        return @intToEnum(Tag, @enumToInt(self) | class_constructed);
    }

    pub fn contextSpecific(self: Tag) Tag {
        return @intToEnum(Tag, @enumToInt(self) | class_context_specific);
    }
};

pub const String = struct {
    pub const Error = error{EndOfStream};

    data: []const u8,

    pub fn init(data: []const u8) String {
        return .{ .data = data };
    }

    // skip advances the String by n bytes.
    pub fn skip(self: *String, n: usize) Error!void {
        _ = try self.readBytes(n);
    }

    pub fn readInt(self: *String, comptime T: type) Error!T {
        const n = @divExact(@typeInfo(T).Int.bits, 8);
        if (self.data.len < n) {
            return error.EndOfStream;
        }
        const v = mem.readIntBig(T, self.data[0..n]);
        self.data = self.data[n..];
        return v;
    }

    // readLengthPrefixed reads the content of a type T length-prefixed value
    // into out and advances over it.
    pub fn readLengthPrefixed(self: *String, comptime T: type) Error![]const u8 {
        const len = try self.readInt(T);
        return try self.readBytes(len);
    }

    // readBytes reads n bytes and advances over them.
    pub fn readBytes(self: *String, n: usize) Error![]const u8 {
        if (self.data.len < n) {
            return error.EndOfStream;
        }
        const v = self.data[0..n];
        self.data = self.data[n..];
        return v;
    }

    // copyBytes copies out.len bytes into out and advances over them.
    pub fn copyBytes(self: *String, out: []u8) Error!void {
        if (self.data.len < out.len) {
            return error.EndOfStream;
        }
        mem.copy(u8, out, self.data[0..out.len]);
        self.data = self.data[out.len..];
    }

    // Empty reports whether the string does not contain any bytes.
    pub fn empty(self: *const String) bool {
        return self.data.len == 0;
    }
};

const testing = std.testing;

test "asn1.Tag" {
    try testing.expectEqual(@intToEnum(Tag, 0x2c), Tag.utf8_string.constructed());
    try testing.expectEqual(@intToEnum(Tag, 0x8c), Tag.utf8_string.contextSpecific());
}

test "String.readBytes" {
    const data = "zig is great";
    var s = String.init(data);

    try testing.expectEqualStrings("zig", try s.readBytes(3));
    try testing.expectEqualStrings(" is great", s.data);

    try testing.expectEqualStrings(" is", try s.readBytes(3));
    try testing.expectEqualStrings(" great", s.data);

    try testing.expectError(error.EndOfStream, s.readBytes(s.data.len + 1));
}

test "String.copyBytes" {
    const data = "zig is great";
    var s = String.init(data);

    var out: [5]u8 = undefined;
    try s.copyBytes(&out);
    try testing.expectEqualStrings("zig i", &out);
    try testing.expectEqualStrings("s great", s.data);

    try s.copyBytes(&out);
    try testing.expectEqualStrings("s gre", &out);
    try testing.expectEqualStrings("at", s.data);

    try testing.expectError(error.EndOfStream, s.copyBytes(&out));
}

test "String.readInt" {
    var s = String.init("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a");
    try testing.expectEqual(@as(u8, 0x01), try s.readInt(u8));
    try testing.expectEqual(@as(u16, 0x0203), try s.readInt(u16));
    try testing.expectEqual(@as(u24, 0x040506), try s.readInt(u24));
    try testing.expectEqual(@as(u32, 0x0708090a), try s.readInt(u32));
}

test "String.readLengthPrefixed" {
    var s = String.init("\x03abc\x00\x03def\x00\x00\x03ghi\x00\x00\x00\x03jkl");
    try testing.expectEqualStrings("abc", try s.readLengthPrefixed(u8));
    try testing.expectEqualStrings("def", try s.readLengthPrefixed(u16));
    try testing.expectEqualStrings("ghi", try s.readLengthPrefixed(u24));
    try testing.expectEqualStrings("jkl", try s.readLengthPrefixed(u32));
    try testing.expect(s.empty());
}

test "String.skip" {
    var s = String.init("abcdef");

    try s.skip(3);
    try testing.expect(!s.empty());

    try testing.expectError(error.EndOfStream, s.skip(4));
    try testing.expect(!s.empty());

    try s.skip(3);
    try testing.expect(s.empty());
}

test "std.mem.readIntBig" {
    const data = "\xff";
    const got = mem.readIntBig(i8, data);
    try testing.expectEqual(@as(i8, -1), got);
}
