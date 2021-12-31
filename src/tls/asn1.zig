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

    pub fn isHighTag(self: Tag) bool {
        return @enumToInt(self) & 0x1f == 0x1f;
    }
};

pub const String = struct {
    data: []const u8,

    pub fn init(data: []const u8) String {
        return .{ .data = data };
    }

    // skip advances the String by n bytes.
    pub fn skip(self: *String, n: usize) !void {
        _ = try self.readBytes(n);
    }

    pub fn readIntOfType(self: *String, comptime T: type) !T {
        const n = @divExact(@typeInfo(T).Int.bits, 8);
        if (self.data.len < n) {
            return error.EndOfStream;
        }
        const v = mem.readIntBig(T, self.data[0..n]);
        self.data = self.data[n..];
        return v;
    }

    pub fn readUnsigned(self: *String, len: usize) !u32 {
        return switch (len) {
            1 => try self.readIntOfType(u8),
            2 => try self.readIntOfType(u16),
            3 => try self.readIntOfType(u24),
            4 => try self.readIntOfType(u32),
            else => error.UnsupportedIntLength,
        };
    }

    // readLengthOfTypePrefixed reads the content of a type T length-prefixed value
    // into out and advances over it.
    pub fn readLengthOfTypePrefixed(self: *String, comptime T: type) ![]const u8 {
        const len = try self.readIntOfType(T);
        return try self.readBytes(len);
    }

    // readLengthPrefixed reads the content of a length-prefixed value
    // into out and advances over it.
    pub fn readLengthPrefixed(self: *String, len_len: usize) ![]const u8 {
        const len = try self.readUnsigned(len_len);
        return try self.readBytes(len);
    }

    // readBytes reads n bytes and advances over them.
    pub fn readBytes(self: *String, n: usize) ![]const u8 {
        if (self.data.len < n) {
            return error.EndOfStream;
        }
        const v = self.data[0..n];
        self.data = self.data[n..];
        return v;
    }

    // copyBytes copies out.len bytes into out and advances over them.
    pub fn copyBytes(self: *String, out: []u8) !void {
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

    fn readAsn1(self: *String, out_tag: ?*Tag, skip_header: bool) !String {
        if (self.data.len < 2) {
            return error.EndOfStream;
        }

        const tag = @intToEnum(Tag, self.data[0]);
        if (tag.isHighTag()) {
            // ITU-T X.690 section 8.1.2
            //
            // An identifier octet with a tag part of 0x1f indicates a high-tag-number
            // form identifier with two or more octets. We only support tags less than
            // 31 (i.e. low-tag-number form, single octet identifier).
            return error.HighTagNotSupported;
        }

        if (out_tag) |t| {
            t.* = tag;
        }

        const len_byte = self.data[1];

        // ITU-T X.690 section 8.1.3
        //
        // Bit 8 of the first length byte indicates whether the length is short- or
        // long-form.
        var length: u32 = undefined;
        var header_len: u32 = undefined; // length includes header_len
        if (len_byte & 0x80 == 0) {
            // Short-form length (section 8.1.3.4), encoded in bits 1-7.
            length = len_byte + 2;
            header_len = 2;
        } else {
            // Long-form length (section 8.1.3.5). Bits 1-7 encode the number of octets
            // used to encode the length.
            const len_len = len_byte & 0x7f;
            if (len_len == 0 or len_len > 4 or self.data.len < 2 + len_len) {
                return error.InvalidLength;
            }

            var len_bytes = String.init(self.data[2 .. 2 + len_len]);
            const len32 = try len_bytes.readUnsigned(len_len);

            // ITU-T X.690 section 10.1 (DER length forms) requires encoding the length
            // with the minimum number of octets.
            if (len32 < 128) {
                // Length should have used short-form encoding.
                return error.InvalidLength;
            }
            if (len32 >> (len_len - 1) * 8 == 0) {
                // Leading octet is 0. Length should have been at least one byte shorter.
                return error.InvalidLength;
            }

            header_len = 2 + len_len;
            length = header_len +% len32;
            if (length < len32) {
                // Overflow.
                return error.InvalidLength;
            }
        }

        if (@bitCast(i32, length) < 0) {
            return error.InvalidLength;
        }
        var out = try self.readBytes(length);
        if (skip_header) {
            try out.skip(header_len);
        }
        return out;
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

test "String.readUnsigned" {
    var s = String.init("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a");
    try testing.expectEqual(@as(u32, 0x01), try s.readUnsigned(1));
    try testing.expectEqual(@as(u32, 0x0203), try s.readUnsigned(2));
    try testing.expectEqual(@as(u32, 0x040506), try s.readUnsigned(3));
    try testing.expectEqual(@as(u32, 0x0708090a), try s.readUnsigned(4));
}

test "String.readLengthPrefixed" {
    var s = String.init("\x03abc\x00\x03def\x00\x00\x03ghi\x00\x00\x00\x03jkl");
    try testing.expectEqualStrings("abc", try s.readLengthPrefixed(1));
    try testing.expectEqualStrings("def", try s.readLengthPrefixed(2));
    try testing.expectEqualStrings("ghi", try s.readLengthPrefixed(3));
    try testing.expectEqualStrings("jkl", try s.readLengthPrefixed(4));
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

test "u32/i32" {
    const a: u32 = 0xffffffff;
    try testing.expectEqual(@as(i32, -1), @bitCast(i32, a));
}
