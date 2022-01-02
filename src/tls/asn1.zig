const std = @import("std");
const math = std.math;
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

    // empty reports whether the string does not contain any bytes.
    pub fn empty(self: *const String) bool {
        return self.data.len == 0;
    }

    // readAsn1 reads the contents of a DER-encoded ASN.1 element (not including
    // tag and length bytes), and advances. The element must match the
    // given tag.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn readAsn1(self: *String, tag: Tag) !String {
        var t: Tag = undefined;
        const out = try self.readAnyAsn1(&t);
        return if (t == tag) out else error.TagMismatch;
    }

    // readAsn1Element reads the contents of a DER-encoded ASN.1 element (including
    // tag and length bytes), and advances. The element must match the
    // given tag.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn readAsn1Element(self: *String, tag: Tag) !String {
        var t: Tag = undefined;
        const out = try self.readAnyAsn1Element(&t);
        return if (t == tag) out else error.TagMismatch;
    }

    // readAnyAsn1 reads the contents of a DER-encoded ASN.1 element (not including
    // tag and length bytes), sets out_tag to its tag, and advances.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn readAnyAsn1(self: *String, out_tag: ?*Tag) !String {
        return self.doReadAsn1(out_tag, true);
    }

    // readAnyAsn1Element reads the contents of a DER-encoded ASN.1 element
    // (including tag and length bytes), sets out_tag to is tag, and advances.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn readAnyAsn1Element(self: *String, out_tag: ?*Tag) !String {
        return self.doReadAsn1(out_tag, false);
    }

    // peekAsn1Tag reports whether the next ASN.1 value on the string starts with
    // the given tag.
    pub fn peekAsn1Tag(self: *const String, tag: Tag) bool {
        return self.data.len > 0 and @intToEnum(Tag, self.data[0]) == tag;
    }

    // skipAsn1 reads and discards an ASN.1 element with the given tag. It
    // reports whether the operation was successful.
    pub fn skipAsn1(self: *String, tag: Tag) !void {
        _ = try self.readAsn1(tag);
    }

    // skipOptionalASN1 advances s over an ASN.1 element with the given tag, or
    // else leaves s unchanged.
    pub fn skipOptionalAsn1(self: *String, tag: Tag) !void {
        if (peekAsn1Tag(tag)) try self.skipAsn1(tag);
    }

    // readOptionalAsn1 attempts to read the contents of a DER-encoded ASN.1
    // element (not including tag and length bytes) tagged with the given tag.
    pub fn readOptionalAsn1(self: *String, tag: Tag) !?String {
        return if (self.peekAsn1Tag(tag)) try self.readAsn1(tag) else null;
    }

    // readASN1Integer decodes an ASN.1 INTEGER and advances.
    // Supported types are i8, i16, i24, i32, i64, u8, u16, u24, u32, u64, and
    // std.math.big.int.Managed. It panics for other types.
    // For std.math.big.int.Managed, deinit method must be called after use of the
    // returned value.
    pub fn readAsn1Integer(self: *String, comptime T: type, allocator: mem.Allocator) !T {
        return switch (T) {
            i8, i16, i24, i32, i64 => @intCast(T, try self.readAsn1Int64()),
            u8, u16, u24, u32, u64 => @intCast(T, try self.readAsn1Uint64()),
            math.big.int.Managed => try self.readAsn1BigInt(allocator),
            else => @panic("unsupported type for readAsn1Integer"),
        };
    }

    fn readAsn1BigInt(self: *String, allocator: mem.Allocator) !math.big.int.Managed {
        var bytes = try self.readAsn1(.integer);
        var data = bytes.data;
        try checkAsn1Integer(data);
        const limb_byte_len = @divExact(@typeInfo(usize).Int.bits, 8);
        if (data[0] & 0x80 == 0x80) {
            // Negative number.
            const capacity = math.big.int.calcTwosCompLimbCount(limb_byte_len * data.len);
            var ret = try math.big.int.Managed.initCapacity(allocator, capacity);
            var b = @ptrCast([*]u8, ret.limbs.ptr);
            var i: usize = 0;
            while (i < data.len) : (i += 1) {
                // Use bitwise NOT here since encoded bytes are encoded in two's-complement form.
                // Also note bytes in zig's big integer are little-endian ordered.
                b[data.len - 1 - i] = ~data[i];
            }
            mem.set(u8, b[data.len .. limb_byte_len * capacity], 0);
            ret.metadata = capacity;

            // ret = -(ret + 1)
            var one_limbs_buf: [1]usize = undefined;
            const one = math.big.int.Mutable.init(&one_limbs_buf, 1).toConst();
            try ret.add(ret.toConst(), one);
            ret.negate();
            return ret;
        } else {
            if (data[0] == 0 and data.len > 1) {
                data = data[1..];
            }
            const capacity = math.big.int.calcTwosCompLimbCount(limb_byte_len * data.len);
            var ret = try math.big.int.Managed.initCapacity(allocator, capacity);
            var b = @ptrCast([*]u8, ret.limbs.ptr);
            var i: usize = 0;
            while (i < data.len) : (i += 1) {
                // Note bytes in zig's big integer are little-endian ordered.
                b[data.len - 1 - i] = data[i];
            }
            mem.set(u8, b[data.len .. limb_byte_len * capacity], 0);
            ret.metadata = capacity;
            return ret;
        }
    }

    fn readAsn1Int64(self: *String) !i64 {
        var bytes = try self.readAsn1(.integer);
        try checkAsn1Integer(bytes.data);
        return try asn1Signed(bytes.data);
    }

    fn readAsn1Uint64(self: *String) !u64 {
        var bytes = try self.readAsn1(.integer);
        try checkAsn1Integer(bytes.data);
        return try asn1Unsigned(bytes.data);
    }

    fn doReadAsn1(self: *String, out_tag: ?*Tag, skip_header: bool) !String {
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
            if (len32 >> @intCast(u5, (len_len - 1) * 8) == 0) {
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
        var out = String.init(try self.readBytes(length));
        if (skip_header) {
            try out.skip(header_len);
        }
        return out;
    }
};

fn checkAsn1Integer(bytes: []const u8) !void {
    switch (bytes.len) {
        0 => {
            // An INTEGER is encoded with at least one octet.
            return error.InvalidInteger;
        },
        1 => {},
        else => {
            if (bytes[0] == 0 and bytes[1] & 0x80 == 0 or bytes[0] == 0xff and bytes[1] & 0x80 == 0x80) {
                // Value is not minimally encoded.
                return error.InvalidInteger;
            }
        },
    }
}

fn asn1Signed(bytes: []const u8) !i64 {
    const len = bytes.len;
    if (len > 8) {
        return error.TooLargeInteger;
    }
    var out: i64 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        out = out << 8 | bytes[i];
    }
    // Shift up and down in order to sign extend the result.
    const n = @intCast(u6, 64 - len * 8);
    _ = @shlWithOverflow(i64, out, n, &out);
    out = @shrExact(out, n);
    return out;
}

fn asn1Unsigned(bytes: []const u8) !u64 {
    const len = bytes.len;
    if (len > 9 or len == 9 and bytes[0] != 0) {
        return error.TooLargeInteger;
    }
    if (bytes[0] & 0x80 != 0) {
        return error.NegativeInteger;
    }
    var out: u64 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        out = out << 8 | bytes[i];
    }
    return out;
}

const testing = std.testing;
const fmtx = @import("../fmtx.zig");

test "readAsn1Integer" {
    testing.log_level = .debug;

    const f = struct {
        fn f(comptime T: type, want_str: []const u8, input: []const u8) !void {
            const allocator = testing.allocator;
            var s = String.init(input);
            var got = try s.readAsn1Integer(T, allocator);
            defer if (T == math.big.int.Managed) got.deinit();

            const got_str =
                switch (T) {
                i8, i16, i24, i32, i64, u8, u16, u24, u32, u64 => blk: {
                    break :blk try std.fmt.allocPrint(allocator, "{}", .{got});
                },
                math.big.int.Managed => blk: {
                    break :blk try got.toString(allocator, 10, .lower);
                },
                else => @panic("unsupported type"),
            };
            defer allocator.free(got_str);

            if (!mem.eql(u8, got_str, want_str)) {
                std.debug.print("T={}, input={}\n", .{ T, fmtx.fmtSliceHexEscapeLower(input) });
            }
            try testing.expectEqualStrings(got_str, want_str);
        }
    }.f;

    try f(u64, "0", "\x02\x01\x00");
    try f(u8, "0", "\x02\x01\x00");
    try f(i8, "0", "\x02\x01\x00");
    try f(math.big.int.Managed, "0", "\x02\x01\x00");
    try f(math.big.int.Managed, "18446744073709551615", "\x02\x09\x00" ++ "\xff" ** 8);
}

test "switchType" {
    const f = struct {
        fn f(comptime T: type) void {
            switch (T) {
                u64 => std.debug.print("T is u64\n", .{}),
                u32 => std.debug.print("T is u32\n", .{}),
                math.big.int.Managed => std.debug.print("T is bigint\n", .{}),
                else => std.debug.print("T is other type\n", .{}),
            }
        }
    }.f;

    f(u64);
    f(u32);
    f(math.big.int.Managed);
}

test "bigInt" {
    const allocator = testing.allocator;
    // var i = try std.math.big.int.Managed.initSet(allocator, 0x1234_5678_9ABC_DEF0);
    var i = try std.math.big.int.Managed.initSet(allocator, 0);
    defer i.deinit();
    // var m = i.toMutable();
    var got_s = try i.toString(allocator, 10, .lower);
    std.debug.print("got_s={s}\n", .{got_s});
    defer allocator.free(got_s);

    // m.addScalar(m.toConst(), 257);
    // i = m.toManaged(allocator);
    const b = @ptrCast([*]const u8, i.limbs.ptr);
    std.debug.print(
        "limbs.len={}, metadata={x}, limbs={any}\n",
        .{ i.limbs.len, i.metadata, fmtx.fmtSliceHexEscapeLower(b[0 .. 8 * i.limbs.len]) },
    );
}

test "readAsn1BigInt" {
    testing.log_level = .debug;
    const f = struct {
        fn f(want_str: anyerror![]const u8, input: []const u8) !void {
            var s = String.init(input);
            if (want_str) |str| {
                var want = try math.big.int.Managed.init(testing.allocator);
                defer want.deinit();
                try want.setString(10, str);
                var got = try s.readAsn1BigInt(testing.allocator);
                defer got.deinit();
                if (!want.eq(got)) {
                    std.debug.print("input={}, want_str={s}, want={}, got={}\n", .{
                        fmtx.fmtSliceHexEscapeLower(input), str, want, got,
                    });
                }
                try testing.expect(want.eq(got));
            } else |err| {
                try testing.expectError(err, s.readAsn1Int64());
            }
        }
    }.f;

    try f("0", "\x02\x01\x00");
    try f("1", "\x02\x01\x01");
    try f("127", "\x02\x01\x7f");
    try f("128", "\x02\x02\x00\x80");
    try f("255", "\x02\x02\x00\xff");
    try f("256", "\x02\x02\x01\x00");
    try f("72057594037927935", "\x02\x08\x00" ++ "\xff" ** 7);
    try f("18446744073709551615", "\x02\x09\x00" ++ "\xff" ** 8);
    try f("-1", "\x02\x01\xff");
    try f("-2", "\x02\x01\xfe");
    try f("-128", "\x02\x01\x80");
    try f("-129", "\x02\x02\xff\x7f");
    try f("-130", "\x02\x02\xff\x7e");
}

test "readAsn1Int64" {
    const f = struct {
        fn f(want: anyerror!i64, input: []const u8) !void {
            var s = String.init(input);
            if (want) |v| {
                try testing.expectEqual(v, try s.readAsn1Int64());
            } else |err| {
                try testing.expectError(err, s.readAsn1Int64());
            }
        }
    }.f;

    try f(0, "\x02\x01\x00");
    try f(127, "\x02\x01\x7f");
    try f(-128, "\x02\x01\x80");
    try f(-129, "\x02\x02\xff\x7f");
    try f(-130, "\x02\x02\xff\x7e");
    try f(std.math.maxInt(i64), "\x02\x08\x7f" ++ "\xff" ** 7);
    try f(error.EndOfStream, "\x02\x01");
}

test "readAsn1Uint64" {
    const f = struct {
        fn f(want: anyerror!u64, input: []const u8) !void {
            var s = String.init(input);
            if (want) |v| {
                try testing.expectEqual(v, try s.readAsn1Uint64());
            } else |err| {
                try testing.expectError(err, s.readAsn1Uint64());
            }
        }
    }.f;

    try f(0, "\x02\x01\x00");
    try f(255, "\x02\x02\x00\xff");
    try f(std.math.maxInt(u64), "\x02\x09\x00" ++ "\xff" ** 8);
    try f(error.EndOfStream, "\x02\x01");
}

test "asn1Signed" {
    try testing.expectEqual(@as(i64, 127), try asn1Signed("\x7f"));
    try testing.expectEqual(@as(i64, -128), try asn1Signed("\x80"));
    try testing.expectEqual(@as(i64, -127), try asn1Signed("\x81"));
    try testing.expectEqual(@as(i64, -2), try asn1Signed("\xfe"));
    try testing.expectEqual(@as(i64, -1), try asn1Signed("\xff"));

    try testing.expectEqual(@as(i64, 32767), try asn1Signed("\x7f\xff"));
    try testing.expectEqual(@as(i64, -32768), try asn1Signed("\x80\x00"));
    try testing.expectEqual(@as(i64, -32767), try asn1Signed("\x80\x01"));
    try testing.expectEqual(@as(i64, -2), try asn1Signed("\xff\xfe"));
    try testing.expectEqual(@as(i64, -1), try asn1Signed("\xff\xff"));

    try testing.expectEqual(@as(i64, std.math.maxInt(i64)), try asn1Signed("\x7f" ++ "\xff" ** 7));
    try testing.expectEqual(@as(i64, -1), try asn1Signed("\xff" ** 8));
    try testing.expectError(error.TooLargeInteger, asn1Signed("\xff" ** 9));
}

test "asn1Unsigned" {
    try testing.expectEqual(@as(u64, 127), try asn1Unsigned("\x7f"));
    try testing.expectError(error.NegativeInteger, asn1Unsigned("\x80"));
    try testing.expectError(error.NegativeInteger, asn1Unsigned("\xff"));
    try testing.expectEqual(@as(u64, 128), try asn1Unsigned("\x00\x80"));
    try testing.expectEqual(@as(u64, 0), try asn1Unsigned("\x00" ** 9));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), try asn1Unsigned("\x00" ++ "\xff" ** 8));
    try testing.expectError(error.TooLargeInteger, asn1Unsigned("\x01" ++ "\xff" ** 8));
    try testing.expectError(error.TooLargeInteger, asn1Unsigned("\x00" ** 10));
}

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
