const std = @import("std");
const math = std.math;
const mem = std.mem;
const x509 = @import("x509.zig");
const pkix = @import("pkix.zig");
const bigint = @import("big_int.zig");

// TagAndClass represents an ASN.1 identifier octet, consisting of a tag number
// (indicating a type) and class (such as context-specific or constructed).
//
// Methods in the cryptobyte package only support the low-tag-number form, i.e.
// a single identifier octet with bits 7-8 encoding the class and bits 1-6
// encoding the tag number.
pub const TagAndClass = enum(u8) {
    pub const class_constructed = 0x20;
    pub const class_context_specific = 0x80;

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
    numeric_string = 18,
    printable_string = 19,
    t61_string = 20,
    ia5_string = 22,
    utc_time = 23,
    generalized_time = 24,
    general_string = 27,
    bmp_string = 30,
    _,

    pub fn init(tag: u8) TagAndClass {
        return @intToEnum(TagAndClass, tag);
    }

    pub fn constructed(self: TagAndClass) TagAndClass {
        return @intToEnum(TagAndClass, @enumToInt(self) | class_constructed);
    }

    pub fn contextSpecific(self: TagAndClass) TagAndClass {
        return @intToEnum(TagAndClass, @enumToInt(self) | class_context_specific);
    }

    pub fn isHighTag(self: TagAndClass) bool {
        return @enumToInt(self) & 0x1f == 0x1f;
    }
};

pub const RawContent = struct {
    bytes: []const u8,

    pub fn deinit(self: *RawContent, allocator: mem.Allocator) void {
        allocator.free(self.bytes);
    }
};

// BitString is the structure to use when you want an ASN.1 BIT STRING type. A
// bit string is padded up to the nearest byte in memory and the number of
// valid bits is recorded. Padding bits will be zero.
pub const BitString = struct {
    bytes: []const u8, // bits packed into bytes.
    bit_length: usize, // length in bits.

    pub fn read(input: *String, allocator: mem.Allocator) !BitString {
        var bytes = try input.readAsn1(.bit_string);
        if (bytes.empty() or bytes.bytes.len * 8 / 8 != bytes.bytes.len) {
            return error.InvalidBitString;
        }

        const pad_len = try bytes.readIntOfType(u8);
        const b = bytes.bytes;
        if (pad_len > 7 or
            b.len == 0 and pad_len != 0 or
            b.len > 0 and b[b.len - 1] & (@shlExact(@as(u8, 1), @intCast(u3, pad_len)) - 1) != 0)
        {
            return error.InvalidBitString;
        }

        return BitString{
            .bytes = try allocator.dupe(u8, b),
            .bit_length = b.len * 8 - pad_len,
        };
    }

    pub fn deinit(self: *BitString, allocator: mem.Allocator) void {
        allocator.free(self.bytes);
    }

    // At returns the bit at the given index. If the index is out of range it
    // returns false.
    pub fn at(self: *const BitString, i: usize) u1 {
        if (i >= self.bit_length) {
            return 0;
        }
        const x = i / 8;
        const y = @intCast(u3, 7 - i % 8);
        return @intCast(u1, (self.bytes[x] >> y) & 1);
    }

    // rightAlign returns a slice where the padding bits are at the beginning.
    pub fn rightAlign(self: *const BitString, allocator: mem.Allocator) ![]const u8 {
        const shift_u4 = @intCast(u4, 8 - self.bit_length % 8);
        if (shift_u4 == 8 or self.bytes.len == 0) {
            return try allocator.dupe(u8, self.bytes);
        }
        const shift = @truncate(u3, shift_u4);
        const shift_rev = @truncate(u3, 8 - shift_u4);

        var a = try allocator.alloc(u8, self.bytes.len);
        var prev = self.bytes[0];
        a[0] = @shrExact(prev, shift);
        var i: usize = 1;
        while (i < self.bytes.len) : (i += 1) {
            const b = self.bytes[i];
            a[i] = @shlExact(prev, shift_rev) | @shrExact(b, shift);
            prev = b;
        }
        return a;
    }
};

test "mod" {
    var bit_len: usize = struct {
        fn f() usize {
            return 7;
        }
    }.f();
    try testing.expectEqual(@as(u3, 1), @intCast(u3, 8 - bit_len % 8));
}

test "shlExact" {
    var padding_bits: u8 = struct {
        fn f() u8 {
            return 7;
        }
    }.f();
    try testing.expectEqual(@as(u8, 0x7f), @shlExact(@as(u8, 1), @intCast(u3, padding_bits)) - 1);
}

pub const String = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) String {
        return .{ .bytes = bytes };
    }

    // skip advances the String by n bytes.
    pub fn skip(self: *String, n: usize) !void {
        _ = try self.readBytes(n);
    }

    pub fn readIntOfType(self: *String, comptime T: type) !T {
        const n = @divExact(@typeInfo(T).Int.bits, 8);
        if (self.bytes.len < n) {
            return error.EndOfStream;
        }
        const v = mem.readIntBig(T, self.bytes[0..n]);
        self.bytes = self.bytes[n..];
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
        if (self.bytes.len < n) {
            return error.EndOfStream;
        }
        const v = self.bytes[0..n];
        self.bytes = self.bytes[n..];
        return v;
    }

    // copyBytes copies out.len bytes into out and advances over them.
    pub fn copyBytes(self: *String, out: []u8) !void {
        if (self.bytes.len < out.len) {
            return error.EndOfStream;
        }
        mem.copy(u8, out, self.bytes[0..out.len]);
        self.bytes = self.bytes[out.len..];
    }

    // empty reports whether the string does not contain any bytes.
    pub fn empty(self: *const String) bool {
        return self.bytes.len == 0;
    }

    // readAsn1 reads the contents of a DER-encoded ASN.1 element (not including
    // tag and length bytes), and advances. The element must match the
    // given tag.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn readAsn1(self: *String, tag: TagAndClass) !String {
        var t: TagAndClass = undefined;
        const out = try self.readAnyAsn1(&t);
        return if (t == tag) out else error.TagMismatch;
    }

    // readAsn1Element reads the contents of a DER-encoded ASN.1 element (including
    // tag and length bytes), and advances. The element must match the
    // given tag.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn readAsn1Element(self: *String, tag: TagAndClass) !String {
        var t: TagAndClass = undefined;
        const out = try self.readAnyAsn1Element(&t);
        return if (t == tag) out else error.TagMismatch;
    }

    // readAnyAsn1 reads the contents of a DER-encoded ASN.1 element (not including
    // tag and length bytes), sets out_tag to its tag, and advances.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn readAnyAsn1(self: *String, out_tag: ?*TagAndClass) !String {
        return self.doReadAsn1(out_tag, true);
    }

    // readAnyAsn1Element reads the contents of a DER-encoded ASN.1 element
    // (including tag and length bytes), sets out_tag to is tag, and advances.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn readAnyAsn1Element(self: *String, out_tag: ?*TagAndClass) !String {
        return self.doReadAsn1(out_tag, false);
    }

    // peekAsn1Tag reports whether the next ASN.1 value on the string starts with
    // the given tag.
    pub fn peekAsn1Tag(self: *const String, tag: TagAndClass) bool {
        return self.bytes.len > 0 and @intToEnum(TagAndClass, self.bytes[0]) == tag;
    }

    // skipAsn1 reads and discards an ASN.1 element with the given tag. It
    // reports whether the operation was successful.
    pub fn skipAsn1(self: *String, tag: TagAndClass) !void {
        _ = try self.readAsn1(tag);
    }

    // skipOptionalAsn1 advances s over an ASN.1 element with the given tag, or
    // else leaves s unchanged.
    pub fn skipOptionalAsn1(self: *String, tag: TagAndClass) !void {
        if (self.peekAsn1Tag(tag)) try self.skipAsn1(tag);
    }

    // readOptionalAsn1 attempts to read the contents of a DER-encoded ASN.1
    // element (not including tag and length bytes) tagged with the given tag.
    pub fn readOptionalAsn1(self: *String, tag: TagAndClass) !?String {
        return if (self.peekAsn1Tag(tag)) try self.readAsn1(tag) else null;
    }

    // readOptionalAsn1Integer attempts to read an optional ASN.1 INTEGER
    // explicitly tagged with tag and advances. If no element with a
    // matching tag is present, it returns defaultValue instead.
    // Supported types are i8, i16, i24, i32, i64, u8, u16, u24, u32, u64, and
    // std.math.big.int.Managed. It panics for other types.
    // For std.math.big.int.Managed, deinit method must be called after use of the
    // returned value.
    pub fn readOptionalAsn1Integer(
        self: *String,
        comptime T: type,
        tag: TagAndClass,
        allocator: mem.Allocator,
        default_value: T,
    ) !T {
        return if (try self.readOptionalAsn1(tag)) |*i| blk: {
            break :blk try i.readAsn1Integer(T, allocator);
        } else switch (T) {
            math.big.int.Const => blk: {
                break :blk math.big.int.Const{
                    .limbs = try allocator.dupe(math.big.Limb, default_value.limbs),
                    .positive = default_value.positive,
                };
            },
            else => default_value,
        };
    }

    // ReadASN1Boolean decodes an ASN.1 BOOLEAN and converts it to a boolean
    // representation and advances.
    pub fn readAsn1Boolean(self: *String) !bool {
        var bytes = try self.readAsn1(.boolean);
        return try parseBool(bytes.bytes);
    }

    // readAsn1Integer decodes an ASN.1 INTEGER and advances.
    // Supported types are i8, i16, i24, i32, i64, u8, u16, u24, u32, u64, and
    // std.math.big.int.Const. It panics for other types.
    // For std.math.big.int.Const, deinit method must be called after use of the
    // returned value.
    pub fn readAsn1Integer(self: *String, comptime T: type, allocator: mem.Allocator) !T {
        return switch (T) {
            i8, i16, i24, i32, i64 => @intCast(T, try self.readAsn1Int64()),
            u8, u16, u24, u32, u64 => @intCast(T, try self.readAsn1Uint64()),
            math.big.int.Const => try self.readAsn1BigInt(allocator),
            else => @panic("unsupported type for readAsn1Integer"),
        };
    }

    pub fn readAsn1BigInt(self: *String, allocator: mem.Allocator) !math.big.int.Const {
        var input = try self.readAsn1(.integer);
        var bytes = input.bytes;
        try checkAsn1Integer(bytes);
        const limb_byte_len = @divExact(@typeInfo(usize).Int.bits, 8);
        if (bytes[0] & 0x80 == 0x80) {
            // Negative number.
            const capacity = math.big.int.calcTwosCompLimbCount(limb_byte_len * bytes.len);
            var ret = try math.big.int.Managed.initCapacity(allocator, capacity);
            var b = @ptrCast([*]u8, ret.limbs.ptr);
            var i: usize = 0;
            while (i < bytes.len) : (i += 1) {
                // Use bitwise NOT here since encoded bytes are encoded in two's-complement form.
                // Also note bytes in zig's big integer are little-endian ordered.
                b[bytes.len - 1 - i] = ~bytes[i];
            }
            mem.set(u8, b[bytes.len .. limb_byte_len * capacity], 0);
            ret.metadata = capacity;

            // ret = -(ret + 1)
            const one = math.big.int.Const{ .limbs = &[_]math.big.Limb{1}, .positive = true };
            try bigint.add(&ret, ret.toConst(), one);
            ret.negate();
            return ret.toConst();
        } else {
            if (bytes[0] == 0 and bytes.len > 1) {
                bytes = bytes[1..];
            }
            const capacity = math.big.int.calcTwosCompLimbCount(limb_byte_len * bytes.len);
            var ret = try math.big.int.Managed.initCapacity(allocator, capacity);
            var b = @ptrCast([*]u8, ret.limbs.ptr);
            var i: usize = 0;
            while (i < bytes.len) : (i += 1) {
                // Note bytes in zig's big integer are little-endian ordered.
                b[bytes.len - 1 - i] = bytes[i];
            }
            mem.set(u8, b[bytes.len .. limb_byte_len * capacity], 0);
            ret.metadata = capacity;
            return ret.toConst();
        }
    }

    fn readAsn1Int64(self: *String) !i64 {
        var bytes = try self.readAsn1(.integer);
        try checkAsn1Integer(bytes.bytes);
        return try asn1Signed(bytes.bytes);
    }

    pub fn readAsn1Uint64(self: *String) !u64 {
        var bytes = try self.readAsn1(.integer);
        try checkAsn1Integer(bytes.bytes);
        return try asn1Unsigned(bytes.bytes);
    }

    fn doReadAsn1(self: *String, out_tag: ?*TagAndClass, skip_header: bool) !String {
        if (self.bytes.len < 2) {
            return error.EndOfStream;
        }

        const tag = @intToEnum(TagAndClass, self.bytes[0]);
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

        const len_byte = self.bytes[1];

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
            if (len_len == 0 or len_len > 4 or self.bytes.len < 2 + len_len) {
                return error.InvalidLength;
            }

            var len_bytes = String.init(self.bytes[2 .. 2 + len_len]);
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

// BOOLEAN

fn parseBool(input: []const u8) !bool {
    if (input.len != 1) {
        return error.Asn1SyntaxError;
    }

    // DER demands that "If the encoding represents the boolean value TRUE,
    // its single contents octet shall have all eight bits set to one."
    // Thus only 0 and 255 are valid encoded values.
    return switch (input[0]) {
        0 => false,
        0xff => true,
        else => error.Asn1SyntaxError,
    };
}

// INTEGER

// checkInteger returns void if the given bytes are a valid DER-encoded
// INTEGER and an error otherwise.
fn checkInteger(input: []const u8) !void {
    if (input.len == 0) {
        return error.Asn1StructuralError;
    }
    if (input.len == 1) {
        return;
    }
    if ((input[0] == 0 and input[1] & 0x80 == 0) or
        (input[0] == 0xff and input[1] & 0x80 == 0x80))
    {
        return error.Asn1StructuralError;
    }
}

// parseInt64 treats the given bytes as a big-endian, signed integer and
// returns the result.
fn parseInt64(input: []const u8) !i64 {
    try checkInteger(input);

    if (input.len > 8) {
        // We'll overflow an int64 in this case.
        return error.Asn1StructuralError;
    }
    var ret: i64 = 0;
    var bytes_read: usize = 0;
    while (bytes_read < input.len) : (bytes_read += 1) {
        ret <<= 8;
        ret |= input[bytes_read];
    }

    // Shift up and down in order to sign extend the result.
    const n = @intCast(u6, 64 - input.len * 8);
    _ = @shlWithOverflow(i64, ret, n, &ret);
    ret = @shrExact(ret, n);
    return ret;
}

// ASN.1 has IMPLICIT and EXPLICIT tags, which can be translated as "instead
// of" and "in addition to". When not specified, every primitive type has a
// default tag in the UNIVERSAL class.
//
// For example: a BIT STRING is tagged [UNIVERSAL 3] by default (although ASN.1
// doesn't actually have a UNIVERSAL keyword). However, by saying [IMPLICIT
// CONTEXT-SPECIFIC 42], that means that the tag is replaced by another.
//
// On the other hand, if it said [EXPLICIT CONTEXT-SPECIFIC 10], then an
// /additional/ tag would wrap the default tag. This explicit tag will have the
// compound flag set.
//
// (This is used in order to remove ambiguity with optional elements.)
//
// You can layer EXPLICIT and IMPLICIT tags to an arbitrary depth, however we
// don't support that here. We support a single layer of EXPLICIT or IMPLICIT
// tagging with tag strings on the fields of a structure.

// FieldParameters is the parameters for parsing ASN.1 value for a structure field.
pub const FieldParameters = struct {
    name: []const u8, // field name
    optional: bool = false, // true iff the field is OPTIONAL
    explicit: bool = false, // true iff an EXPLICIT tag is in use.
    application: bool = false, // true iff an APPLICATION tag is in use.
    private: bool = false, // true iff a PRIVATE tag is in use.
    default_value: ?i64 = null, // a default value for INTEGER typed fields.
    tag: ?TagAndClass = null, // the EXPLICIT or IMPLICIT tag
    string_type: ?TagAndClass = null, // the string tag to use when marshaling.
    time_type: ?TagAndClass = null, // the time tag to use when marshaling.
    set: bool = false, // true iff this should be encoded as a SET
    omit_empty: bool = false, // true iff this should be omitted if empty when marshaling.

    pub fn getSlice(comptime Struct: type) []const FieldParameters {
        const struct_info = @typeInfo(Struct).Struct;
        inline for (struct_info.decls) |decl| {
            switch (decl.data) {
                .Var => |v| {
                    switch (@typeInfo(v)) {
                        .Array => |a| {
                            if (a.child == FieldParameters) {
                                return &@field(Struct, decl.name);
                            }
                        },
                        else => {},
                    }
                },
                else => {},
            }
        }
        return &[_]FieldParameters{};
    }

    pub fn forField(
        comptime params: []const FieldParameters,
        comptime name: []const u8,
    ) ?*const FieldParameters {
        for (params) |*param| {
            if (mem.eql(u8, param.name, name)) {
                return param;
            }
        }
        return null;
    }

    // setDefaultValue is used to install a default value into out.
    // It is successful if the field was optional, even if a default value
    // wasn't provided or it failed to install it into the Value.
    fn setDefaultValue(self: *const FieldParameters, out: anytype) !void {
        if (!self.optional) {
            return error.NotOptionalField;
        }
        if (self.default_value) |v| {
            const OutType = @TypeOf(out);
            switch (@typeInfo(OutType)) {
                .Pointer => |ptr| {
                    if (!ptr.is_const and ptr.size == .One) {
                        switch (@typeInfo(ptr.child)) {
                            .Int => |i| {
                                if (i.signedness == .signed) {
                                    out.* = @intCast(ptr.child, v);
                                    return;
                                }
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
            @panic("out must be a pointer to single mutable signed integer");
        }
    }
};

test "FieldParameters.setDefaultValue" {
    testing.log_level = .err;

    {
        const MyStruct = struct {
            pub const field_parameters = [_]FieldParameters{
                .{ .name = "v", .optional = true, .default_value = 3 },
            };

            v: i32 = undefined,
        };

        var s = MyStruct{};
        try MyStruct.field_parameters[0].setDefaultValue(&s.v);
        try testing.expectEqual(@as(i32, 3), s.v);
    }

    {
        const MyStruct = struct {
            pub const field_parameters = [_]FieldParameters{
                .{ .name = "v", .optional = true },
            };

            v: i32 = undefined,
        };

        var s = MyStruct{ .v = 2 };
        try MyStruct.field_parameters[0].setDefaultValue(&s.v);
        try testing.expectEqual(@as(i32, 2), s.v);
    }
}

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

pub const ObjectIdentifier = struct {
    pub const country = initConst(&.{ 2, 5, 4, 6 });
    pub const organization = initConst(&.{ 2, 5, 4, 10 });
    pub const organizational_unit = initConst(&.{ 2, 5, 4, 11 });
    pub const common_name = initConst(&.{ 2, 5, 4, 3 });
    pub const serial_number = initConst(&.{ 2, 5, 4, 5 });
    pub const locality = initConst(&.{ 2, 5, 4, 7 });
    pub const province = initConst(&.{ 2, 5, 4, 8 });
    pub const street_address = initConst(&.{ 2, 5, 4, 9 });
    pub const postal_code = initConst(&.{ 2, 5, 4, 17 });

    // RFC 3279, 2.3 Public Key Algorithms
    //
    // pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
    //    rsadsi(113549) pkcs(1) 1 }
    //
    // rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
    //
    // id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
    //    x9-57(10040) x9cm(4) 1 }
    //
    // RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
    //
    // id-ecPublicKey OBJECT IDENTIFIER ::= {
    //       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
    pub const public_key_rsa = initConst(&.{ 1, 2, 840, 113549, 1, 1, 1 });
    pub const public_key_dsa = initConst(&.{ 1, 2, 840, 10040, 4, 1 });
    pub const public_key_ecdsa = initConst(&.{ 1, 2, 840, 10045, 2, 1 });
    pub const public_key_ed25519 = signature_ed25519;

    pub const signature_md2_with_rsa = initConst(&.{ 1, 2, 840, 113549, 1, 1, 2 });
    pub const signature_md5_with_rsa = initConst(&.{ 1, 2, 840, 113549, 1, 1, 4 });
    pub const signature_sha1_with_rsa = initConst(&.{ 1, 2, 840, 113549, 1, 1, 5 });
    pub const signature_sha256_with_rsa = initConst(&.{ 1, 2, 840, 113549, 1, 1, 11 });
    pub const signature_sha384_with_rsa = initConst(&.{ 1, 2, 840, 113549, 1, 1, 12 });
    pub const signature_sha512_with_rsa = initConst(&.{ 1, 2, 840, 113549, 1, 1, 13 });
    pub const signature_dsa_with_sha1 = initConst(&.{ 1, 2, 840, 10040, 4, 3 });
    pub const signature_dsa_with_sha256 = initConst(&.{ 2, 16, 840, 1, 101, 3, 4, 3, 2 });
    pub const signature_ecdsa_with_sha1 = initConst(&.{ 1, 2, 840, 10045, 4, 1 });
    pub const signature_ecdsa_with_sha256 = initConst(&.{ 1, 2, 840, 10045, 4, 3, 2 });
    pub const signature_ecdsa_with_sha384 = initConst(&.{ 1, 2, 840, 10045, 4, 3, 3 });
    pub const signature_ecdsa_with_sha512 = initConst(&.{ 1, 2, 840, 10045, 4, 3, 4 });
    pub const signature_rsa_pss = initConst(&.{ 1, 2, 840, 113549, 1, 1, 10 });
    pub const signature_ed25519 = initConst(&.{ 1, 3, 101, 112 });

    // iso_signature_sha1_with_rsa means the same as signature_sha1_with_rsa
    // but it's specified by ISO. Microsoft's makecert.exe has been known
    // to produce certificates with this OID.
    pub const iso_signature_sha1_with_rsa = initConst(&.{ 1, 3, 14, 3, 2, 29 });

    pub const sha256 = initConst(&.{ 2, 16, 840, 1, 101, 3, 4, 2, 1 });
    pub const sha384 = initConst(&.{ 2, 16, 840, 1, 101, 3, 4, 2, 2 });
    pub const sha512 = initConst(&.{ 2, 16, 840, 1, 101, 3, 4, 2, 3 });

    pub const extension_subject_key_id = initConst(&.{ 2, 5, 29, 14 });
    pub const extension_key_usage = initConst(&.{ 2, 5, 29, 15 });
    pub const extension_extended_key_usage = initConst(&.{ 2, 5, 29, 37 });
    pub const extension_authority_key_id = initConst(&.{ 2, 5, 29, 35 });
    pub const extension_basic_constraints = initConst(&.{ 2, 5, 29, 19 });
    pub const extension_subject_alt_name = initConst(&.{ 2, 5, 29, 17 });
    pub const extension_certificate_policies = initConst(&.{ 2, 5, 29, 32 });
    pub const extension_name_constraints = initConst(&.{ 2, 5, 29, 30 });
    pub const extension_crl_distribution_points = initConst(&.{ 2, 5, 29, 31 });
    pub const extension_authority_info_access = initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 1, 1 });
    pub const extension_crl_number = initConst(&.{ 2, 5, 29, 20 });

    pub const authority_info_access_ocsp = initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 48, 1 });
    pub const authority_info_access_issuers = initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 48, 2 });

    components: []const u32,

    pub fn initConst(components: []const u32) ObjectIdentifier {
        return .{ .components = components };
    }

    // parse decodes an ASN.1 OBJECT IDENTIFIER and advances.
    pub fn parse(allocator: mem.Allocator, s: *String) !ObjectIdentifier {
        var input = try s.readAsn1(.object_identifier);
        if (input.empty()) return error.InvalidObjectIdentifier;

        var components = try std.ArrayListUnmanaged(u32).initCapacity(
            allocator,
            input.bytes.len + 1,
        );
        errdefer components.deinit(allocator);

        const v = try readBase128Int(&input);
        if (v < 80) {
            try components.append(allocator, v / 40);
            try components.append(allocator, v % 40);
        } else {
            try components.append(allocator, 2);
            try components.append(allocator, v - 80);
        }

        while (!input.empty()) {
            try components.append(allocator, try readBase128Int(&input));
        }

        return ObjectIdentifier{ .components = components.toOwnedSlice(allocator) };
    }

    pub fn deinit(self: *ObjectIdentifier, allocator: mem.Allocator) void {
        allocator.free(self.components);
    }

    pub fn clone(self: ObjectIdentifier, allocator: mem.Allocator) !ObjectIdentifier {
        return ObjectIdentifier{
            .components = try allocator.dupe(u32, self.components),
        };
    }

    pub fn format(
        self: ObjectIdentifier,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        for (self.components) |c, i| {
            if (i > 0) {
                try writer.writeByte('.');
            }
            try std.fmt.format(writer, "{}", .{c});
        }
    }

    pub fn eql(self: ObjectIdentifier, other: ObjectIdentifier) bool {
        return mem.eql(u32, self.components, other.components);
    }
};

test "ObjectIdentifier.eql" {
    try testing.expect(
        x509.oid_signature_ed25519.eql(ObjectIdentifier{
            .components = &[_]u32{ 1, 3, 101, 112 },
        }),
    );
}

pub fn readBase128Int(self: *String) !u32 {
    var ret: u32 = 0;
    var i: usize = 0;
    while (self.bytes.len > 0) : (i += 1) {
        if (i == 5) {
            return error.InvalidBase128Int;
        }
        // Avoid overflowing int on a 32-bit platform.
        // We don't want different behavior based on the architecture.
        if (ret >= 1 << (31 - 7)) {
            return error.InvalidBase128Int;
        }

        ret <<= 7;
        const b = (try self.readBytes(1))[0];
        ret |= b & 0x7f;
        if (b & 0x80 == 0) {
            return ret;
        }
    }
    return error.InvalidBase128Int; // truncated
}

// null_bytes contains bytes representing the DER-encoded ASN.1 NULL type.
pub const null_bytes = &[_]u8{ @enumToInt(TagAndClass.@"null"), 0 };

// A RawValue represents an undecoded ASN.1 object.
pub const RawValue = struct {
    // null is a RawValue with its TagAndClass set to the ASN.1 NULL type tag (5).
    pub const @"null" = RawValue{ .tag = .@"null" };

    class: TagAndClass = @intToEnum(TagAndClass, 0),
    tag: TagAndClass,
    is_compound: bool = false,
    bytes: ?[]const u8 = null,
    full_bytes: []const u8, // includes the tag and length

    pub fn deinit(self: *RawValue, allocator: mem.Allocator) void {
        allocator.free(self.full_bytes);
        if (self.bytes) |b| allocator.free(b);
    }
};

//
// parse functions which take []const u8 as input stead of *asn1.String.
//

// ASN.1 class types represent the namespace of the tag.
pub const Class = enum(u2) {
    universal = 0,
    application = 1,
    context_specific = 2,
    private = 3,
};

pub const PrimitiveOrConstructive = enum(u1) {
    primitive = 0,
    constructive = 1,
};

// ASN.1 tags represent the type of the following object.
pub const Tag = enum(u32) {
    boolean = 1,
    integer = 2,
    bit_string = 3,
    octet_string = 4,
    @"null" = 5,
    oid = 6,
    @"enum" = 10,
    utf8_string = 12,
    sequence = 16,
    set = 17,
    numeric_string = 18,
    printable_string = 19,
    t61_string = 20,
    ia5_string = 22,
    utc_time = 23,
    generalized_time = 24,
    general_string = 27,
    bmp_string = 30,
    _,
};

pub const TagAndLength = struct {
    class: Class,
    pc: PrimitiveOrConstructive,
    tag: Tag,
    length: usize,

    // parse parses an ASN.1 tag and length pair from the given offset
    // into a byte slice. It returns the new offset. SET and
    // SET OF (tag 17) are mapped to SEQUENCE and SEQUENCE OF (tag 16) since we
    // don't distinguish between ordered and unordered objects in this code.
    pub fn parse(input: []const u8, init_offset: usize, out: *TagAndLength) !usize {
        var offset = init_offset;
        if (offset >= input.len) {
            // TagAndLength.parse should not be called without at least a single
            // byte to read. Thus this check is for robustness:
            @panic("no byte to read");
        }
        var b = input[offset];
        offset += 1;
        out.class = @intToEnum(Class, @intCast(u2, b >> 6));
        out.pc = if (b & 0x20 == 0x20) .constructive else .primitive;
        out.tag = @intToEnum(Tag, b & 0x1f);

        // If the bottom five bits are set, then the tag number is actually base 128
        // encoded afterwards
        if (@enumToInt(out.tag) == 0x1f) {
            var tag: u32 = undefined;
            offset = try parseBase128Int(input, offset, &tag);
            out.tag = @intToEnum(Tag, tag);

            // Tags should be encoded in minimal form.
            if (tag < 0x1f) {
                std.log.warn("non-minimal tag", .{});
                return error.Asn1SyntaxError;
            }
        }
        if (offset >= input.len) {
            std.log.warn("truncated tag or length", .{});
            return error.Asn1SyntaxError;
        }
        b = input[offset];
        offset += 1;
        if (b & 0x80 == 0) {
            // The length is encoded in the bottom 7 bits.
            out.length = b & 0x7f;
        } else {
            // Bottom 7 bits give the number of length bytes to follow.
            const num_bytes = b & 0x7f;
            if (num_bytes == 0) {
                std.log.warn("indefinite length found (not DER)", .{});
                return error.Asn1SyntaxError;
            }
            out.length = 0;
            var i: usize = 0;
            while (i < num_bytes) : (i += 1) {
                if (offset >= input.len) {
                    std.log.warn("truncated tag or length", .{});
                    return error.Asn1SyntaxError;
                }
                b = input[offset];
                offset += 1;
                if (out.length >= 1 << 23) {
                    // We can't shift out.length up without
                    // overflowing.
                    std.log.warn("length too large", .{});
                    return error.Asn1StructuralError;
                }
                out.length <<= 8;
                out.length |= b;
                if (out.length == 0) {
                    // DER requires that lengths be minimal.
                    std.log.warn("superfluous leading zeros in length", .{});
                    return error.Asn1StructuralError;
                }
            }
            // Short lengths must be encoded in short form.
            if (out.length < 0x80) {
                std.log.warn("non-minimal length", .{});
                return error.Asn1StructuralError;
            }
        }
        return offset;
    }
};

pub fn parseBigInt(allocator: mem.Allocator, der: []const u8) !math.big.int.Const {
    try checkAsn1Integer(der);
    const limb_byte_len = @divExact(@typeInfo(usize).Int.bits, 8);
    if (der[0] & 0x80 == 0x80) {
        // Negative number.
        const capacity = math.big.int.calcTwosCompLimbCount(limb_byte_len * der.len);
        var ret = try math.big.int.Managed.initCapacity(allocator, capacity);
        var b = @ptrCast([*]u8, ret.limbs.ptr);
        var i: usize = 0;
        while (i < der.len) : (i += 1) {
            // Use bitwise NOT here since encoded bytes are encoded in two's-complement form.
            // Also note bytes in zig's big integer are little-endian ordered.
            b[der.len - 1 - i] = ~der[i];
        }
        mem.set(u8, b[der.len .. limb_byte_len * capacity], 0);
        ret.metadata = capacity;

        // ret = -(ret + 1)
        const one = math.big.int.Const{ .limbs = &[_]math.big.Limb{1}, .positive = true };
        try ret.add(ret.toConst(), one);
        ret.negate();
        return ret.toConst();
    } else {
        var bytes = der;
        if (bytes[0] == 0 and bytes.len > 1) {
            bytes = bytes[1..];
        }
        const capacity = math.big.int.calcTwosCompLimbCount(limb_byte_len * bytes.len);
        var ret = try math.big.int.Managed.initCapacity(allocator, capacity);
        var b = @ptrCast([*]u8, ret.limbs.ptr);
        var i: usize = 0;
        while (i < bytes.len) : (i += 1) {
            // Note bytes in zig's big integer are little-endian ordered.
            b[bytes.len - 1 - i] = bytes[i];
        }
        mem.set(u8, b[bytes.len .. limb_byte_len * capacity], 0);
        ret.metadata = capacity;
        return ret.toConst();
    }
}

// parse decodes an ASN.1 OBJECT IDENTIFIER and advances.
pub fn parseObjectIdentifier(input: []const u8, allocator: mem.Allocator) !ObjectIdentifier {
    if (input.len == 0) return error.Asn1SyntaxError;

    // In the worst case, we get two elements from the first byte (which is
    // encoded differently) and then every varint is a single byte long.
    var components = try std.ArrayListUnmanaged(u32).initCapacity(
        allocator,
        input.len + 1,
    );
    errdefer components.deinit(allocator);

    // The first varint is 40*value1 + value2:
    // According to this packing, value1 can take the values 0, 1 and 2 only.
    // When value1 = 0 or value1 = 1, then value2 is <= 39. When value1 = 2,
    // then there are no restrictions on value2.
    var v: u32 = undefined;
    var offset = try parseBase128Int(input, 0, &v);
    if (v < 80) {
        try components.append(allocator, v / 40);
        try components.append(allocator, v % 40);
    } else {
        try components.append(allocator, 2);
        try components.append(allocator, v - 80);
    }

    while (offset < input.len) {
        offset = try parseBase128Int(input, offset, &v);
        try components.append(allocator, v);
    }

    return ObjectIdentifier{ .components = components.toOwnedSlice(allocator) };
}

// parseBase128Int parses a base-128 encoded int from the given offset in the
// given byte slice and sets the value to out. It returns the new offset.
fn parseBase128Int(input: []const u8, init_offset: usize, out: *u32) !usize {
    var offset = init_offset;
    var ret64: u64 = 0;
    var shifted: usize = 0;
    while (offset < input.len) : (shifted += 1) {
        // 5 * 7 bits per byte == 35 bits of data
        // Thus the representation is either non-minimal or too large for an int32
        if (shifted == 5) {
            std.log.warn("base 128 integer too large", .{});
            return error.Asn1StructuralError;
        }
        ret64 <<= 7;
        const b = input[offset];
        // integers should be minimally encoded, so the leading octet should
        // never be 0x80
        if (shifted == 0 and b == 0x80) {
            std.log.warn("integer is not minimally encoded", .{});
            return error.Asn1SyntaxError;
        }
        ret64 |= b & 0x7f;
        offset += 1;
        if (b & 0x80 == 0) {
            // Ensure that the returned value fits in an int on all platforms
            if (ret64 > std.math.maxInt(i32)) {
                std.log.warn("base 128 integer too large", .{});
                return error.Asn1StructuralError;
            }
            out.* = @intCast(u32, ret64);
            return offset;
        }
    }
    std.log.warn("truncated base 128 integer", .{});
    return error.Asn1SyntaxError;
}

// invalidLength reports whether offset + length > slice_length, or if the
// addition would overflow.
fn invalidLength(offset: usize, length: usize, slice_length: usize) bool {
    const end_offest = offset +% length;
    return end_offest < offset or end_offest > slice_length;
}

// parseField is the main parsing function. Given a byte slice and an offset
// into the array, it will try to parse a suitable ASN.1 value out and store it
// in the given Value.
pub fn parseField(
    self: *const FieldParameters,
    allocator: mem.Allocator,
    input: []const u8,
    init_offset: usize,
    out: anytype,
) !usize {
    const OutPtrChildType = switch (@typeInfo(@TypeOf(out))) {
        .Pointer => |ptr| ptr.child,
        else => @panic("out must be pointer"),
    };

    var offset = init_offset;
    // If we have run out of data, it may be that there are optional elements at the end.
    if (offset == input.len) {
        self.setDefaultValue(out) catch {
            std.log.warn("sequence truncated", .{});
            return error.Asn1SyntaxError;
        };
    }
    // Deal with the ANY type.
    var t: TagAndLength = undefined;
    offset = try TagAndLength.parse(input, offset, &t);
    std.log.debug("offset={}, t={}", .{ offset, t });
    if (invalidLength(offset, t.length, input.len)) {
        std.log.warn("data truncated", .{});
        return error.Asn1SyntaxError;
    }

    const inner_input = input[offset .. offset + t.length];
    std.log.debug("inner_input={}", .{fmtx.fmtSliceHexEscapeLower(inner_input)});
    switch (OutPtrChildType) {
        []const u8, ?[]const u8 => switch (t.tag) {
            .printable_string => {
                const result = try parsePrintableString(inner_input);
                out.* = if (result.len == 0) &[_]u8{} else try allocator.dupe(u8, result);
                return offset + t.length;
            },
            else => {},
        },
        ObjectIdentifier, ?ObjectIdentifier => {
            out.* = try parseObjectIdentifier(inner_input, allocator);
            return offset + t.length;
        },
        else => switch (@typeInfo(OutPtrChildType)) {
            .Int => {
                out.* = @intCast(OutPtrChildType, try parseInt64(inner_input));
                return offset + t.length;
            },
            else => {},
        },
    }

    // if (t.class == .universal) {
    //     const inner_input = input[offset .. offset + t.length];
    //     switch (t.tag) {
    //         .printable_string => {
    //             const result = try parsePrintableString(inner_input);
    //             if (OutPtrChildType == []const u8) {
    //                 out.* = if (result.len == 0) &[_]u8{} else try allocator.dupe(u8, result);
    //             } else @panic("out pointer child type mismatch");
    //         },
    //         .integer => switch (@typeInfo(OutPtrChildType)) {
    //             .Int => out.* = @intCast(OutPtrChildType, try parseInt64(inner_input)),
    //             else => @panic("out pointer child type mismatch"),
    //         },
    //         .oid => if (OutPtrChildType == ObjectIdentifier) {
    //             out.* = try parseObjectIdentifier(inner_input, allocator);
    //         } else @panic("out pointer child type mismatch"),
    //         else => {
    //             // If we don't know how to handle the type, we just leave Value unmodified.
    //         },
    //     }
    //     return offset + t.length;
    // }
    // TODO: implement
    @panic("not implemented yet");
    // return offset;
}

test "out two types" {
    testing.log_level = .err;
    try struct {
        fn f(out: anytype) void {
            const OutType = @TypeOf(out);
            switch (@typeInfo(OutType)) {
                .Pointer => |ptr| {
                    if (!ptr.is_const and ptr.size == .One) {
                        switch (@typeInfo(ptr.child)) {
                            .Int => out.* = @intCast(ptr.child, 3),
                            .Pointer => |p| {
                                if (p.size == .Slice and p.is_const and p.child == u8) {
                                    out.* = "hello";
                                }
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }

        fn runTest() !void {
            var i: i64 = undefined;
            f(&i);
            try testing.expectEqual(@as(i64, 3), i);

            var j: i33 = undefined;
            f(&j);
            try testing.expectEqual(@as(i33, 3), j);

            var k: usize = undefined;
            f(&k);
            try testing.expectEqual(@as(usize, 3), k);

            var a: []const u8 = undefined;
            f(&a);
            try testing.expectEqualStrings("hello", a);
        }
    }.runTest();
}

// test "parseField all" {
//     testing.log_level = .err;

//     const T1 = struct {
//         const Self = @This();

//         pub const field_parameters = [_]FieldParameters{
//             .{ .name = "a" },
//             .{ .name = "b" },
//             .{ .name = "c" },
//         };

//         a: []const u8 = &[_]u8{},
//         c: ?ObjectIdentifier = null,
//         b: u32 = undefined,

//         pub fn deinit(self: *Self, allocator: mem.Allocator) void {
//             if (self.a.len > 0) allocator.free(self.a);
//             if (self.c) |*c| c.deinit(allocator);
//         }
//     };

//     const Test = struct {
//         const params_list = FieldParameters.getSlice(T1);

//         fn a(input: []const u8, want: []const u8) !void {
//             const allocator = testing.allocator;
//             var t1: T1 = undefined;
//             defer t1.deinit(allocator);
//             const field_param = FieldParameters.forField(params_list, "a").?;
//             const new_offset = try parseField(field_param, allocator, input, 0, &t1.a);
//             try testing.expectEqual(input.len, new_offset);
//             try testing.expectEqualStrings(want, t1.a);
//         }

//         fn b(input: []const u8, want: u32) !void {
//             const allocator = testing.allocator;
//             var t1: T1 = undefined;
//             const field_param = FieldParameters.forField(params_list, "b").?;
//             const new_offset = try parseField(field_param, allocator, input, 0, &t1.b);
//             try testing.expectEqual(input.len, new_offset);
//             try testing.expectEqual(want, t1.b);
//         }

//         fn c(input: []const u8, want: ObjectIdentifier) !void {
//             const allocator = testing.allocator;
//             var t1: T1 = undefined;
//             const field_param = FieldParameters.forField(params_list, "c").?;
//             const new_offset = try parseField(field_param, allocator, input, 0, &t1.c);
//             try testing.expectEqual(input.len, new_offset);
//             if (!want.eql(t1.c.?)) {
//                 std.log.warn("oid mismatch, want={}, got={}", .{ want, t1.c.? });
//             }
//             try testing.expect(want.eql(t1.c.?));
//         }
//     };

//     // try Test.a(&[_]u8{ 0x13, 0x04, 't', 'e', 's', 't' }, "test");
//     // try Test.a(&[_]u8{ 0x13, 0x00 }, "");

//     // try Test.b(&[_]u8{ 0x02, 0x01, 0x10 }, 16);

//     try Test.c(&[_]u8{
//         0x30, 0x08, 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
//     }, ObjectIdentifier.initConst(&.{ 1, 2, 840, 113549 }));
// }

// PrintableString

// parsePrintableString parses an ASN.1 PrintableString from the given byte
// array and returns it.
fn parsePrintableString(input: []const u8) ![]const u8 {
    for (input) |b| {
        if (!isPrintable(b, .allow_asterisk, .allow_ampersand)) {
            std.log.warn("PrintableString contains invalid character", .{});
            return error.Asn1SyntaxError;
        }
    }
    return input;
}

const AsteriskFlag = enum(u1) {
    reject_asterisk = 0,
    allow_asterisk = 1,
};

const AmpersandFlag = enum(u1) {
    reject_ampersand = 0,
    allow_ampersand = 1,
};

fn isPrintable(b: u8, comptime asterisk: AsteriskFlag, comptime ampersand: AmpersandFlag) bool {
    return 'a' <= b and b <= 'z' or
        'A' <= b and b <= 'Z' or
        '0' <= b and b <= '9' or
        '\'' <= b and b <= ')' or
        '+' <= b and b <= '/' or
        b == ' ' or
        b == ':' or
        b == '=' or
        b == '?' or
        // This is technically not allowed in a PrintableString.
        // However, x509 certificates with wildcard strings don't
        // always use the correct string type so we permit it.
        (asterisk == .allow_asterisk and b == '*') or
        // This is not technically allowed either. However, not
        // only is it relatively common, but there are also a
        // handful of CA certificates that contain it. At least
        // one of which will not expire until 2027.
        (ampersand == .allow_ampersand and b == '&');
}

const testing = std.testing;
const fmtx = @import("../fmtx.zig");

test "TagAndLength.parse" {
    testing.log_level = .err;
    const f = struct {
        fn f(input: []const u8, want: anyerror!TagAndLength) !void {
            var got: TagAndLength = undefined;
            if (want) |val_want| {
                try testing.expectEqual(input.len, try TagAndLength.parse(input, 0, &got));
                // std.log.debug("got={}", .{got});
                try testing.expectEqual(val_want, got);
            } else |err_want| {
                try testing.expectError(err_want, TagAndLength.parse(input, 0, &got));
            }
        }
    }.f;

    try f("\x80\x01", TagAndLength{
        .class = .context_specific,
        .tag = @intToEnum(Tag, 0),
        .pc = .primitive,
        .length = 1,
    });
    try f("\xa0\x01", TagAndLength{
        .class = .context_specific,
        .tag = @intToEnum(Tag, 0),
        .pc = .constructive,
        .length = 1,
    });
    try f("\x02\x00", TagAndLength{
        .class = .universal,
        .tag = .integer,
        .pc = .primitive,
        .length = 0,
    });
    try f("\xfe\x00", TagAndLength{
        .class = .private,
        .tag = .bmp_string,
        .pc = .constructive,
        .length = 0,
    });
    try f("\x1f\x1f\x00", TagAndLength{
        .class = .universal,
        .tag = @intToEnum(Tag, 31),
        .pc = .primitive,
        .length = 0,
    });
    try f("\x1f\x81\x00\x00", TagAndLength{
        .class = .universal,
        .tag = @intToEnum(Tag, 128),
        .pc = .primitive,
        .length = 0,
    });
    try f("\x1f\x81\x80\x01\x00", TagAndLength{
        .class = .universal,
        .tag = @intToEnum(Tag, 0x4001),
        .pc = .primitive,
        .length = 0,
    });
    try f("\x00\x81\x80", TagAndLength{
        .class = .universal,
        .tag = @intToEnum(Tag, 0),
        .pc = .primitive,
        .length = 128,
    });
    try f("\x00\x82\x01\x00", TagAndLength{
        .class = .universal,
        .tag = @intToEnum(Tag, 0),
        .pc = .primitive,
        .length = 256,
    });
    try f("\x00\x83\x01\x00", error.Asn1SyntaxError);
    try f("\x01\x85", error.Asn1SyntaxError);
    try f("\x30\x80", error.Asn1SyntaxError);
    // Superfluous zeros in the length should be an error.
    try f("\xa0\x82\x00\xff", error.Asn1StructuralError);
    // Lengths up to the maximum size of an int should work.
    try f("\xa0\x84\x7f\xff\xff\xff", TagAndLength{
        .class = .context_specific,
        .tag = @intToEnum(Tag, 0),
        .pc = .constructive,
        .length = 0x7fffffff,
    });
    // Lengths that would overflow an int should be rejected.
    try f("\xa0\x84\x80\x00\x00\x00", error.Asn1StructuralError);
    // Long length form may not be used for lengths that fit in short form.
    try f("\xa0\x81\x7f", error.Asn1StructuralError);
    // Tag numbers which would overflow int32 are rejected. (The value below is 2^31.)
    try f("\x1f\x88\x80\x80\x80\x00\x00", error.Asn1StructuralError);
    // Tag numbers that fit in an int32 are valid. (The value below is 2^31 - 1.)
    try f("\x1f\x87\xff\xff\xff\x7f\x00", TagAndLength{
        .class = .universal,
        .tag = @intToEnum(Tag, std.math.maxInt(i32)),
        .pc = .primitive,
        .length = 0,
    });
    // Long tag number form may not be used for tags that fit in short form.
    try f("\x1f\x1e\x00", error.Asn1SyntaxError);
}

test "readOptionalAsn1" {
    testing.log_level = .err;
    const f = struct {
        fn f(want: ?String, input: []const u8, tag: TagAndClass) !void {
            var s = String.init(input);
            if (try s.readOptionalAsn1(tag)) |got| {
                if (want) |w| {
                    if (!mem.eql(u8, w.bytes, got.bytes)) {
                        std.debug.print(
                            "input={}, got {}, want {}\n",
                            .{
                                fmtx.fmtSliceHexEscapeLower(input),
                                fmtx.fmtSliceHexEscapeLower(got.bytes),
                                fmtx.fmtSliceHexEscapeLower(w.bytes),
                            },
                        );
                    }
                    try testing.expectEqualSlices(u8, w.bytes, got.bytes);
                } else {
                    std.debug.print(
                        "input={}, got {}, want null\n",
                        .{
                            fmtx.fmtSliceHexEscapeLower(input),
                            fmtx.fmtSliceHexEscapeLower(got.bytes),
                        },
                    );
                }
            } else {
                if (want) |w| {
                    std.debug.print(
                        "input={}, got null, want {}\n",
                        .{
                            fmtx.fmtSliceHexEscapeLower(input),
                            fmtx.fmtSliceHexEscapeLower(w.bytes),
                        },
                    );
                }
            }
        }
    }.f;

    try f(String.init("\x00"), "\x02\x01\x00", .integer);
}

fn allocDebugPrintBigIntManaged(
    i: math.big.int.Managed,
    allocator: mem.Allocator,
) error{OutOfMemory}![]u8 {
    var counting_writer = std.io.countingWriter(std.io.null_writer);
    debugFormatBigIntManaged(i, counting_writer.writer()) catch unreachable;
    const size = math.cast(usize, counting_writer.bytes_written) catch |err| switch (err) {
        // Output too long. Can't possibly allocate enough memory to display it.
        error.Overflow => return error.OutOfMemory,
    };
    const buf = try allocator.alloc(u8, size);
    var fbs = std.io.fixedBufferStream(buf);
    debugFormatBigIntManaged(i, fbs.writer()) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable, // we just counted the size above
    };
    return fbs.getWritten();
}

fn debugFormatBigIntManaged(
    i: math.big.int.Managed,
    out_stream: anytype,
) !void {
    const b = @ptrCast([*]const u8, i.limbs.ptr);
    try std.fmt.format(
        out_stream,
        "limbs.ptr=0x{x}, limbs.len={}, metadata={x}, limbs={}",
        .{
            @ptrToInt(i.limbs.ptr),
            i.limbs.len,
            i.metadata,
            fmtx.fmtSliceHexEscapeLower(b[0 .. 8 * i.limbs.len]),
        },
    );
}

pub fn writeAsn1(
    allocator: mem.Allocator,
    tag: TagAndClass,
    comptime Context: type,
    comptime writeToFn: fn (context: Context, writer: anytype) anyerror!void,
    context: Context,
    writer: anytype,
) !void {
    const tag_int = @enumToInt(tag);
    // Identifiers with the low five bits set indicate high-tag-number format
    // (two or more octets), which we don't support.
    if (tag_int & 0x1f == 0x1f) {
        return error.Asn1HighTagNotSupported;
    }
    try writeInt(u8, tag_int, writer);

    var buf = std.fifo.LinearFifo(u8, .Dynamic).init(allocator);
    defer buf.deinit();
    var writer2 = buf.writer();
    try writeToFn(context, writer2);
    const len = buf.readableLength();

    if (len > 0xfffffffe) {
        return error.Asn1TooLong;
    } else if (len > 0xffffff) {
        try writer.writeByte(0x80 | 4);
        try writer.writeIntBig(u32, @intCast(u32, len));
    } else if (len > 0xffff) {
        try writer.writeByte(0x80 | 3);
        try writer.writeIntBig(u24, @intCast(u24, len));
    } else if (len > 0xff) {
        try writer.writeByte(0x80 | 2);
        try writer.writeIntBig(u16, @intCast(u16, len));
    } else if (len > 0x7f) {
        try writer.writeByte(0x80 | 1);
        try writer.writeIntBig(u8, @intCast(u8, len));
    } else {
        try writer.writeIntBig(u8, @intCast(u8, len));
    }

    try writer.writeAll(buf.readableSlice(0));
}

pub fn writeAsn1BigInt(
    allocator: mem.Allocator,
    n: std.math.big.int.Const,
    out_stream: anytype,
) !void {
    const Context = struct {
        const Self = @This();

        allocator: mem.Allocator,
        n: std.math.big.int.Const,

        fn write(context: Self, writer: anytype) !void {
            if (context.n.eqZero()) {
                try writer.writeByte(0);
            } else if (context.n.positive) {
                const b = @ptrCast([*]const u8, context.n.limbs.ptr);
                var i: usize = context.n.limbs.len * @sizeOf(math.big.Limb) - 1;
                while (b[i] == 0) : (i -= 1) {}
                if (b[i] & 0x80 != 0) {
                    try writer.writeByte(0);
                }
                while (true) : (i -= 1) {
                    try writer.writeByte(b[i]);
                    if (i == 0) break;
                }
            } else {
                // A negative number has to be converted to two's-complement form. So we
                // invert and subtract 1. If the most-significant-bit isn't set then
                // we'll need to pad the beginning with 0xff in order to keep the number
                // negative.
                var n_neg_minus_one_m = try context.n.negate().toManaged(context.allocator);
                defer n_neg_minus_one_m.deinit();
                try n_neg_minus_one_m.sub(n_neg_minus_one_m.toConst(), bigint.one);

                var b: []const u8 = undefined;
                b.ptr = @ptrCast([*]const u8, n_neg_minus_one_m.limbs.ptr);
                b.len = n_neg_minus_one_m.len() * @sizeOf(math.big.Limb);

                var i: usize = b.len - 1;
                while (true) : (i -= 1) {
                    if (i == 0 or b[i - 1] != 0) break;
                }
                const len = i;
                if (len == 0 or ~b[len - 1] & 0x80 == 0) {
                    try writer.writeByte(0xff);
                }
                if (len > 0) {
                    i = len - 1;
                    while (true) : (i -= 1) {
                        try writer.writeByte(~b[i]);
                        if (i == 0) break;
                    }
                }
            }
        }
    };

    const context = Context{ .allocator = allocator, .n = n };
    try writeAsn1(allocator, .integer, Context, Context.write, context, out_stream);
}

test "writeAsn1BigInt" {
    const f = struct {
        fn f(input: i64) !void {
            const allocator = testing.allocator;
            var buf = std.fifo.LinearFifo(u8, .Dynamic).init(allocator);
            defer buf.deinit();
            var writer = buf.writer();

            var input_big = try std.math.big.int.Managed.initSet(allocator, input);
            defer input_big.deinit();

            try writeAsn1BigInt(allocator, input_big.toConst(), writer);

            var s = String.init(buf.readableSlice(0));
            var got = s.readAsn1BigInt(allocator) catch |err| {
                std.log.err("input={}, buf={}", .{ input, fmtx.fmtSliceHexColonLower(buf.readableSlice(0)) });
                return err;
            };
            defer bigint.deinitConst(got, allocator);
            if (!got.eq(input_big.toConst())) {
                std.debug.print("result mismatch, input={}, got={}\n", .{ input, got });
            }
            try testing.expect(got.eq(input_big.toConst()));
        }
    }.f;

    try f(-32768);
    try f(-32767);
    try f(-257);
    try f(-256);
    try f(-255);
    try f(-2);
    try f(-1);
    try f(0);
    try f(1);
    try f(2);
    try f(127);
    try f(128);
    try f(255);
    try f(256);
    try f(32767);
    try f(32768);

    // const start = std.time.nanoTimestamp();
    // var i: i64 = std.math.minInt(i16);
    // while (i <= std.math.maxInt(i16)) : (i += 1) {
    //     try f(i);
    // }
    // const end = std.time.nanoTimestamp();
    // std.debug.print("elapsed={}ms\n", .{@divTrunc(end - start, std.time.ns_per_ms)});

    // elapsed=11902ms for counting and write again
    // elapsed=11863ms
}

fn writeInt(comptime T: type, val: anytype, writer: anytype) !void {
    try writer.writeIntBig(T, toInt(T, val));
}

fn toInt(comptime T: type, val: anytype) T {
    return switch (@typeInfo(@TypeOf(val))) {
        .ComptimeInt, .Int => @intCast(T, val),
        .Enum => @intCast(T, @enumToInt(val)),
        else => @panic("invalid type for writeIntBig"),
    };
}

test "readOptionalAsn1Integer" {
    testing.log_level = .err;
    const f = struct {
        fn f(comptime T: type, want_str: []const u8, input: []const u8, tag: TagAndClass, default_value: T) !void {
            const allocator = testing.allocator;
            var s = String.init(input);
            var got = try s.readOptionalAsn1Integer(T, tag, allocator, default_value);
            defer if (T == math.big.int.Const) bigint.deinitConst(got, allocator);
            const got_str =
                switch (T) {
                i8, i16, i24, i32, i64, u8, u16, u24, u32, u64 => blk: {
                    break :blk try std.fmt.allocPrint(allocator, "{}", .{got});
                },
                math.big.int.Const => blk: {
                    break :blk try got.toStringAlloc(allocator, 10, .lower);
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

    try f(u64, "2", "\xa0\x03\x02\x01\x02", @intToEnum(TagAndClass, 0).constructed().contextSpecific(), 0);
    {
        const allocator = testing.allocator;
        var default_value = (try math.big.int.Managed.initSet(allocator, 0)).toConst();
        defer bigint.deinitConst(default_value, allocator);

        // var default_value_debug_str = try allocDebugPrintBigIntManaged(default_value, allocator);
        // std.debug.print("default_value: {s}\n", .{default_value_debug_str});
        // defer allocator.free(default_value_debug_str);

        try f(
            math.big.int.Const,
            "2",
            "\xa0\x03\x02\x01\x02",
            @intToEnum(TagAndClass, 0).constructed().contextSpecific(),
            default_value,
        );
    }
    {
        const allocator = testing.allocator;
        var default_value = (try math.big.int.Managed.initSet(allocator, 0)).toConst();
        defer bigint.deinitConst(default_value, allocator);

        // var default_value_debug_str = try allocDebugPrintBigIntManaged(default_value, allocator);
        // std.debug.print("default_value: {s}\n", .{default_value_debug_str});
        // defer allocator.free(default_value_debug_str);

        try f(
            math.big.int.Const,
            "0",
            "\x02\x01\x00",
            @intToEnum(TagAndClass, 0).constructed().contextSpecific(),
            default_value,
        );
    }
}

test "readAsn1Integer" {
    testing.log_level = .err;

    const f = struct {
        fn f(comptime T: type, want_str: []const u8, input: []const u8) !void {
            const allocator = testing.allocator;
            var s = String.init(input);
            var got = try s.readAsn1Integer(T, allocator);
            defer if (T == math.big.int.Const) bigint.deinitConst(got, allocator);

            const got_str =
                switch (T) {
                i8, i16, i24, i32, i64, u8, u16, u24, u32, u64 => blk: {
                    break :blk try std.fmt.allocPrint(allocator, "{}", .{got});
                },
                math.big.int.Const => blk: {
                    break :blk try got.toStringAlloc(allocator, 10, .lower);
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
    try f(math.big.int.Const, "0", "\x02\x01\x00");
    try f(math.big.int.Const, "18446744073709551615", "\x02\x09\x00" ++ "\xff" ** 8);
}

test "readAsn1BigInt" {
    testing.log_level = .err;
    const f = struct {
        fn f(want_str: anyerror![]const u8, input: []const u8) !void {
            const allocator = testing.allocator;
            var s = String.init(input);
            if (want_str) |w_str| {
                var got = try s.readAsn1BigInt(allocator);
                defer bigint.deinitConst(got, allocator);
                var got_str = try got.toStringAlloc(allocator, 10, .lower);
                defer allocator.free(got_str);
                if (!mem.eql(u8, w_str, got_str)) {
                    std.debug.print("input={}, want={s}, got={s}\n", .{
                        fmtx.fmtSliceHexEscapeLower(input), w_str, got_str,
                    });
                }
                try testing.expectEqualStrings(w_str, got_str);
            } else |err| {
                if (s.readAsn1BigInt(allocator)) |got| {
                    var got_str = try got.toStringAlloc(allocator, 10, .lower);
                    defer allocator.free(got_str);
                    std.debug.print("input={}, want error {}, got={s}\n", .{
                        fmtx.fmtSliceHexEscapeLower(input), err, got_str,
                    });
                    return error.TestExpectedError;
                } else |_| {}
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

test "parseBigInt" {
    testing.log_level = .err;
    const f = struct {
        fn f(want_str: anyerror![]const u8, input: []const u8) !void {
            const allocator = testing.allocator;
            var t: TagAndLength = undefined;
            var offset = try TagAndLength.parse(input, 0, &t);
            const inner_der = input[offset .. offset + t.length];
            if (want_str) |w_str| {
                var got = try parseBigInt(allocator, inner_der);
                defer bigint.deinitConst(got, allocator);
                var got_str = try got.toStringAlloc(allocator, 10, .lower);
                defer allocator.free(got_str);
                if (!mem.eql(u8, w_str, got_str)) {
                    std.debug.print("input={}, want={s}, got={s}\n", .{
                        fmtx.fmtSliceHexEscapeLower(input), w_str, got_str,
                    });
                }
                try testing.expectEqualStrings(w_str, got_str);
            } else |err| {
                if (parseBigInt(allocator, inner_der)) |got| {
                    var got_str = try got.toStringAlloc(allocator, 10, .lower);
                    defer allocator.free(got_str);
                    std.debug.print("input={}, want error {}, got={s}\n", .{
                        fmtx.fmtSliceHexEscapeLower(input), err, got_str,
                    });
                    return error.TestExpectedError;
                } else |_| {}
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

test "asn1.TagAndClass" {
    try testing.expectEqual(@intToEnum(TagAndClass, 0x2c), TagAndClass.utf8_string.constructed());
    try testing.expectEqual(@intToEnum(TagAndClass, 0x8c), TagAndClass.utf8_string.contextSpecific());
}

test "String.readBytes" {
    const bytes = "zig is great";
    var s = String.init(bytes);

    try testing.expectEqualStrings("zig", try s.readBytes(3));
    try testing.expectEqualStrings(" is great", s.bytes);

    try testing.expectEqualStrings(" is", try s.readBytes(3));
    try testing.expectEqualStrings(" great", s.bytes);

    try testing.expectError(error.EndOfStream, s.readBytes(s.bytes.len + 1));
}

test "String.copyBytes" {
    const bytes = "zig is great";
    var s = String.init(bytes);

    var out: [5]u8 = undefined;
    try s.copyBytes(&out);
    try testing.expectEqualStrings("zig i", &out);
    try testing.expectEqualStrings("s great", s.bytes);

    try s.copyBytes(&out);
    try testing.expectEqualStrings("s gre", &out);
    try testing.expectEqualStrings("at", s.bytes);

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
    const bytes = "\xff";
    const got = mem.readIntBig(i8, bytes);
    try testing.expectEqual(@as(i8, -1), got);
}

test "u32/i32" {
    const a: u32 = 0xffffffff;
    try testing.expectEqual(@as(i32, -1), @bitCast(i32, a));
}

test "ObjectIdentifier.format" {
    const allocator = testing.allocator;
    var got = try std.fmt.allocPrint(allocator, "{}", .{x509.oid_signature_ed25519});
    defer allocator.free(got);
    try testing.expectEqualStrings("1.3.101.112", got);
}
