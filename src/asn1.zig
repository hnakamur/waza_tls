const std = @import("std");

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

const testing = std.testing;

test "asn1.Tag" {
    try testing.expectEqual(@intToEnum(Tag, 0x2c), Tag.utf8_string.constructed());
    try testing.expectEqual(@intToEnum(Tag, 0x8c), Tag.utf8_string.contextSpecific());
}

comptime {
    std.testing.refAllDecls(@This());
}
