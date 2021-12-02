const std = @import("std");

pub fn isDelimChar(c: u8) bool {
    return delimCharBitset.isSet(c);
}

pub fn isTokenChar(c: u8) bool {
    return tokenCharBitset.isSet(c);
}

pub inline fn isVisibleChar(c: u8) bool {
    return '\x21' <= c and c <= '\x7e';
}

pub inline fn isObsTextChar(c: u8) bool {
    return '\x80' <= c;
}

pub inline fn isFieldVisibleChar(c: u8) bool {
    return isVisibleChar(c) or isObsTextChar(c);
}

pub inline fn isWhiteSpaceChar(c: u8) bool {
    return c == ' ' or c == '\t';
}

const delimCharBitset = makeStaticCharBitSet(_isDelimChar);
const tokenCharBitset = makeStaticCharBitSet(_isTokenChar);

const char_bitset_size = 256;

fn makeStaticCharBitSet(predicate: fn(u8) bool) std.StaticBitSet(char_bitset_size) {
    @setEvalBranchQuota(10000);
    var bitset = std.StaticBitSet(char_bitset_size).initEmpty();
    var c: u8 = 0;
    while (true) : (c += 1) {
        if (predicate(c)) bitset.set(c);
        if (c == '\xff') break;
    }
    return bitset;
}

const delim_chars = "\"(),/:;<=>?@[\\]{}";

fn _isDelimChar(c: u8) bool {
    return if (std.mem.indexOfScalar(u8, delim_chars, c)) |_| true else false;
}

fn _isTokenChar(c: u8) bool {
    return _isVisibleChar(c) and !_isDelimChar(c);
}

fn _isVisibleChar(c: u8) bool {
    return c > '\x20' and c < '\x7f';
}

const testing = std.testing;

test "isDelimChar" {
    var c: u8 = 0;
    while (true) : (c += 1) {
        try testing.expectEqual(_isDelimChar(c), isDelimChar(c));
        if (c == '\xff') break;
    }
}

test "isTokenChar" {
    var c: u8 = 0;
    while (true) : (c += 1) {
        try testing.expectEqual(_isTokenChar(c), isTokenChar(c));
        if (c == '\xff') break;
    }
}
