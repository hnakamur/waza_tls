const std = @import("std");

pub fn isDelimChar(c: u8) bool {
    return delimCharBitset.isSet(c);
}

pub fn isTokenChar(c: u8) bool {
    return tokenCharBitset.isSet(c);
}

pub fn isVisibleChar(c: u8) bool {
    return '\x21' <= c and c <= '\x7e';
}

pub fn isObsTextChar(c: u8) bool {
    return '\x80' <= c;
}

pub fn isFieldVisibleChar(c: u8) bool {
    return isVisibleChar(c) or isObsTextChar(c);
}

pub fn isWhiteSpaceChar(c: u8) bool {
    return c == ' ' or c == '\t';
}

const delimCharBitset = makeStaticCharBitSet(_isDelimChar);
const tokenCharBitset = makeStaticCharBitSet(_isTokenChar);

const char_bitset_size = 256;

fn makeStaticCharBitSet(predicate: fn (u8) bool) std.StaticBitSet(char_bitset_size) {
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

test "makeStaticCharBitSet" {
    const bs = makeStaticCharBitSet(_isTokenChar);
    var c: u8 = 0;
    while (true) : (c += 1) {
        try testing.expectEqual(_isTokenChar(c), bs.isSet(c));
        if (c == '\xff') break;
    }
}

test "isVisibleChar" {
    try testing.expect(!isVisibleChar('\x20'));
    try testing.expect(isVisibleChar('\x21'));
    try testing.expect(isVisibleChar('\x7e'));
    try testing.expect(!isVisibleChar('\x7f'));
}

test "isObsTextChar" {
    try testing.expect(!isObsTextChar('\x00'));
    try testing.expect(!isObsTextChar('\x7f'));
    try testing.expect(isObsTextChar('\x80'));
    try testing.expect(isObsTextChar('\xff'));
}

test "isDelimChar" {
    var c: u8 = 0;
    while (true) : (c += 1) {
        try testing.expectEqual(_isDelimChar(c), isDelimChar(c));
        if (c == '\xff') break;
    }
}

test "isTokenChar" {
    var c: u8 = 0;
    var done: bool = false;
    while (true) : (c += 1) {
        try testing.expectEqual(_isTokenChar(c), isTokenChar(c));
        if (c == '\xff') break;
    }
}

test "isFieldVisibleChar" {
    try testing.expect(isFieldVisibleChar('a'));
    try testing.expect(isFieldVisibleChar('\xff'));
    try testing.expect(!isFieldVisibleChar('\t'));
}

test "isWhiteSpaceChar" {
    try testing.expect(isWhiteSpaceChar(' '));
    try testing.expect(isWhiteSpaceChar('\t'));
    try testing.expect(!isWhiteSpaceChar('\r'));
    try testing.expect(!isWhiteSpaceChar('\n'));
}
