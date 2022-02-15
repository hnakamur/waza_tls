const std = @import("std");

const char_bitset_size = 256;

pub fn makeStaticCharBitSet(predicate: fn (u8) bool) std.StaticBitSet(char_bitset_size) {
    @setEvalBranchQuota(10000);
    var bitset = std.StaticBitSet(char_bitset_size).initEmpty();
    var c: u8 = 0;
    while (true) : (c += 1) {
        if (predicate(c)) bitset.set(c);
        if (c == '\xff') break;
    }
    return bitset;
}
