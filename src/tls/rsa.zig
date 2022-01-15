const std = @import("std");
const math = std.math;
const mem = std.mem;

const big_zero = math.big.int.Const{ .limbs = &[_]math.big.Limb{0}, .positive = true };
const big_one = math.big.int.Const{ .limbs = &[_]math.big.Limb{1}, .positive = true };

pub const PublicKey = struct {
    modulus: math.big.int.Const,
    exponent: u64,

    pub fn deinit(self: *PublicKey, allocator: mem.Allocator) void {
        allocator.free(self.modulus.limbs);
    }
};

const testing = std.testing;

test "std.math.big.int.Const const" {
    try testing.expectEqual(@as(u64, 0), try big_zero.to(u64));
    try testing.expectEqual(@as(u64, 1), try big_one.to(u64));
}
