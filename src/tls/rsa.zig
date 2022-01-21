const std = @import("std");
const math = std.math;
const mem = std.mem;
const memx = @import("../memx.zig");

const big_zero = math.big.int.Const{ .limbs = &[_]math.big.Limb{0}, .positive = true };
const big_one = math.big.int.Const{ .limbs = &[_]math.big.Limb{1}, .positive = true };

pub const PublicKey = struct {
    modulus: math.big.int.Const,
    exponent: u64,

    pub fn deinit(self: *PublicKey, allocator: mem.Allocator) void {
        allocator.free(self.modulus.limbs);
    }
};

// A PrivateKey represents an RSA key
pub const PrivateKey = struct {
    public_key: PublicKey,

    // private exponent
    d: math.big.int.Const,

    // prime factors of N, has >= 2 elements.
    primes: []math.big.int.Const,

    pub fn deinit(self: *PrivateKey, allocator: mem.Allocator) void {
        self.public_key.deinit(allocator);
        allocator.free(self.d.limbs);
        for (self.primes) |*prime| {
            allocator.free(prime.limbs);
        }
        allocator.free(self.primes);
    }
};

const testing = std.testing;

test "std.math.big.int.Const const" {
    try testing.expectEqual(@as(u64, 0), try big_zero.to(u64));
    try testing.expectEqual(@as(u64, 1), try big_one.to(u64));
}
