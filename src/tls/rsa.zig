const std = @import("std");
const math = std.math;
const mem = std.mem;
const memx = @import("../memx.zig");
const HashType = @import("auth.zig").HashType;
const SignOpts = @import("crypto.zig").SignOpts;
const bigIntConstFromBytes = @import("big_int.zig").bigIntConstFromBytes;

pub const PublicKey = struct {
    modulus: math.big.int.Const,
    exponent: u64,

    pub fn deinit(self: *PublicKey, allocator: mem.Allocator) void {
        allocator.free(self.modulus.limbs);
    }

    // Size returns the modulus size in bytes. Raw signatures and ciphertexts
    // for or by this public key will have the same size.
    pub fn size(self: *const PublicKey) usize {
        return math.divCeil(usize, self.modulus.bitCountAbs(), 8) catch unreachable;
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

    // Sign signs digest with priv, reading randomness from rand. If opts is a
    // *PSSOptions then the PSS algorithm will be used, otherwise PKCS #1 v1.5 will
    // be used. digest must be the result of hashing the input message using
    // opts.HashFunc().
    //
    // This method implements crypto.Signer, which is an interface to support keys
    // where the private part is kept in, for example, a hardware module. Common
    // uses should use the Sign* functions in this package directly.
    pub fn sign(
        self: *const PrivateKey,
        allocator: mem.Allocator,
        digest: []const u8,
        opts: SignOpts,
    ) ![]const u8 {
        // TODO: handle PSSOptions case
        return try signPKCS1v15(self, allocator, opts.hash_type, digest);
    }
};

// SignPKCS1v15 calculates the signature of hashed using
// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.  Note that hashed must
// be the result of hashing the input message using the given hash
// function. If hash is zero, hashed is signed directly. This isn't
// advisable except for interoperability.
//
// If rand is not nil then RSA blinding will be used to avoid timing
// side-channel attacks.
//
// This function is deterministic. Thus, if the set of possible
// messages is small, an attacker may be able to build a map from
// messages to signatures and identify the signed messages. As ever,
// signatures provide authenticity, not confidentiality.
fn signPKCS1v15(
    priv_key: *const PrivateKey,
    allocator: mem.Allocator,
    hash_type: HashType,
    digest: []const u8,
) ![]const u8 {
    var hash_len: usize = undefined;
    const prefix = try pcks1v15HashInfo(hash_type, digest.len);

    const t_len = prefix.len + hash_len;
    const k = priv_key.public_key.size();
    if (k < t_len + 11) {
        return error.MessageTooLong;
    }

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    var em = try allocator.alloc(u8, k);
    errdefer allocator.free(em);
    em[0] = 0;
    em[1] = 1;
    mem.set(u8, em[2 .. k - t_len - 1], 0xff);
    em[k - t_len - 1] = 0;
    mem.copy(u8, em[k - t_len .. k - hash_len], prefix);
    mem.copy(u8, em[k - hash_len .. k], digest);

    var m = try bigIntConstFromBytes(allocator, em);
    defer allocator.free(m);
}

fn decryptAndCheck(
    allocator: mem.Allocator,
    priv_key: *const PrivateKey,
    c: *const math.big.int.Const,
) !math.big.Int {
    _ = allocator;
    _ = priv_key;
    _ = c;
    @panic("not implemented yet");
}

// decrypt performs an RSA decryption, resulting in a plaintext integer.
fn decrypt(priv_key: *const PrivateKey, c: *const math.big.int.Const) !math.big.Int {
    // TODO(agl): can we get away with reusing blinds?
    if (c.order(priv_key.public_key.modulus) == .gt) {
        return error.Decryption;
    }
    if (priv_key.public_key.modulus.eqZero()) {
        return error.Decryption;
    }
}

// These are ASN1 DER structures:
//   DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
//   }
// For performance, we don't use the generic ASN1 encoder. Rather, we
// precompute a prefix of the digest value that makes a valid ASN1 DER string
// with the correct contents.
const HashPrefix = struct {
    hash_type: HashType,
    prefix: []const u8,
};
const hash_prefixes = [_]HashPrefix{
    .{
        .hash_type = .sha1,
        .prefix = &[_]u8{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 },
    },
    .{
        .hash_type = .sha256,
        .prefix = &[_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 },
    },
    .{
        .hash_type = .sha384,
        .prefix = &[_]u8{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 },
    },
    .{
        .hash_type = .sha512,
        .prefix = &[_]u8{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 },
    },
};

pub fn pcks1v15HashInfo(hash_type: HashType, in_len: usize, hash_len: *usize) ![]const u8 {
    if (hash_type == .direct_signing) {
        hash_len.* = in_len;
        return &[_]u8{};
    }

    hash_len.* = hash_type.digestLength();
    if (in_len != hash_len.*) {
        return error.InputMustBeHashedMessage;
    }

    for (hash_prefixes) |hp| {
        if (hp.hash_type == hash_type) {
            return hp.prefix;
        }
    }
    return error.UnsupportedHashType;
}

const testing = std.testing;

test "divCeil" {
    try testing.expectEqual(@as(usize, 0), try math.divCeil(usize, 0, 8));
    try testing.expectEqual(@as(usize, 1), try math.divCeil(usize, 1, 8));
    try testing.expectEqual(@as(usize, 1), try math.divCeil(usize, 8, 8));
    try testing.expectEqual(@as(usize, 2), try math.divCeil(usize, 9, 8));
}
