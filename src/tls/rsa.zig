const std = @import("std");
const math = std.math;
const mem = std.mem;
const memx = @import("../memx.zig");
const fmtx = @import("../fmtx.zig");
const HashType = @import("auth.zig").HashType;
const SignOpts = @import("crypto.zig").SignOpts;
const bigint = @import("big_int.zig");
const crypto = @import("crypto.zig");
const constantTimeEqlBytes = @import("constant_time.zig").constantTimeEqlBytes;
const constantTimeEqlByte = @import("constant_time.zig").constantTimeEqlByte;

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

    pub fn format(
        self: PublicKey,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = try writer.write("PublicKey{ modulus = ");
        try bigint.formatConst(self.modulus, fmt, options, writer);
        try std.fmt.format(writer, ", exponent = {} }}", .{self.exponent});
    }
};

// A PrivateKey represents an RSA key
pub const PrivateKey = struct {
    public_key: PublicKey,

    // private exponent
    d: math.big.int.Const,

    // prime factors of N, has >= 2 elements.
    primes: []math.big.int.Const,

    // Precomputed contains precomputed values that speed up private
    // operations, if available.
    precomputed: ?PrecomputedValues = null,

    pub fn deinit(self: *PrivateKey, allocator: mem.Allocator) void {
        self.public_key.deinit(allocator);
        allocator.free(self.d.limbs);
        for (self.primes) |prime| {
            bigint.deinitConst(prime, allocator);
        }
        allocator.free(self.primes);
        if (self.precomputed) |*precomputed| {
            precomputed.deinit(allocator);
        }
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

const PrecomputedValues = struct {
    // D mod (P-1) (or mod Q-1)
    dp: math.big.int.Const,
    dq: math.big.int.Const,

    // Q^-1 mod P
    qinv: math.big.int.Const,

    // CRTValues is used for the 3rd and subsequent primes. Due to a
    // historical accident, the CRT for the first two primes is handled
    // differently in PKCS #1 and interoperability is sufficiently
    // important that we mirror this.
    crt_values: []CrtValue = &[_]CrtValue{},

    pub fn deinit(self: *PrecomputedValues, allocator: mem.Allocator) void {
        allocator.free(self.dp.limbs);
        allocator.free(self.dq.limbs);
        allocator.free(self.qinv.limbs);
        memx.deinitSliceAndElems(CrtValue, self.crt_values, allocator);
    }
};

// CRTValue contains the precomputed Chinese remainder theorem values.
const CrtValue = struct {
    // D mod (prime-1).
    exp: math.big.int.Const,

    // R·Coeff ≡ 1 mod Prime.
    coeff: math.big.int.Const,

    // product of primes prior to this (inc p and q).
    r: math.big.int.Const,

    pub fn deinit(self: *CrtValue, allocator: mem.Allocator) void {
        allocator.free(self.exp.limbs);
        allocator.free(self.coeff.limbs);
        allocator.free(self.r.limbs);
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
    const prefix = try pcks1v15HashInfo(hash_type, digest.len, &hash_len);

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

    var m = try bigint.constFromBytes(allocator, em);
    defer bigint.deinitConst(m, allocator);

    var c = try decryptAndCheck(priv_key, allocator, m);
    defer bigint.deinitConst(c, allocator);
    bigint.fillBytes(c, em);
    return em;
}

fn decryptAndCheck(
    priv_key: *const PrivateKey,
    allocator: mem.Allocator,
    c: math.big.int.Const,
) !math.big.int.Const {
    var m = try decrypt(priv_key, allocator, c);

    // In order to defend against errors in the CRT computation, m^e is
    // calculated, which should match the original ciphertext.
    var check = try encrypt(allocator, &priv_key.public_key, m);
    defer bigint.deinitConst(check, allocator);
    if (!c.eq(check)) {
        return error.RsaInternalError;
    }
    return m;
}

// decrypt performs an RSA decryption, resulting in a plaintext integer.
fn decrypt(
    priv_key: *const PrivateKey,
    allocator: mem.Allocator,
    c: math.big.int.Const,
) !math.big.int.Const {
    // TODO(agl): can we get away with reusing blinds?
    if (c.order(priv_key.public_key.modulus) == .gt) {
        return error.Decryption;
    }
    if (priv_key.public_key.modulus.eqZero()) {
        return error.Decryption;
    }

    var m = if (priv_key.precomputed) |_| {
        @panic("not implemented yet");
    } else blk: {
        break :blk try bigint.expConst(allocator, c, priv_key.d, priv_key.public_key.modulus);
    };
    return m;
}

fn encrypt(
    allocator: mem.Allocator,
    public_key: *const PublicKey,
    m: math.big.int.Const,
) !math.big.int.Const {
    var e = try math.big.int.Managed.initSet(allocator, public_key.exponent);
    defer e.deinit();
    return try bigint.expConst(allocator, m, e.toConst(), public_key.modulus);
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

// verifyPkcs1v15 verifies an RSA PKCS #1 v1.5 signature.
// hashed is the result of hashing the input message using the given hash
// function and sig is the signature. A valid signature is indicated by
// returning a nil error. If hash is zero then hashed is used directly. This
// isn't advisable except for interoperability.
pub fn verifyPkcs1v15(
    allocator: mem.Allocator,
    pub_key: *const PublicKey,
    hash_type: HashType,
    hashed: []const u8,
    sig: []const u8,
) !void {
    var hash_len: usize = undefined;
    const prefix = try pcks1v15HashInfo(hash_type, hashed.len, &hash_len);

    const t_len = prefix.len + hash_len;
    const k = pub_key.size();
    if (k < t_len + 11) {
        return error.Verification;
    }

    // RFC 8017 Section 8.2.2: If the length of the signature S is not k
    // octets (where k is the length in octets of the RSA modulus n), output
    // "invalid signature" and stop.
    if (k != sig.len) {
        return error.Verification;
    }

    var c = try bigint.constFromBytes(allocator, sig);
    defer bigint.deinitConst(c, allocator);

    var m = try encrypt(allocator, pub_key, c);
    defer bigint.deinitConst(m, allocator);

    var em = try allocator.alloc(u8, k);
    defer allocator.free(em);

    bigint.fillBytes(m, em);

    // EM = 0x00 || 0x01 || PS || 0x00 || T

    var ok = constantTimeEqlByte(em[0], 0);
    ok &= constantTimeEqlByte(em[1], 1);
    ok &= constantTimeEqlBytes(em[k - hash_len .. k], hashed);
    ok &= constantTimeEqlBytes(em[k - t_len .. k - hash_len], prefix);
    ok &= constantTimeEqlByte(em[k - t_len - 1], 0);

    var i: usize = 2;
    while (i < k - t_len - 1) : (i += 1) {
        ok &= constantTimeEqlByte(em[i], 0xff);
    }

    if (ok != 1) {
        return error.Verification;
    }
}

pub fn pcks1v15HashInfo(hash_type: HashType, in_len: usize, out_hash_len: *usize) ![]const u8 {
    if (hash_type == .direct_signing) {
        out_hash_len.* = in_len;
        return &[_]u8{};
    }

    out_hash_len.* = hash_type.digestLength();
    if (in_len != out_hash_len.*) {
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

test "verifyPkcs1v15" {
    const in = "Test.\n";
    const out = "\xa4\xf3\xfa\x6e\xa9\x3b\xcd\xd0\xc5\x7b\xe0\x20\xc1\x19\x3e\xcb\xfd\x6f\x20\x0a\x3d\x95\xc4\x09\x76\x9b\x02\x95\x78\xfa\x0e\x33\x6a\xd9\xa3\x47\x60\x0e\x40\xd3\xae\x82\x3b\x8c\x7e\x6b\xad\x88\xcc\x07\xc1\xd5\x4c\x3a\x15\x23\xcb\xbb\x6d\x58\xef\xc3\x62\xae";

    const allocator = testing.allocator;

    var pub_key = PublicKey{
        .modulus = try bigint.constFromDecimal(
            allocator,
            "9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077",
        ),
        .exponent = 65537,
    };
    defer pub_key.deinit(allocator);

    var h = crypto.Sha1Hash.init(.{});
    h.update(in);
    var digest = try h.allocFinal(allocator);
    defer allocator.free(digest);

    try verifyPkcs1v15(allocator, &pub_key, .sha1, digest, out);
}
