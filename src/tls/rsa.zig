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
        random: ?std.rand.Random,
        digest: []const u8,
        opts: SignOpts,
    ) ![]const u8 {
        if (opts.salt_length != null) {
            return signPss(
                self,
                allocator,
                random.?,
                opts.hash_type,
                digest,
                opts.salt_length.?,
            );
        }
        return try signPkcs1v15(self, allocator, random, opts.hash_type, digest);
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

// signPkcs1v15 calculates the signature of hashed using
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
fn signPkcs1v15(
    priv_key: *const PrivateKey,
    allocator: mem.Allocator,
    random: ?std.rand.Random,
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

    var m = try bigint.constFromBytes(allocator, em, .Big);
    defer bigint.deinitConst(m, allocator);

    var c = try decryptAndCheck(priv_key, allocator, random, m);
    defer bigint.deinitConst(c, allocator);
    bigint.fillBytes(c, em);
    return em;
}

fn decryptAndCheck(
    priv_key: *const PrivateKey,
    allocator: mem.Allocator,
    random: ?std.rand.Random,
    c: math.big.int.Const,
) !math.big.int.Const {
    var m = try decrypt(priv_key, allocator, random, c);
    errdefer bigint.deinitConst(m, allocator);

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
    random: ?std.rand.Random,
    c: math.big.int.Const,
) !math.big.int.Const {
    // TODO(agl): can we get away with reusing blinds?
    if (c.order(priv_key.public_key.modulus) == .gt) {
        return error.Decryption;
    }
    if (priv_key.public_key.modulus.eqZero()) {
        return error.Decryption;
    }

    var c2 = c;
    defer if (c2.limbs.ptr != c.limbs.ptr) {
        bigint.deinitConst(c2, allocator);
    };
    var ir: ?math.big.int.Managed = null;
    defer if (ir) |*ir2| ir2.deinit();
    if (random) |rand| {
        // Blinding enabled. Blinding involves multiplying c by r^e.
        // Then the decryption operation performs (m^e * r^e)^d mod n
        // which equals mr mod n. The factor of r can then be removed
        // by multiplying by the multiplicative inverse of r.

        var r = try math.big.int.Managed.init(allocator);
        defer r.deinit();
        ir = try math.big.int.Managed.init(allocator);
        while (true) {
            try bigint.unsignedRandomLessThan(&r, rand, priv_key.public_key.modulus);
            if (r.eqZero()) {
                try r.set(1);
            }
            try bigint.modInverse(&ir.?, r.toConst(), priv_key.public_key.modulus);
            if (!ir.?.eqZero()) {
                break;
            }
        }

        var big_e = try math.big.int.Managed.initSet(allocator, priv_key.public_key.exponent);
        defer big_e.deinit();

        var r_pow_e = try math.big.int.Managed.init(allocator);
        defer r_pow_e.deinit();
        try bigint.exp(&r_pow_e, r.toConst(), big_e.toConst(), priv_key.public_key.modulus);

        var c_copy = try c.toManaged(allocator);
        errdefer c_copy.deinit();

        try bigint.mul(&c_copy, c_copy.toConst(), r_pow_e.toConst());
        try bigint.mod(&c_copy, c_copy.toConst(), priv_key.public_key.modulus);

        c2 = c_copy.toConst();
    }

    var m = try math.big.int.Managed.init(allocator);
    errdefer m.deinit();
    if (priv_key.precomputed) |_| {
        @panic("not implemented yet");
    } else {
        try bigint.exp(&m, c2, priv_key.d, priv_key.public_key.modulus);
    }

    if (ir) |*ir2| {
        // Unblind.
        try bigint.mul(&m, m.toConst(), ir2.toConst());
        try bigint.mod(&m, m.toConst(), priv_key.public_key.modulus);
    }

    return m.toConst();
}

fn encrypt(
    allocator: mem.Allocator,
    public_key: *const PublicKey,
    m: math.big.int.Const,
) !math.big.int.Const {
    var e = try math.big.int.Managed.initSet(allocator, public_key.exponent);
    defer e.deinit();
    var out = try math.big.int.Managed.init(allocator);
    errdefer out.deinit();
    try bigint.exp(&out, m, e.toConst(), public_key.modulus);
    return out.toConst();
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
        .prefix = &[_]u8{
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        },
    },
    .{
        .hash_type = .sha256,
        .prefix = &[_]u8{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
    },
    .{
        .hash_type = .sha384,
        .prefix = &[_]u8{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        },
    },
    .{
        .hash_type = .sha512,
        .prefix = &[_]u8{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
    },
};

pub const VerifyPkcs1v15Error = error{
    Verification,
    InputMustBeHashedMessage,
    UnsupportedHashType,
    OutOfMemory,
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
) VerifyPkcs1v15Error!void {
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

    var c = try bigint.constFromBytes(allocator, sig, .Big);
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

pub const PssSaltLength = union(enum) {
    // auto causes the salt in a PSS signature to be as large
    // as possible when signing, and to be auto-detected when verifying.
    auto: void,

    manual: usize,
    // equals_hash causes the salt length to equal the length
    // of the hash used in the signature.
    equals_hash: void,
};

fn signPss(
    priv_key: *const PrivateKey,
    allocator: mem.Allocator,
    random: std.rand.Random,
    hash_type: HashType,
    digest: []const u8,
    salt_length: PssSaltLength,
) ![]const u8 {
    const salt_len = switch (salt_length) {
        .auto => (priv_key.d.bitCountAbs() - 1 + 7) / 8 - 2 - hash_type.digestLength(),
        .manual => |len| len,
        .equals_hash => hash_type.digestLength(),
    };

    var salt = try allocator.alloc(u8, salt_len);
    defer allocator.free(salt);
    random.bytes(salt);

    return try signPssWithSalt(priv_key, allocator, random, hash_type, digest, salt);
}

fn signPssWithSalt(
    priv_key: *const PrivateKey,
    allocator: mem.Allocator,
    random: std.rand.Random,
    hash_type: HashType,
    hashed: []const u8,
    salt: []const u8,
) ![]const u8 {
    const em_bits = priv_key.public_key.modulus.bitCountAbs() - 1;
    var em = try emsaPssEncode(allocator, hashed, em_bits, salt, hash_type);
    defer allocator.free(em);

    var m = try bigint.constFromBytes(allocator, em, .Big);
    defer bigint.deinitConst(m, allocator);

    var c = try decryptAndCheck(priv_key, allocator, random, m);
    defer bigint.deinitConst(c, allocator);

    var s = try allocator.alloc(u8, priv_key.public_key.size());
    bigint.fillBytes(c, s);
    return s;
}

// Per RFC 8017, Section 9.1
//
//     EM = MGF1 xor DB || H( 8*0x00 || mHash || salt ) || 0xbc
//
// where
//
//     DB = PS || 0x01 || salt
//
// and PS can be empty so
//
//     emLen = dbLen + hLen + 1 = psLen + sLen + hLen + 2
//

fn emsaPssEncode(
    allocator: mem.Allocator,
    m_hash: []const u8,
    em_bits: usize,
    salt: []const u8,
    hash_type: HashType,
) ![]const u8 {
    // See RFC 8017, Section 9.1.1.
    const h_len = hash_type.digestLength();
    const s_len = salt.len;
    const em_len = (em_bits + 7) / 8;

    // 1.  If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "message too
    //     long" and stop.
    //
    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    if (m_hash.len != h_len) {
        return error.CryptoRsaInputMustBeHashedWithGivenHash;
    }

    // 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.
    if (em_len < h_len + s_len + 2) {
        return error.CryptoRsaKeySizeTooSmallForPssSignature;
    }

    var em = try allocator.alloc(u8, em_len);
    errdefer allocator.free(em);
    mem.set(u8, em, 0);
    const ps_len = em_len - s_len - h_len - 2;
    var db = em[0 .. ps_len + 1 + s_len];
    const h = em[ps_len + 1 + s_len .. em_len - 1];

    // 4.  Generate a random octet string salt of length sLen; if sLen = 0,
    //     then salt is the empty string.
    //
    // 5.  Let
    //       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
    //
    //     M' is an octet string of length 8 + hLen + sLen with eight
    //     initial zero octets.
    //
    // 6.  Let H = Hash(M'), an octet string of length hLen.
    var prefix = [_]u8{0} ** 8;

    var hash = crypto.Hash.init(hash_type);
    hash.update(&prefix);
    hash.update(m_hash);
    hash.update(salt);

    hash.finalToSlice(h);

    // 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
    //     zero octets. The length of PS may be 0.
    //
    // 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
    //     emLen - hLen - 1.

    db[ps_len] = 0x01;
    mem.copy(u8, db[ps_len + 1 ..], salt);

    // 9.  Let dbMask = MGF(H, emLen - hLen - 1).
    //
    // 10. Let maskedDB = DB \xor dbMask.
    mgf1Xor(db, hash_type, h);

    // 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
    //     maskedDB to zero.
    db[0] &= @as(u8, 0xff) >> @intCast(u3, 8 * em_len - em_bits);

    // 12. Let EM = maskedDB || H || 0xbc.
    em[em_len - 1] = 0xbc;

    // 13. Output EM.
    return em;
}

test "emsaPssEncode" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    const m_hash = "\x7f\xdd\xeb\x8d\x8a\x9e\x4c\x5e\x2e\x7e\x8c\x13\x5a\xb8\xf8\xb6\x19\xba\x21\xae\xb5\x2d\x61\xba\x85\xeb\x1e\x29\x28\x32\xe6\x81";
    const em_bits = 2047;
    const salt = "\xc4\xd8\x67\x64\x3b\xf8\xdc\x07\xd4\xb0\x0b\x3b\x4c\x36\x21\x1b\x57\xa6\x9d\xf9\x78\x78\x6a\xfd\xe9\xea\x94\x88\x85\xfd\x59\xfd";
    const got = try emsaPssEncode(allocator, m_hash, em_bits, salt, .sha256);
    defer allocator.free(got);

    const want = "\x59\x08\x28\xf1\xae\x1c\x6d\x71\x5e\x6f\xd7\x63\xb3\x6c\xef\x35\x59\x20\x00\x04\x95\xde\x46\xfc\x01\x2f\x11\x3d\x20\x23\x73\xec\xdd\xd3\xbd\xda\x1f\x75\x4d\x56\xc7\x7b\xe7\x84\x73\x97\x58\x71\xeb\x4f\x37\xff\xa0\x22\x36\xfa\x0e\x81\x91\x1c\xb1\xbb\xc3\x01\x59\x80\xc0\x9e\x04\x1c\x9f\x20\xe2\x42\x8c\xbc\xc8\x8c\xab\x3a\x74\xf6\x95\x30\x76\xb6\x34\x93\x97\x3c\x6d\x74\x1e\xc1\xd3\xbd\x9d\x61\x4b\x9d\xea\x9f\xff\xef\x71\x70\xfe\xbe\xc6\xeb\xfc\xba\x18\x15\xb8\x54\x6c\x8b\xa3\x81\x1e\x3f\xe0\x3e\x9b\x5d\x94\x74\xca\x0c\xcf\x89\x86\x1f\x60\xbd\x13\xc8\x34\x30\x5b\xd5\x89\xab\x1f\x9c\xf8\xe8\x2d\x64\x6a\x59\x64\xfe\x5d\xe0\xcb\xbb\xa1\xf6\xba\x7d\xde\xe0\x7a\xd8\x58\xf8\xbb\x22\x53\x39\x12\xbd\x0e\xa3\xd3\x02\xa1\x38\x9d\xd7\x3d\xef\xb6\xea\x1f\xb1\xe8\xca\x64\x2e\x42\xde\x6a\xca\xd6\x26\xfa\xb0\x79\x00\xa3\x89\xe5\xa2\x07\x11\x6e\x8c\xdc\xac\x2a\xb3\xef\x9a\xcc\xc3\xd8\x87\x6a\x90\xf4\x42\xb7\x92\x6e\x21\x34\x40\x7c\x91\x9d\xa4\xb7\xa6\xae\xd2\x45\x1d\x4f\x6e\xe8\xaf\x21\x5c\xcc\xf0\x67\x58\x45\x46\x23\xaa\xcf\xbc";
    try testing.expectEqualSlices(u8, want, got);
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
fn mgf1Xor(out: []u8, hash_type: HashType, seed: []const u8) void {
    var counter = [_]u8{0} ** 4;
    var digest = hash_type.initDigestArray().slice();

    var done: usize = 0;
    while (done < out.len) {
        var hash = crypto.Hash.init(hash_type);
        hash.update(seed);
        hash.update(counter[0..4]);
        hash.finalToSlice(digest);

        var i: usize = 0;
        while (i < digest.len and done < out.len) : (i += 1) {
            out[done] ^= digest[i];
            done += 1;
        }
        incCounter(&counter);
    }
}

test "mgf1Xor" {
    const allocator = testing.allocator;
    var out = try allocator.dupe(u8, "\x59\x08\x28\xf1\xae\x1c\x6d\x71\x5e\x6f\xd7\x63\xb3\x6c\xef\x35\x59\x20\x00\x04\x95\xde\x46\xfc\x01\x2f\x11\x3d\x20\x23\x73\xec\xdd\xd3\xbd\xda\x1f\x75\x4d\x56\xc7\x7b\xe7\x84\x73\x97\x58\x71\xeb\x4f\x37\xff\xa0\x22\x36\xfa\x0e\x81\x91\x1c\xb1\xbb\xc3\x01\x59\x80\xc0\x9e\x04\x1c\x9f\x20\xe2\x42\x8c\xbc\xc8\x8c\xab\x3a\x74\xf6\x95\x30\x76\xb6\x34\x93\x97\x3c\x6d\x74\x1e\xc1\xd3\xbd\x9d\x61\x4b\x9d\xea\x9f\xff\xef\x71\x70\xfe\xbe\xc6\xeb\xfc\xba\x18\x15\xb8\x54\x6c\x8b\xa3\x81\x1e\x3f\xe0\x3e\x9b\x5d\x94\x74\xca\x0c\xcf\x89\x86\x1f\x60\xbd\x13\xc8\x34\x30\x5b\xd5\x89\xab\x1f\x9c\xf8\xe8\x2d\x64\x6a\x59\x64\xfe\x5d\xe0\xcb\xbb\xa1\xf6\xba\x7d\xde\xe0\x7a\xd8\x58\xf8\xbb\x22\x53\x39\x12\xbd\x0e\xa3\xd3\x02\xa1\x38\x9d\xd7\x3d\xef\xb6\xea\x1f\xb1\xe8\xca\x64\x2e\x42\xde\x6a\xca\xd6\x26\xfa\xb0\x79\x00\xa3\x89\xe5\xa2\x07\x11\x6e\x8c\xdc\xac\x2a\xb3\xef\x9a\xcc\xc3\xd8\x87\x6a\x90\xf4");
    defer allocator.free(out);
    const seed = "\x42\xb7\x92\x6e\x21\x34\x40\x7c\x91\x9d\xa4\xb7\xa6\xae\xd2\x45\x1d\x4f\x6e\xe8\xaf\x21\x5c\xcc\xf0\x67\x58\x45\x46\x23\xaa\xcf";
    mgf1Xor(out, .sha256, seed);

    const want = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc4\xd8\x67\x64\x3b\xf8\xdc\x07\xd4\xb0\x0b\x3b\x4c\x36\x21\x1b\x57\xa6\x9d\xf9\x78\x78\x6a\xfd\xe9\xea\x94\x88\x85\xfd\x59\xfd";
    try testing.expectEqualSlices(u8, want, out);
}

// incCounter increments a four byte, big-endian counter.
fn incCounter(c: *[4]u8) void {
    c[3] +%= 1;
    if (c[3] != 0) {
        return;
    }
    c[2] +%= 1;
    if (c[2] != 0) {
        return;
    }
    c[1] +%= 1;
    if (c[1] != 0) {
        return;
    }
    c[0] +%= 1;
}

// digest must be the result of hashing the input message using the given hash function.
pub fn verifyPss(
    allocator: mem.Allocator,
    pub_key: *const PublicKey,
    hash_type: HashType,
    digest: []const u8,
    sig: []const u8,
    salt_length: PssSaltLength,
) !void {
    if (sig.len != pub_key.size()) {
        return error.Verification;
    }

    var s = try bigint.constFromBytes(allocator, sig, .Big);
    defer bigint.deinitConst(s, allocator);

    var m = try encrypt(allocator, pub_key, s);
    defer bigint.deinitConst(m, allocator);

    const em_bits = pub_key.modulus.bitCountAbs() - 1;
    const em_len = (em_bits + 7) / 8;
    if (m.bitCountAbs() > em_len * 8) {
        return error.Verification;
    }

    var em = try allocator.alloc(u8, em_len);
    defer allocator.free(em);
    bigint.fillBytes(m, em);

    try emsaPssVerify(allocator, digest, em, em_bits, salt_length, hash_type);
}

fn emsaPssVerify(
    allocator: mem.Allocator,
    m_hash: []const u8,
    em: []const u8,
    em_bits: usize,
    salt_length: PssSaltLength,
    hash_type: HashType,
) !void {
    // See RFC 8017, Section 9.1.2.
    const h_len = hash_type.digestLength();
    var s_len = switch (salt_length) {
        .auto => 0,
        .manual => |len| len,
        .equals_hash => hash_type.digestLength(),
    };
    const em_len = (em_bits + 7) / 8;
    if (em_len != em.len) {
        return error.CryptoRsaInconsistentLength;
    }

    // 1.  If the length of M is greater than the input limitation for the
    //     hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
    //     and stop.
    //
    // 2.  Let mHash = Hash(M), an octet string of length hLen.
    if (h_len != m_hash.len) {
        return error.Verification;
    }

    // 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    if (em_len < h_len + s_len + 2) {
        return error.Verification;
    }

    // 4.  If the rightmost octet of EM does not have hexadecimal value
    //     0xbc, output "inconsistent" and stop.
    if (em[em_len - 1] != 0xbc) {
        return error.Verification;
    }

    // 5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
    //     let H be the next hLen octets.
    var db = try allocator.dupe(u8, em[0 .. em_len - h_len - 1]);
    defer allocator.free(db);
    const h = em[em_len - h_len - 1 .. em_len - 1];

    // 6.  If the leftmost 8 * emLen - emBits bits of the leftmost octet in
    //     maskedDB are not all equal to zero, output "inconsistent" and
    //     stop.
    const bit_mask = @as(u8, 0xff) >> @intCast(u3, 8 * em_len - em_bits);
    if (em[0] & ~bit_mask != 0) {
        return error.Verification;
    }

    // 7.  Let dbMask = MGF(H, emLen - hLen - 1).
    //
    // 8.  Let DB = maskedDB \xor dbMask.
    mgf1Xor(db, hash_type, h);

    // 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
    //     to zero.
    db[0] &= bit_mask;

    if (salt_length == .auto) {
        if (mem.indexOfScalar(u8, db, 0x01)) |ps_len| {
            s_len = db.len - ps_len - 1;
        } else return error.Verification;
    }

    // 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
    //     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
    //     position is "position 1") does not have hexadecimal value 0x01,
    //     output "inconsistent" and stop.
    const ps_len = em_len - h_len - s_len - 2;
    for (db[0..ps_len]) |e| {
        if (e != 0x00) {
            return error.Verification;
        }
    }
    if (db[ps_len] != 0x01) {
        return error.Verification;
    }

    // 11.  Let salt be the last sLen octets of DB.
    const salt = db[db.len - s_len ..];

    // 12.  Let
    //          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    //     M' is an octet string of length 8 + hLen + sLen with eight
    //     initial zero octets.
    //
    // 13. Let H' = Hash(M'), an octet string of length hLen.
    var prefix = [_]u8{0} ** 8;

    var hash = crypto.Hash.init(hash_type);
    hash.update(&prefix);
    hash.update(m_hash);
    hash.update(salt);

    var h0 = try hash.allocFinal(allocator);
    defer allocator.free(h0);

    // 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    if (!mem.eql(u8, h0, h)) { // TODO: constant time?
        return error.Verification;
    }
}

const testing = std.testing;

test "rsa.signPss and verifyPss" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);

    const priv_key_der = "\x30\x82\x04\xa4\x02\x01\x00\x02\x82\x01\x01\x00\xd3\x72\xe8\x35\x01\xed\xac\xf7\xe7\xd8\x4f\x70\x77\x2d\xba\x3a\x8c\x50\xaa\x2a\xff\xc4\xb4\xc5\xd5\x51\xb3\xaa\x8e\xea\xf1\xb2\x6f\xd4\x17\xea\x6e\x7d\x00\xb2\xdc\x1b\x94\x4f\xc2\xce\x4d\xd9\x77\xf3\xd3\x58\x75\x73\x44\xd9\xdd\x21\xc4\x41\xf0\xaf\x32\xf2\x7b\x9d\x3f\x1d\xed\xe6\x5f\xc2\x0c\x56\x60\x07\x76\xf3\xfe\x11\x09\x44\x42\x23\x47\x58\xe4\xbc\x02\x91\x91\xbc\xa0\x9c\x50\x64\x8e\x70\xab\x23\x56\x94\xe5\xfa\x8a\x26\xaa\xa8\xf1\xc8\x7e\xe4\xc8\x3b\xb1\xc7\x8b\x44\x44\xd3\x3f\xe6\xe4\xf6\xc5\xb4\x7e\x84\xe3\x8d\xdd\x8a\x10\x35\x7f\xd1\x7f\xb2\x10\x7b\xe5\xaa\xa6\xb8\x1d\x90\x27\x42\x85\x5c\xa9\xf4\xc3\x51\xf4\x2a\x09\x1d\x6c\xfe\x16\xa9\x99\x63\x23\x58\xcf\x20\xfe\xcd\xc0\x95\xe3\xa1\xce\x7e\x5a\x45\x45\xd7\x16\x25\x35\x32\x35\x6b\xc0\x2a\x35\x04\xdf\x54\xc2\x33\x46\xa1\x27\x20\x29\xf1\xa4\xac\x96\xb5\x94\xba\x9c\x26\xa5\xb1\xc6\x4d\x28\xc7\x39\xb8\x65\x7e\x95\xf6\x8b\x0d\x2f\xf1\xb8\xcc\xb2\xa6\x33\x90\xcd\x67\x97\xc5\xe9\x82\x24\x29\xb7\x9f\x1b\x23\x83\x20\x64\xf8\x08\x51\x86\x6f\x47\xed\x04\x19\x9c\x11\x02\x03\x01\x00\x01\x02\x82\x01\x00\x27\x0d\x69\xe5\xa0\x5d\x8d\x3c\x9c\x0d\x4f\x5e\xae\x24\x3b\xe8\xe4\x51\x61\x9c\x5f\x70\xad\x12\x7c\xbb\x82\x3b\x55\xf9\xfe\x79\xbe\x3d\xa5\xcd\x1e\x6a\xe7\xde\x20\xd8\xd7\x23\x84\x0f\x26\x41\xab\xed\xd4\x72\xd9\xfe\x58\x11\x04\xce\x5f\xb8\xee\x02\xed\x9d\xeb\x46\xb7\x89\x87\x8e\xac\xd0\xe2\x06\x71\xe5\xef\x0a\x51\x3a\x44\x43\xdf\x13\x34\xf2\x2e\x0c\xab\x4c\xc7\x65\xd7\x24\x07\x95\x0a\xd9\xb4\x41\xea\x93\xc5\x85\xe8\x4e\x0b\xe6\xf8\x00\xd7\xae\xd9\x6c\x6d\x01\x35\xaf\x7e\x26\xa5\xfe\xb6\xfa\xfc\xb8\xc1\x44\xe3\xb0\xcc\xce\xdb\x93\x83\xaa\x44\x83\x61\x85\x52\xd3\x78\x7e\x2e\x0f\x76\xc3\xaf\xf4\x2f\xb0\x4b\xbe\xf5\xc0\x75\xbc\x0c\x06\x63\x94\x07\x5b\x12\x33\xa8\xee\xff\xdf\xc2\xdb\x28\xeb\xa3\x69\x27\x5a\x2f\x88\xa0\xa8\x99\xc8\x5c\xe3\x60\x42\x51\x19\xab\xe8\x8a\xd8\x68\xee\xf6\x41\x36\x15\x70\x44\x77\x64\xad\x5d\x75\x72\x1d\x74\xf3\x8e\x82\xb1\x8f\x6a\xcd\xaa\x71\xaa\xd0\xd0\x63\x66\x20\xf8\x4d\x2d\x83\xfe\x64\xf7\xe3\x4c\xb7\x00\x4c\xd2\x3e\xa7\x8f\xbe\xeb\x6a\xce\xe3\xdb\x67\x09\x80\xa6\x23\x50\x83\xd3\x81\x02\x81\x81\x00\xd7\x86\xf6\x85\xe5\xfd\x98\xdb\xb1\x5d\x7b\xf5\x1f\xe3\x79\x24\xbe\xc1\x5b\xf0\x86\x16\x65\x7f\x8d\x37\x5e\xac\x0b\xc5\xc7\xd4\x6c\x71\x3b\x2e\xbf\xc2\x83\x5a\x14\xd7\xe0\xf9\x6d\x40\x12\x53\xe0\x2e\xda\x7b\x78\x6c\x1e\x42\x88\xfb\xcf\x74\x2e\x12\xa6\xd7\xc6\x74\x86\x43\xd0\xcb\x5c\x2c\x89\x5b\x6f\x12\x5c\x58\xfe\x6b\xa7\x24\xbf\x9b\x43\x5a\x8f\x0a\xa3\x4e\xd2\xfd\x00\x88\x5e\x3c\xe4\x1e\x2e\xa7\xff\xb1\x95\xa7\x9b\x1f\x81\xe7\xff\xbf\xb4\x6c\x33\x9f\x14\xae\x45\xa6\x81\x33\xbe\x83\x52\x7f\x5b\xb1\xb9\x8d\x02\x81\x81\x00\xfb\x27\xe2\xcb\x22\xe4\x80\xa4\x14\x17\x33\xba\xa0\x07\x92\xb8\xf6\xa1\x58\xb4\x7f\xb3\x3d\x6d\x04\x5f\xec\xa4\x7e\x58\xca\xd7\xc7\xc7\x73\x09\x0a\x72\x05\x55\x5d\x0a\xf7\x3c\xc8\xce\xc7\x10\x05\xf2\x10\x9b\x66\x89\xa9\x71\x7a\x71\xb1\x4f\x4b\x37\xfe\x93\x2c\xcb\x05\xeb\x50\x3c\x84\x32\x46\x97\x8c\xa0\x3e\x42\x15\xdf\x24\x4d\x62\xaa\xa8\x57\x78\xd7\x71\x89\x48\x5c\xcf\x25\x78\x66\x66\x0e\xd4\x68\xc6\x25\xc1\x01\xf8\x27\x49\x60\xdf\x28\x4a\x0e\x38\xc3\xfb\xdc\x54\xd0\x61\x27\x7d\xa6\x41\x7c\x11\x7f\x51\x95\x02\x81\x80\x59\x65\xf1\xfb\xb8\x5a\x68\x7d\x38\x24\xbe\xb5\xfe\x74\x2c\x5b\xc1\x84\x12\xce\xc1\xcf\xa8\x6a\x2f\xf9\x37\x9b\xc5\x86\x54\x4d\x18\x6e\x1f\x4e\x54\xdc\x29\xff\xc3\x85\x88\x1b\xed\xe5\x15\xb5\x14\xd8\x5a\x67\xbc\x9b\x9c\x31\x9d\x00\x56\x1c\xaa\xbf\xb1\xd4\xee\xcc\x86\xa4\xba\x86\x9f\xc5\x19\x74\x83\xad\xea\x00\x40\x08\x07\x5c\x86\xdd\xb0\x22\x70\x12\xc9\x8a\x78\x99\xd9\x0e\xb7\x88\x2a\x57\x1a\xa3\x34\xbc\x44\x87\x31\x20\xf0\x91\x7a\xd3\xd9\xd2\xc7\xd6\xc4\x8d\x44\xf6\xbb\xc0\xea\xd5\x2d\xf3\x05\xe5\xc2\x41\x02\x81\x81\x00\xd9\x86\x15\x16\x2c\xd5\x4d\x59\x4e\x91\x3d\xdb\x40\x28\xee\xf9\xc5\x99\xbe\x93\x2e\x1a\xd6\x73\xaa\x1b\x4e\x80\xb5\x71\x3f\xd5\x9d\x90\xef\xdf\xff\xac\xfb\x53\x90\xaf\x23\xad\x00\x9a\x9e\xac\x11\x0a\x33\x39\xf4\x97\xfc\x2a\x6d\x8b\x34\xaf\x61\x8d\x50\xae\xb5\x57\xed\x7b\x7d\xd5\xbc\x05\x33\x40\xa4\xaa\x50\xe1\xb9\xc1\xb6\xd6\x53\x43\x4d\x63\xdd\x24\x73\x90\x1c\x1d\x4d\xc7\xbd\x3c\xaa\xdd\xe3\x38\x0f\x8d\xb9\x59\x74\x4c\xca\x6f\xdd\x37\x2e\xd4\x9c\x73\x99\x9a\x9d\xd6\x90\x9e\xbc\x63\x97\x49\xd6\x79\xb7\xf5\x02\x81\x81\x00\xcd\xd6\x71\x32\x43\xed\x5f\x95\x4c\x1b\x9a\xfd\x59\xe7\x2f\x9d\x15\x4b\xb8\x46\x48\x2d\x87\xd4\xf8\x8f\x50\x8d\x68\x06\x54\xd1\x35\xd7\x0d\xdf\x3e\xd4\x6d\x2b\xcf\x04\xbc\x1a\x00\x78\x3c\x51\x38\x3a\x4a\xf0\x84\xbb\x87\x93\x7b\xcb\x00\xfa\x70\x3e\xc5\xc2\x17\xcf\xb9\x2a\xce\x76\x4d\x95\x6d\x96\xb5\x66\x1a\x22\x37\xed\xce\xfb\x6d\xb3\x50\xb5\x4f\x4c\xf5\xa3\x45\x61\x62\x93\x09\x9a\xfe\x77\x2b\x92\x0a\x2c\x43\x59\x6b\x4f\xf7\x32\xcd\x3a\xe6\x0d\x37\x7b\xd1\x8e\x42\xd6\x19\x44\x3b\x7e\x46\x71\x00\xf8\x2a\xc9";
    var priv_key = try crypto.PrivateKey.parse(allocator, priv_key_der);
    defer priv_key.deinit(allocator);
    const want_priv_d = "\x27\x0d\x69\xe5\xa0\x5d\x8d\x3c\x9c\x0d\x4f\x5e\xae\x24\x3b\xe8\xe4\x51\x61\x9c\x5f\x70\xad\x12\x7c\xbb\x82\x3b\x55\xf9\xfe\x79\xbe\x3d\xa5\xcd\x1e\x6a\xe7\xde\x20\xd8\xd7\x23\x84\x0f\x26\x41\xab\xed\xd4\x72\xd9\xfe\x58\x11\x04\xce\x5f\xb8\xee\x02\xed\x9d\xeb\x46\xb7\x89\x87\x8e\xac\xd0\xe2\x06\x71\xe5\xef\x0a\x51\x3a\x44\x43\xdf\x13\x34\xf2\x2e\x0c\xab\x4c\xc7\x65\xd7\x24\x07\x95\x0a\xd9\xb4\x41\xea\x93\xc5\x85\xe8\x4e\x0b\xe6\xf8\x00\xd7\xae\xd9\x6c\x6d\x01\x35\xaf\x7e\x26\xa5\xfe\xb6\xfa\xfc\xb8\xc1\x44\xe3\xb0\xcc\xce\xdb\x93\x83\xaa\x44\x83\x61\x85\x52\xd3\x78\x7e\x2e\x0f\x76\xc3\xaf\xf4\x2f\xb0\x4b\xbe\xf5\xc0\x75\xbc\x0c\x06\x63\x94\x07\x5b\x12\x33\xa8\xee\xff\xdf\xc2\xdb\x28\xeb\xa3\x69\x27\x5a\x2f\x88\xa0\xa8\x99\xc8\x5c\xe3\x60\x42\x51\x19\xab\xe8\x8a\xd8\x68\xee\xf6\x41\x36\x15\x70\x44\x77\x64\xad\x5d\x75\x72\x1d\x74\xf3\x8e\x82\xb1\x8f\x6a\xcd\xaa\x71\xaa\xd0\xd0\x63\x66\x20\xf8\x4d\x2d\x83\xfe\x64\xf7\xe3\x4c\xb7\x00\x4c\xd2\x3e\xa7\x8f\xbe\xeb\x6a\xce\xe3\xdb\x67\x09\x80\xa6\x23\x50\x83\xd3\x81";
    {
        const d_bytes = try bigint.constToBytesBig(allocator, priv_key.rsa.d);
        defer allocator.free(d_bytes);
        try testing.expectEqualSlices(u8, want_priv_d, d_bytes);
    }

    const digest = "\x7f\xdd\xeb\x8d\x8a\x9e\x4c\x5e\x2e\x7e\x8c\x13\x5a\xb8\xf8\xb6\x19\xba\x21\xae\xb5\x2d\x61\xba\x85\xeb\x1e\x29\x28\x32\xe6\x81";
    const sig = try priv_key.rsa.sign(
        allocator,
        rand.random(),
        digest,
        .{ .salt_length = .equals_hash },
    );
    defer allocator.free(sig);

    const want_sig = "\x10\x39\x5d\x99\x1e\x59\x91\xdc\x8a\x6e\x8e\x89\xed\x35\xb2\x42\x40\xe5\x32\x8e\xa4\xe0\xb0\xb0\x5f\x96\xd2\x18\xf1\x9f\x7a\x3d\xce\x8b\xee\x9d\x4a\xb9\xf0\x0f\x8b\xa7\xaf\xc9\xf9\x49\xa4\x9a\x02\x44\x55\x8c\xaf\xf6\x7b\xd8\x2e\x8d\x93\xf8\xf6\x22\xc9\x74\x31\x62\x3e\xb3\xa8\x1b\xcf\x1b\x9e\xac\x3f\x19\x3a\x58\xff\x38\x21\xe3\xb6\x52\x2c\xdf\x5c\x45\xf3\x72\x19\x50\xc0\x89\xae\x98\x0d\xb7\xdf\xc5\x5a\xed\xa7\x1d\x29\xe8\x77\x1f\x61\xd9\xaf\x2a\xfc\xb0\xa6\x72\xfe\xa5\x9e\x7c\x26\x3d\x8e\xc1\x3f\x5f\xc5\xdd\x55\xff\xe1\x4e\x7e\x58\xd2\x36\x40\x0c\xd4\xec\x1f\xcb\x0c\xf3\x1b\x28\xd6\x49\xa4\x6b\xe4\x2f\x55\xe1\x43\x4e\xed\x66\xf0\xc0\x51\x3b\x09\x30\x2d\xbb\x0e\xd7\x21\x5f\x3a\x54\xa5\x87\x8d\x3f\x45\xf2\xc7\x36\xd4\xad\x87\x94\x8e\xbf\x4b\x5e\x28\x7c\x30\x9f\xc3\x1e\x1b\xf7\xa4\x5f\x3e\x65\xf3\x92\x2f\x51\xff\xff\xb2\x36\xbe\x95\x18\x6c\xea\xf2\x73\x7a\x0b\x1a\xed\x5b\x49\x7b\xb7\x35\x2a\x14\x9e\x62\xe9\x87\xfe\xe0\x47\x03\xf3\x6d\xe1\x26\x0d\xe4\xd6\xbe\xac\x12\x01\xe0\xec\x8e\xd6\x7c\x22\xb3\x9a\xfb\x42\x3f";
    try testing.expectEqualSlices(u8, want_sig, sig);

    try verifyPss(
        allocator,
        &priv_key.public().rsa,
        .sha256,
        digest,
        sig,
        .equals_hash,
    );
}

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

    var modulus = try math.big.int.Managed.init(allocator);
    errdefer modulus.deinit();
    try modulus.setString(10, "9353930466774385905609975137998169297361893554149986716853295022578535724979677252958524466350471210367835187480748268864277464700638583474144061408845077");
    var pub_key = PublicKey{
        .modulus = modulus.toConst(),
        .exponent = 65537,
    };
    defer pub_key.deinit(allocator);

    var h = crypto.Sha1Hash.init(.{});
    h.update(in);
    var digest = try h.allocFinal(allocator);
    defer allocator.free(digest);

    try verifyPkcs1v15(allocator, &pub_key, .sha1, digest, out);
}
