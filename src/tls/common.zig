const std = @import("std");
const math = std.math;
const mem = std.mem;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;

// supportedSignatureAlgorithms contains the signature and hash algorithms that
// the code advertises as supported in a TLS 1.2+ ClientHello and in a TLS 1.2+
// CertificateRequest. The two fields are merged to match with TLS 1.3.
// Note that in TLS 1.2, the ECDSA algorithms are not constrained to P-256, etc.
pub const supported_signature_algorithms = &[_]SignatureScheme{
    .pss_with_sha256,
    .ecdsa_with_p256_and_sha256,
    .ed25519,
    .pss_with_sha384,
    .pss_with_sha512,
    .pkcs1_with_sha256,
    .pkcs1_with_sha384,
    .pkcs1_with_sha512,
    .ecdsa_with_p384_and_sha384,
    .ecdsa_with_p521_and_sha512,
    .pkcs1_with_sha1,
    .ecdsa_with_sha1,
};

// setBytes interprets buf as the bytes of a big-endian unsigned
// integer, sets z to that value, and returns z.
pub fn bigIntConstFromBytes(allocator: mem.Allocator, buf: []const u8) !math.big.int.Const {
    const Limb = math.big.Limb;
    var limbs = try allocator.alloc(Limb, try math.divCeil(usize, buf.len, @sizeOf(Limb)));
    errdefer allocator.free(limbs);

    var limbs_bytes = @ptrCast([*]u8, limbs.ptr);
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        // Note:  note bytes in zig's big integer are little-endian ordered.
        limbs_bytes[i] = buf[buf.len - 1 - i];
    }
    mem.set(u8, limbs_bytes[i..limbs.len * @sizeOf(Limb)], 0);

    return math.big.int.Const{ .limbs = limbs, .positive = true };
}

const testing = std.testing;

test "bigIntConstFromBytes" {
    testing.log_level = .debug;
    const buf = &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90 };
    const allocator = testing.allocator;
    var i = try bigIntConstFromBytes(allocator, buf);
    defer allocator.free(i.limbs);

    var s = try i.toStringAlloc(allocator, 10, .lower);
    defer allocator.free(s);
    try testing.expectEqualStrings("78187493520", s);
}
