const std = @import("std");
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

// hello_retry_request_random is set as the Random value of a ServerHello
// to signal that the message is actually a HelloRetryRequest.
pub const hello_retry_request_random = [_]u8{ // See RFC 8446, Section 4.1.3.
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};
