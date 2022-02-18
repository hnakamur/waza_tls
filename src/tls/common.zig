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
