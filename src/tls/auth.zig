const std = @import("std");
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;

// Signature algorithms (for internal signaling use). Starting at 225 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
pub const SignatureType = enum(u8) {
    Pkcs1v15 = 225,
    RsaPss = 226,
    Ecdsa = 227,
    Ed25519 = 228,

    pub fn fromSinatureScheme(s: SignatureScheme) !SignatureType{
        return switch (s) {
            .Pkcs1WithSha256 => SignatureType.Pkcs1v15,
            .Ed25519 => SignatureType.Ed25519,
        };
    }
};

pub const HashType = enum {
    sha256,
    direct_signing,

    pub fn fromSinatureScheme(s: SignatureScheme) !HashType{
        return switch (s) {
            .Pkcs1WithSha256 => HashType.sha256,
            .Ed25519 => HashType.direct_signing,
        };
    }
};
