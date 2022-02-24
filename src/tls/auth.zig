const std = @import("std");
const mem = std.mem;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const crypto = @import("crypto.zig");
const ecdsa = @import("ecdsa.zig");
const memx = @import("../memx.zig");

pub const server_signature_context = "TLS 1.3, server CertificateVerify\x00";
pub const client_signature_context = "TLS 1.3, client CertificateVerify\x00";

const signature_padding = [_]u8{0x20} ** 64;

pub fn verifyHandshakeSignature(
    allocator: mem.Allocator,
    sig_type: SignatureType,
    public_key: crypto.PublicKey,
    sig_hash: HashType,
    signed: []const u8,
    signature: []const u8,
) !void {
    _ = sig_hash;
    switch (sig_type) {
        .pkcs1v15 => @panic("not implemented yet"),
        .rsa_pss => @panic("not implemented yet"),
        .ecdsa => {
            switch (public_key) {
                .ecdsa => |*pub_key| {
                    if (!(ecdsa.verifyAsn1(allocator, pub_key, signed, signature) catch false)) {
                        return error.HandshakeVerifyFailure;
                    }
                },
                else => return error.ExpectedEcdsaPublicKey,
            }
        },
        .ed25519 => @panic("not implemented yet"),
        else => return error.InvalidSignatureType,
    }
}

// signedMessage returns the pre-hashed (if necessary) message to be signed by
// certificate keys in TLS 1.3. See RFC 8446, Section 4.4.3.
pub fn signedMessage(
    allocator: mem.Allocator,
    sig_hash: HashType,
    context: []const u8,
    transcript: crypto.Hash,
) ![]const u8 {
    if (sig_hash == .direct_signing) {
        var buf = std.ArrayList(u8).init(allocator);
        errdefer buf.deinit();
        var writer = buf.writer();
        try writer.writeAll(&signature_padding);
        try writer.writeAll(context);
        _ = try transcript.writeFinal(writer);
        return buf.toOwnedSlice();
    }

    var h = crypto.Hash.init(sig_hash);
    h.update(&signature_padding);
    h.update(context);
    switch (h) {
        .sha256 => |*h2| _ = try transcript.writeFinal(h2.writer()),
        .sha384 => |*h2| _ = try transcript.writeFinal(h2.writer()),
        else => @panic("invalid hash_type for TLS 1.3"),
    }
    return try h.allocFinal(allocator);
}

// Signature algorithms (for internal signaling use). Starting at 225 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
pub const SignatureType = enum(u8) {
    pkcs1v15 = 225,
    rsa_pss = 226,
    ecdsa = 227,
    ed25519 = 228,
    _,

    pub fn fromSinatureScheme(s: SignatureScheme) !SignatureType {
        return switch (s) {
            .pkcs1_with_sha256,
            .pkcs1_with_sha384,
            .pkcs1_with_sha512,
            .pkcs1_with_sha1,
            => SignatureType.pkcs1v15,
            .pss_with_sha256,
            .pss_with_sha384,
            .pss_with_sha512,
            => SignatureType.rsa_pss,
            .ecdsa_with_p256_and_sha256,
            .ecdsa_with_p384_and_sha384,
            .ecdsa_with_p521_and_sha512,
            .ecdsa_with_sha1,
            => SignatureType.ecdsa,
            .ed25519 => SignatureType.ed25519,
            else => @panic("unsupported signature scheme"),
        };
    }
};

pub const HashType = enum {
    sha256,
    sha384,
    sha512,
    direct_signing,
    sha1,

    pub fn fromSinatureScheme(s: SignatureScheme) !HashType {
        return switch (s) {
            .pkcs1_with_sha256, .pss_with_sha256, .ecdsa_with_p256_and_sha256 => HashType.sha256,
            .pkcs1_with_sha384, .pss_with_sha384, .ecdsa_with_p384_and_sha384 => HashType.sha384,
            .pkcs1_with_sha512, .pss_with_sha512, .ecdsa_with_p521_and_sha512 => HashType.sha512,
            .ed25519 => HashType.direct_signing,
            .pkcs1_with_sha1, .ecdsa_with_sha1 => HashType.sha1,
            else => @panic("unsupported signature scheme"),
        };
    }

    pub fn digestLength(hash_type: HashType) usize {
        return switch (hash_type) {
            .sha256 => std.crypto.hash.sha2.Sha256.digest_length,
            .sha384 => std.crypto.hash.sha2.Sha384.digest_length,
            .sha512 => std.crypto.hash.sha2.Sha512.digest_length,
            .sha1 => std.crypto.hash.Sha1.digest_length,
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn hmacType(hash_type: HashType) type {
        return switch (hash_type) {
            .sha256 => std.crypto.auth.hmac.sha2.HmacSha256,
            .sha384 => std.crypto.auth.hmac.sha2.HmacSha384,
            .sha512 => std.crypto.auth.hmac.sha2.HmacSha512,
            .sha1 => std.crypto.auth.hmac.HmacSha1,
            else => @panic("Unsupported HashType"),
        };
    }
};

// selectSignatureScheme picks a SignatureScheme from the peer's preference list
// that works with the selected certificate. It's only called for protocol
// versions that support signature algorithms, so TLS 1.2 and 1.3.
pub fn selectSignatureScheme(
    allocator: mem.Allocator,
    ver: ProtocolVersion,
    cert: *const CertificateChain,
    peer_algs: ?[]const SignatureScheme,
) !SignatureScheme {
    var supported_algs = try signatureSchemesForCertificate(allocator, ver, cert);
    defer allocator.free(supported_algs);
    if (supported_algs.len == 0) {
        return error.UnsupportedCertificate;
    }

    var peer_algs2: ?[]const SignatureScheme = peer_algs;
    if ((peer_algs == null or peer_algs.?.len == 0) and ver == .v1_2) {
        // For TLS 1.2, if the client didn't send signature_algorithms then we
        // can assume that it supports SHA1. See RFC 5246, Section 7.4.1.4.1.
        peer_algs2 = &[_]SignatureScheme{ .pkcs1_with_sha1, .ecdsa_with_sha1 };
    }

    // Pick signature scheme in the peer's preference order, as our
    // preference order is not configurable.
    if (peer_algs2) |peer_algs3| {
        for (peer_algs3) |preferred_alg| {
            if (isSupportedSignatureAlgorithm(preferred_alg, supported_algs)) {
                return preferred_alg;
            }
        }
    }
    return error.PeerDoesNotSupportCertificateSignatureScheme;
}

const RsaSignatureScheme = struct {
    scheme: SignatureScheme,
    min_modulus_bytes: usize,
    max_version: ProtocolVersion,
};

const rsa_signature_schemes = &[_]RsaSignatureScheme{
    // RSA-PSS is used with PSSSaltLengthEqualsHash, and requires
    //    emLen >= hLen + sLen + 2
    .{
        .scheme = .pss_with_sha256,
        .min_modulus_bytes = std.crypto.hash.sha2.Sha256.digest_length * 2 + 2,
        .max_version = .v1_3,
    },
    .{
        .scheme = .pss_with_sha384,
        .min_modulus_bytes = std.crypto.hash.sha2.Sha384.digest_length * 2 + 2,
        .max_version = .v1_3,
    },
    .{
        .scheme = .pss_with_sha512,
        .min_modulus_bytes = std.crypto.hash.sha2.Sha512.digest_length * 2 + 2,
        .max_version = .v1_3,
    },
    // PKCS #1 v1.5 uses prefixes from hashPrefixes in crypto/rsa, and requires
    //    emLen >= len(prefix) + hLen + 11
    // TLS 1.3 dropped support for PKCS #1 v1.5 in favor of RSA-PSS.
    .{
        .scheme = .pss_with_sha256,
        .min_modulus_bytes = 19 + std.crypto.hash.sha2.Sha256.digest_length + 11,
        .max_version = .v1_2,
    },
    .{
        .scheme = .pss_with_sha384,
        .min_modulus_bytes = 19 + std.crypto.hash.sha2.Sha384.digest_length + 11,
        .max_version = .v1_2,
    },
    .{
        .scheme = .pss_with_sha512,
        .min_modulus_bytes = 19 + std.crypto.hash.sha2.Sha512.digest_length + 11,
        .max_version = .v1_2,
    },
    .{
        .scheme = .pkcs1_with_sha1,
        .min_modulus_bytes = 15 + std.crypto.hash.Sha1.digest_length + 11,
        .max_version = .v1_2,
    },
};

// signatureSchemesForCertificate returns the list of supported SignatureSchemes
// for a given certificate, based on the public key and the protocol version,
// and optionally filtered by its explicit SupportedSignatureAlgorithms.
//
// This function must be kept in sync with supportedSignatureAlgorithms.
fn signatureSchemesForCertificate(
    allocator: mem.Allocator,
    ver: ProtocolVersion,
    cert: *const CertificateChain,
) ![]SignatureScheme {
    const priv_key = cert.private_key.?;
    var sig_algs = blk: {
        switch (priv_key.public()) {
            .rsa => |pub_key| {
                const size = pub_key.size();
                var algs = try std.ArrayListUnmanaged(SignatureScheme).initCapacity(
                    allocator,
                    rsa_signature_schemes.len,
                );
                errdefer algs.deinit(allocator);
                for (rsa_signature_schemes) |*candidate| {
                    if (size >= candidate.min_modulus_bytes and
                        @enumToInt(ver) <= @enumToInt(candidate.max_version))
                    {
                        try algs.append(allocator, candidate.scheme);
                    }
                }
                break :blk algs.toOwnedSlice(allocator);
            },
            .ecdsa => |pub_key| {
                if (ver != .v1_3) {
                    break :blk try allocator.dupe(SignatureScheme, &[_]SignatureScheme{
                        .ecdsa_with_p256_and_sha256,
                        .ecdsa_with_p384_and_sha384,
                        .ecdsa_with_p521_and_sha512,
                        .ecdsa_with_sha1,
                    });
                }
                switch (pub_key) {
                    .secp256r1 => break :blk try allocator.dupe(
                        SignatureScheme,
                        &[_]SignatureScheme{.ecdsa_with_p256_and_sha256},
                    ),
                    .secp384r1 => break :blk try allocator.dupe(
                        SignatureScheme,
                        &[_]SignatureScheme{.ecdsa_with_p384_and_sha384},
                    ),
                    .secp521r1 => break :blk try allocator.dupe(
                        SignatureScheme,
                        &[_]SignatureScheme{.ecdsa_with_p521_and_sha512},
                    ),
                    .x25519 => return &[_]SignatureScheme{},
                }
            },
            .ed25519 => break :blk try allocator.dupe(
                SignatureScheme,
                &[_]SignatureScheme{.ed25519},
            ),
            else => @panic("not implmented yet"),
        }
    };
    if (cert.supported_signature_algorithms) |sup_algs| {
        defer allocator.free(sig_algs);
        var filtered_algs = try std.ArrayListUnmanaged(SignatureScheme).initCapacity(
            allocator,
            sig_algs.len,
        );
        errdefer filtered_algs.deinit(allocator);
        for (sig_algs) |alg| {
            if (isSupportedSignatureAlgorithm(alg, sup_algs)) {
                try filtered_algs.append(allocator, alg);
            }
        }
        return filtered_algs.toOwnedSlice(allocator);
    } else {
        return sig_algs;
    }
}

pub fn isSupportedSignatureAlgorithm(
    aig_alg: SignatureScheme,
    supported_algs: []const SignatureScheme,
) bool {
    return memx.containsScalar(SignatureScheme, supported_algs, aig_alg);
}
