const std = @import("std");
const mem = std.mem;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const crypto = @import("crypto.zig");
const ecdsa = @import("ecdsa.zig");
const rsa = @import("rsa.zig");
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
        .pkcs1v15 => {
            switch (public_key) {
                .rsa => |*pub_key| {
                    try rsa.verifyPkcs1v15(allocator, pub_key, sig_hash, signed, signature);
                },
                else => return error.ExpectedRsaPublicKey,
            }
        },
        .rsa_pss => {
            switch (public_key) {
                .rsa => |*pub_key| {
                    try rsa.verifyPss(
                        allocator,
                        pub_key,
                        sig_hash,
                        signed,
                        signature,
                        .equals_hash,
                    );
                },
                else => return error.ExpectedRsaPublicKey,
            }
        },
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

const signed_message_buf_len = signature_padding.len + server_signature_context.len +
    crypto.Hash.max_digest_length;
pub const SignedMessageBuf = std.BoundedArray(u8, signed_message_buf_len);

// signedMessage returns the pre-hashed (if necessary) message to be signed by
// certificate keys in TLS 1.3. See RFC 8446, Section 4.4.3.
pub fn signedMessageNoAlloc(
    sig_hash: HashType,
    context: []const u8,
    transcript: crypto.Hash,
    out_buf: *SignedMessageBuf,
) ![]const u8 {
    if (sig_hash == .direct_signing) {
        try out_buf.resize(signature_padding.len + context.len + transcript.digestLength());
        var out_slice = out_buf.slice();
        var fbs = std.io.fixedBufferStream(out_slice);
        var writer = fbs.writer();
        try writer.writeAll(&signature_padding);
        try writer.writeAll(context);
        _ = try transcript.writeFinal(writer);
        return out_slice;
    }

    var h = crypto.Hash.init(sig_hash);
    h.update(&signature_padding);
    h.update(context);
    switch (h) {
        .sha256 => |*h2| _ = try transcript.writeFinal(h2.writer()),
        .sha384 => |*h2| _ = try transcript.writeFinal(h2.writer()),
        else => @panic("invalid hash_type for TLS 1.3"),
    }
    out_buf.resize(sig_hash.digestLength()) catch unreachable;
    var out_slice = out_buf.slice();
    h.finalToSlice(out_slice);
    return out_slice;
}

pub fn signedMessageNoAlloc2(
    sig_hash: HashType,
    context: []const u8,
    transcript: crypto.Hash,
) !SignedMessageBuf {
    if (sig_hash == .direct_signing) {
        var out_buf = try SignedMessageBuf.init(signature_padding.len + context.len +
            transcript.digestLength());
        var fbs = std.io.fixedBufferStream(out_buf.slice());
        var writer = fbs.writer();
        try writer.writeAll(&signature_padding);
        try writer.writeAll(context);
        _ = try transcript.writeFinal(writer);
        return out_buf;
    }

    var h = crypto.Hash.init(sig_hash);
    h.update(&signature_padding);
    h.update(context);
    switch (h) {
        .sha256 => |*h2| _ = try transcript.writeFinal(h2.writer()),
        .sha384 => |*h2| _ = try transcript.writeFinal(h2.writer()),
        else => @panic("invalid hash_type for TLS 1.3"),
    }
    var out_buf = SignedMessageBuf.init(sig_hash.digestLength()) catch unreachable;
    h.finalToSlice(out_buf.slice());
    return out_buf;
}

const testing = std.testing;

test "signedMessageNoAlloc" {
    const test_cases = [_]struct {
        sig_hash: HashType,
        transcript: crypto.Hash,
        want: []const u8,
    }{
        .{
            .sig_hash = .direct_signing,
            .transcript = crypto.Hash.init(.sha256),
            .want = "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        },
        .{
            .sig_hash = .direct_signing,
            .transcript = crypto.Hash.init(.sha384),
            .want = "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b",
        },
        .{
            .sig_hash = .direct_signing,
            .transcript = crypto.Hash.init(.sha512),
            .want = "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e",
        },
        .{
            .sig_hash = .sha256,
            .transcript = crypto.Hash.init(.sha256),
            .want = "\x92\x2d\xff\x4b\x3f\xd9\x4f\x97\xf1\x85\x33\x61\x08\x40\xed\xdc\x20\xff\x77\x87\x39\x72\xcc\xa7\xac\xe1\x4b\xb8\x50\x9c\x09\x78",
        },
        .{
            .sig_hash = .sha384,
            .transcript = crypto.Hash.init(.sha256),
            .want = "\xe1\x13\xea\x7b\x46\xb1\xfc\xe4\xfe\x66\xae\xb5\x85\x78\x4d\xd2\xcd\xbd\x58\x60\x04\x07\xc0\x6a\x76\x75\x0f\xd5\xb4\x1b\x0f\x4f\x17\x9a\x46\x66\x02\x5a\x58\xc6\x74\x3b\x8e\x9c\x59\x1a\x74\x4d",
        },
    };
    for (test_cases) |c| {
        var signed_buf = SignedMessageBuf.init(0) catch unreachable;
        var got = try signedMessageNoAlloc(c.sig_hash, server_signature_context, c.transcript, &signed_buf);
        try testing.expectEqualSlices(u8, c.want, got);
    }
}

test "signedMessageNoAlloc2" {
    const test_cases = [_]struct {
        sig_hash: HashType,
        transcript: crypto.Hash,
        want: []const u8,
    }{
        .{
            .sig_hash = .direct_signing,
            .transcript = crypto.Hash.init(.sha256),
            .want = "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        },
        .{
            .sig_hash = .direct_signing,
            .transcript = crypto.Hash.init(.sha384),
            .want = "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b",
        },
        .{
            .sig_hash = .direct_signing,
            .transcript = crypto.Hash.init(.sha512),
            .want = "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54\x4c\x53\x20\x31\x2e\x33\x2c\x20\x73\x65\x72\x76\x65\x72\x20\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x56\x65\x72\x69\x66\x79\x00\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e",
        },
        .{
            .sig_hash = .sha256,
            .transcript = crypto.Hash.init(.sha256),
            .want = "\x92\x2d\xff\x4b\x3f\xd9\x4f\x97\xf1\x85\x33\x61\x08\x40\xed\xdc\x20\xff\x77\x87\x39\x72\xcc\xa7\xac\xe1\x4b\xb8\x50\x9c\x09\x78",
        },
        .{
            .sig_hash = .sha384,
            .transcript = crypto.Hash.init(.sha256),
            .want = "\xe1\x13\xea\x7b\x46\xb1\xfc\xe4\xfe\x66\xae\xb5\x85\x78\x4d\xd2\xcd\xbd\x58\x60\x04\x07\xc0\x6a\x76\x75\x0f\xd5\xb4\x1b\x0f\x4f\x17\x9a\x46\x66\x02\x5a\x58\xc6\x74\x3b\x8e\x9c\x59\x1a\x74\x4d",
        },
    };
    for (test_cases) |c| {
        var got = try signedMessageNoAlloc2(c.sig_hash, server_signature_context, c.transcript);
        try testing.expectEqualSlices(u8, c.want, got.slice());
    }
}

// Signature algorithms (for internal signaling use). Starting at 225 to avoid overlap with
// TLS 1.2 codepoints (RFC 5246, Appendix A.4.1), with which these have nothing to do.
pub const SignatureType = enum(u8) {
    pkcs1v15 = 225,
    rsa_pss = 226,
    ecdsa = 227,
    ed25519 = 228,
    _,

    pub fn fromSignatureScheme(s: SignatureScheme) !SignatureType {
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

    pub fn fromSignatureScheme(s: SignatureScheme) !HashType {
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

    pub fn initDigestArray(hash_type: HashType) crypto.Hash.DigestArray {
        return crypto.Hash.DigestArray.init(hash_type.digestLength()) catch unreachable;
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
) ![]const SignatureScheme {
    std.debug.assert(cert.private_key != null);
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
    if (cert.supported_signature_algorithms.len > 0) {
        defer allocator.free(cert.supported_signature_algorithms);
        var filtered_algs = try std.ArrayListUnmanaged(SignatureScheme).initCapacity(
            allocator,
            cert.supported_signature_algorithms.len,
        );
        errdefer filtered_algs.deinit(allocator);
        for (sig_algs) |alg| {
            if (isSupportedSignatureAlgorithm(alg, cert.supported_signature_algorithms)) {
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
