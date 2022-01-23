const std = @import("std");
const mem = std.mem;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const crypto = @import("crypto.zig");
const memx = @import("../memx.zig");
const pem = @import("pem.zig");
const x509 = @import("x509.zig");

pub const CertificateChain = struct {
    certificate_chain: []const []const u8,
    // PrivateKey contains the private key corresponding to the public key in
    // Leaf. This must implement crypto.Signer with an RSA, ECDSA or Ed25519 PublicKey.
    // For a server up to TLS 1.2, it can also implement crypto.Decrypter with
    // an RSA PublicKey.
    private_key: ?crypto.PrivateKey = null,
    // SupportedSignatureAlgorithms is an optional list restricting what
    // signature algorithms the PrivateKey can be used for.
    supported_signature_algorithms: ?[]const SignatureScheme = null,
    // OCSPStaple contains an optional OCSP response which will be served
    // to clients that request it.
    ocsp_staple: ?[]const u8 = null,
    // SignedCertificateTimestamps contains an optional list of Signed
    // Certificate Timestamps which will be served to clients that request it.
    signed_certificate_timestamps: ?[]const []const u8 = null,
    // Leaf is the parsed form of the leaf certificate, which may be initialized
    // using x509.ParseCertificate to reduce per-handshake processing. If nil,
    // the leaf certificate will be parsed as needed.
    leaf: ?*x509.Certificate = null,

    pub fn deinit(self: *CertificateChain, allocator: mem.Allocator) void {
        for (self.certificate_chain) |cert| {
            allocator.free(cert);
        }
        allocator.free(self.certificate_chain);
        if (self.private_key) |*key| {
            key.deinit(allocator);
        }
        if (self.leaf) |leaf| {
            leaf.deinit(allocator);
        }
    }
};

// x509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be nil because
// the parsed form of the certificate is not retained.
pub fn x509KeyPair(
    allocator: mem.Allocator,
    cert_pem_block: []const u8,
    key_pem_block: []const u8,
) !CertificateChain {
    var certificate_chain = std.ArrayListUnmanaged([]const u8){};
    errdefer {
        for (certificate_chain.items) |cert| {
            allocator.free(cert);
        }
        allocator.free(certificate_chain.items);
    }

    var offset: usize = 0;
    while (offset < cert_pem_block.len) {
        var cert_der_block = try pem.Block.decode(allocator, cert_pem_block, &offset);
        errdefer cert_der_block.deinit(allocator);
        if (mem.eql(u8, cert_der_block.label, pem.Block.certificate_label)) {
            try certificate_chain.append(allocator, cert_der_block.bytes);
            allocator.free(cert_der_block.label);
        } else {
            return error.NotCertificate;
        }
    }
    if (certificate_chain.items.len == 0) {
        return error.NoCertificate;
    }

    offset = 0;
    var key_der_block = try pem.Block.decode(allocator, key_pem_block, &offset);
    defer key_der_block.deinit(allocator);
    if (!mem.eql(u8, key_der_block.label, pem.Block.private_key_label) and
        !mem.endsWith(u8, key_der_block.label, pem.Block.private_key_label_suffix))
    {
        return error.NotPrivateKey;
    }

    // We don't need to parse the public key for TLS, but we so do anyway
    // to check that it looks sane and matches the private key.

    // TODO: implement

    const private_key = try crypto.PrivateKey.parse(allocator, key_der_block.bytes);

    // TODO: implement

    return CertificateChain{
        .certificate_chain = certificate_chain.toOwnedSlice(allocator),
        .private_key = private_key,
    };
}

const testing = std.testing;

test "x509KeyPair" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    const cert_pem = @embedFile("../../tests/rsa2048.crt.pem");
    const key_pem = @embedFile("../../tests/rsa2048.key.pem");
    var cert_chain = try x509KeyPair(allocator, cert_pem, key_pem);
    defer cert_chain.deinit(allocator);
    std.log.debug("cert_chain={}", .{cert_chain});
}
