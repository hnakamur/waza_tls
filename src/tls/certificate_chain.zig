const std = @import("std");
const mem = std.mem;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const ExtensionType = @import("handshake_msg.zig").ExtensionType;
const status_type_ocsp = @import("handshake_msg.zig").status_type_ocsp;
const u24_size = @import("handshake_msg.zig").u24_size;
const u16_size = @import("handshake_msg.zig").u16_size;
const u8_size = @import("handshake_msg.zig").u8_size;
const writeInt = @import("handshake_msg.zig").writeInt;
const writeBytes = @import("handshake_msg.zig").writeBytes;
const crypto = @import("crypto.zig");
const BytesView = @import("../BytesView.zig");
const memx = @import("../memx.zig");
const pem = @import("pem.zig");
const x509 = @import("x509.zig");

pub const CertificateChain = struct {
    certificate_chain: []const []const u8 = &.{},
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
    ocsp_staple: []const u8 = "",
    // SignedCertificateTimestamps contains an optional list of Signed
    // Certificate Timestamps which will be served to clients that request it.
    signed_certificate_timestamps: ?[]const []const u8 = null,
    // Leaf is the parsed form of the leaf certificate, which may be initialized
    // using x509.ParseCertificate to reduce per-handshake processing. If nil,
    // the leaf certificate will be parsed as needed.
    leaf: ?*x509.Certificate = null,

    pub fn deinit(self: *CertificateChain, allocator: mem.Allocator) void {
        if (self.certificate_chain.len > 0) {
            for (self.certificate_chain) |cert| allocator.free(cert);
            allocator.free(self.certificate_chain);
        }
        if (self.private_key) |*key| {
            key.deinit(allocator);
        }
        if (self.ocsp_staple.len > 0) allocator.free(self.ocsp_staple);
        if (self.signed_certificate_timestamps) |scts| {
            for (scts) |sct| allocator.free(sct);
            allocator.free(scts);
        }
        if (self.leaf) |leaf| {
            leaf.deinit(allocator);
        }
    }

    pub fn unmarshal(
        allocator: mem.Allocator,
        data: []const u8,
    ) !CertificateChain {
        var bv = BytesView.init(data);
        var certificates_len = try bv.readIntBig(u24);
        try bv.ensureRestLen(certificates_len);
        const certificates_end_pos = bv.pos + certificates_len;
        var certificates = std.ArrayListUnmanaged([]const u8){};
        errdefer {
            for (certificates.items) |cert| allocator.free(cert);
            certificates.deinit(allocator);
        }
        var ocsp_staple: []const u8 = "";
        errdefer if (ocsp_staple.len > 0) allocator.free(ocsp_staple);
        var scts = std.ArrayListUnmanaged([]const u8){};
        errdefer {
            for (scts.items) |sct| allocator.free(sct);
            scts.deinit(allocator);
        }
        while (bv.pos < certificates_end_pos) {
            {
                const cert = try allocator.dupe(u8, try bv.readLenPrefixedBytes(u24, .Big));
                errdefer allocator.free(cert);
                try certificates.append(allocator, cert);
            }
            const extensions_len = try bv.readIntBig(u16);
            const extensions_end_pos = bv.pos + extensions_len;
            while (bv.pos < extensions_end_pos) {
                const ext_type = try bv.readEnum(ExtensionType, .Big);
                const ext_len = try bv.readIntBig(u16);
                switch (ext_type) {
                    .StatusRequest => {
                        const status_type = try bv.readByte();
                        if (status_type != status_type_ocsp) {
                            return error.InvalidCertificateMsgTls12;
                        }
                        ocsp_staple = try allocator.dupe(
                            u8,
                            try bv.readLenPrefixedBytes(u24, .Big),
                        );
                    },
                    .Sct => {
                        const scts_len = try bv.readIntBig(u16);
                        const scts_end_pos = bv.pos + scts_len;
                        while (bv.pos < scts_end_pos) {
                            const sct = try allocator.dupe(
                                u8,
                                try bv.readLenPrefixedBytes(u16, .Big),
                            );
                            errdefer allocator.free(sct);
                            try scts.append(allocator, sct);
                        }
                    },
                    else => bv.skip(ext_len),
                }
            }
        }

        return CertificateChain{
            .certificate_chain = certificates.toOwnedSlice(allocator),
            .ocsp_staple = ocsp_staple,
            .signed_certificate_timestamps = scts.toOwnedSlice(allocator),
        };
    }

    pub fn marshaledLen(self: *const CertificateChain) usize {
        var total_len: usize = u24_size;
        for (self.certificate_chain) |cert, i| {
            total_len += u24_size + cert.len + u16_size;
            if (i == 0) {
                total_len += self.ocspStaplingMarshaledLen() + self.sctsMarshaledLen();
            }
        }
        return total_len;
    }

    pub fn ocspStaplingMarshaledLen(self: *const CertificateChain) usize {
        return if (self.ocsp_staple.len > 0)
            u16_size * 2 + u8_size + u24_size + self.ocsp_staple.len
        else
            0;
    }

    pub fn sctsMarshaledLen(self: *const CertificateChain) usize {
        var scts_marshaled_len: usize = 0;
        if (self.signed_certificate_timestamps) |scts| {
            scts_marshaled_len = u16_size * 3;
            for (scts) |sct| {
                scts_marshaled_len += u16_size + sct.len;
            }
        }
        return scts_marshaled_len;
    }

    pub fn writeTo(self: *const CertificateChain, writer: anytype) !void {
        try writeInt(u24, self.marshaledLen() - u24_size, writer);
        for (self.certificate_chain) |cert, i| {
            try writeInt(u24, cert.len, writer);
            try writeBytes(cert, writer);
            const oscp_stapling_len = if (i == 0) self.ocspStaplingMarshaledLen() else 0;
            const scts_len = if (i == 0) self.sctsMarshaledLen() else 0;
            const ext_len = if (i == 0) oscp_stapling_len + scts_len else 0;
            try writeInt(u16, ext_len, writer);
            // This library only supports OCSP and SCT for leaf certificates.
            if (i == 0) {
                if (self.ocsp_staple.len > 0) {
                    try writeInt(u16, ExtensionType.StatusRequest, writer);
                    try writeInt(u16, oscp_stapling_len - u16_size * 2, writer);
                    try writeInt(u8, status_type_ocsp, writer);
                    try writeInt(u24, self.ocsp_staple.len, writer);
                    try writeBytes(self.ocsp_staple, writer);
                }
                if (self.signed_certificate_timestamps != null) {
                    if (self.signed_certificate_timestamps) |scts| {
                        try writeInt(u16, ExtensionType.Sct, writer);
                        var rest_len = scts_len - u16_size * 2;
                        try writeInt(u16, rest_len, writer);
                        rest_len -= u16_size;
                        try writeInt(u16, rest_len, writer);
                        for (scts) |sct| {
                            try writeInt(u16, sct.len, writer);
                            try writeBytes(sct, writer);
                        }
                    }
                }
            }
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
    testing.log_level = .err;
    const allocator = testing.allocator;
    const cert_pem = @embedFile("../../tests/rsa2048.crt.pem");
    const key_pem = @embedFile("../../tests/rsa2048.key.pem");
    var cert_chain = try x509KeyPair(allocator, cert_pem, key_pem);
    defer cert_chain.deinit(allocator);
    std.log.debug("cert_chain={}", .{cert_chain});
}
