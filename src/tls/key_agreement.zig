const std = @import("std");
const mem = std.mem;
const SignatureType = @import("auth.zig").SignatureType;
const HashType = @import("auth.zig").HashType;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const CurveId = @import("handshake_msg.zig").CurveId;
const ServerKeyExchangeMsg = @import("handshake_msg.zig").ServerKeyExchangeMsg;
const ClientKeyExchangeMsg = @import("handshake_msg.zig").ClientKeyExchangeMsg;
const EcdheParameters = @import("key_schedule.zig").EcdheParameters;
const BytesView = @import("../BytesView.zig");
const x509 = @import("x509.zig");
const selectSignatureScheme = @import("auth.zig").selectSignatureScheme;
const crypto = @import("crypto.zig");
const SignOpts = @import("crypto.zig").SignOpts;

pub const KeyAgreement = union(enum) {
    rsa: RsaKeyAgreement,
    ecdhe: EcdheKeyAgreement,

    pub fn deinit(self: *KeyAgreement, allocator: mem.Allocator) void {
        switch (self.*) {
            .rsa => @panic("not imeplmented yet"),
            .ecdhe => |*ka| ka.deinit(allocator),
        }
    }

    pub fn generateServerKeyExchange(
        self: *KeyAgreement,
        allocator: mem.Allocator,
        cert_chain: *const CertificateChain,
        client_hello: *const ClientHelloMsg,
        server_hello: *const ServerHelloMsg,
    ) !ServerKeyExchangeMsg {
        switch (self.*) {
            .rsa => @panic("not imeplmented yet"),
            .ecdhe => |*ka| return try ka.generateServerKeyExchange(
                allocator,
                cert_chain,
                client_hello,
                server_hello,
            ),
        }
    }

    pub fn processServerKeyExchange(
        self: *KeyAgreement,
        allocator: mem.Allocator,
        client_hello: *const ClientHelloMsg,
        server_hello: *const ServerHelloMsg,
        cert: *const x509.Certificate,
        skx: *const ServerKeyExchangeMsg,
    ) !void {
        switch (self.*) {
            .rsa => @panic("not imeplmented yet"),
            .ecdhe => |*ka| return try ka.processServerKeyExchange(
                allocator,
                client_hello,
                server_hello,
                cert,
                skx,
            ),
        }
    }

    pub fn generateClientKeyExchange(
        self: *KeyAgreement,
        allocator: mem.Allocator,
        client_hello: *const ClientHelloMsg,
        cert: *const x509.Certificate,
        out_pre_master_secret: *[]const u8,
        out_ckx: *ClientKeyExchangeMsg,
    ) !void {
        switch (self.*) {
            .rsa => @panic("not imeplmented yet"),
            .ecdhe => |*ka| return try ka.generateClientKeyExchange(
                allocator,
                client_hello,
                cert,
                out_pre_master_secret,
                out_ckx,
            ),
        }
    }

    pub fn processClientKeyExchange(
        self: *KeyAgreement,
        allocator: mem.Allocator,
        cert_chain: *const CertificateChain,
        ckx: *const ClientKeyExchangeMsg,
        version: ProtocolVersion,
    ) ![]const u8 {
        switch (self.*) {
            .rsa => @panic("not imeplmented yet"),
            .ecdhe => |*ka| return try ka.processClientKeyExchange(
                allocator,
                cert_chain,
                ckx,
                version,
            ),
        }
    }
};

pub const RsaKeyAgreement = struct {};

pub const EcdheKeyAgreement = struct {
    is_rsa: bool,
    version: ProtocolVersion,
    params: ?EcdheParameters = null,

    // ckx and pre_master_secret are generated in processServerKeyExchange
    // and returned in generateClientKeyExchange.
    ckx: ?ClientKeyExchangeMsg = null,
    pre_master_secret: ?[]const u8 = null,

    pub fn deinit(self: *EcdheKeyAgreement, allocator: mem.Allocator) void {
        if (self.ckx) |*ckx| ckx.deinit(allocator);
        if (self.pre_master_secret) |s| allocator.free(s);
        if (self.params) |*p| p.deinit(allocator);
    }

    pub fn generateServerKeyExchange(
        self: *EcdheKeyAgreement,
        allocator: mem.Allocator,
        cert_chain: *const CertificateChain,
        client_hello: *const ClientHelloMsg,
        server_hello: *const ServerHelloMsg,
    ) !ServerKeyExchangeMsg {
        const curve_id = CurveId.x25519;

        const params = try EcdheParameters.generate(allocator, curve_id, std.crypto.random.*);
        self.params = params;

        // See RFC 4492, Section 5.4.
        const ecdhe_public = params.publicKey();
        var server_ecdhe_params = try allocator.alloc(u8, 1 + 2 + 1 + ecdhe_public.len);
        defer allocator.free(server_ecdhe_params);
        server_ecdhe_params[0] = 3; // named curve
        server_ecdhe_params[1] = @intCast(u8, @enumToInt(curve_id) >> 8);
        server_ecdhe_params[2] = @truncate(u8, @enumToInt(curve_id));
        server_ecdhe_params[3] = @intCast(u8, ecdhe_public.len);
        mem.copy(u8, server_ecdhe_params[4..], ecdhe_public);

        const sig_alg = try selectSignatureScheme(
            allocator,
            self.version,
            cert_chain,
            client_hello.supported_signature_algorithms,
        );
        var sig_type: SignatureType = undefined;
        var sig_hash_type: HashType = undefined;
        const v1_2_or_later = @enumToInt(self.version) >= @enumToInt(ProtocolVersion.v1_2);
        if (v1_2_or_later) {
            sig_type = try SignatureType.fromSinatureScheme(sig_alg);
            sig_hash_type = try HashType.fromSinatureScheme(sig_alg);
        } else {
            // TODO: implement
        }

        const signed = try hashForServerKeyExchange(
            allocator,
            sig_type,
            sig_hash_type,
            self.version,
            &.{
                client_hello.random,
                server_hello.random,
                server_ecdhe_params,
            },
        );
        defer allocator.free(signed);

        const private_key = cert_chain.private_key.?;
        var sign_opts = SignOpts{ .hash_type = sig_hash_type };
        var sig = try private_key.sign(allocator, signed, sign_opts);
        defer allocator.free(sig);

        const sig_and_hash_len: usize = if (v1_2_or_later) 2 else 0;
        var key = try allocator.alloc(u8, server_ecdhe_params.len + sig_and_hash_len + 2 + sig.len);
        mem.copy(u8, key, server_ecdhe_params);

        var k = key[server_ecdhe_params.len..];
        if (v1_2_or_later) {
            k[0] = @intCast(u8, @enumToInt(sig_alg) >> 8);
            k[1] = @truncate(u8, @enumToInt(sig_alg));
            k = k[2..];
        }
        k[0] = @intCast(u8, sig.len >> 8);
        k[1] = @truncate(u8, sig.len);
        mem.copy(u8, k[2..], sig);
        return ServerKeyExchangeMsg{ .key = key };
    }

    pub fn processServerKeyExchange(
        self: *EcdheKeyAgreement,
        allocator: mem.Allocator,
        client_hello: *const ClientHelloMsg,
        server_hello: *const ServerHelloMsg,
        cert: *const x509.Certificate,
        skx: *const ServerKeyExchangeMsg,
    ) !void {
        if (skx.key.len < 4) {
            return error.InvalidServerKeyExchangeMessage;
        }
        if (skx.key[0] != 3) { // named curve
            return error.UnsupportedCurve;
        }
        var bv = BytesView.init(skx.key[1..]);
        const curve_id = try bv.readEnum(CurveId, .Big);
        const public_len = @as(usize, try bv.readByte());
        if (public_len + 4 > skx.key.len) {
            return error.InvalidServerKeyExchangeMessage;
        }
        const server_ecdhe_params = skx.key[0 .. 4 + public_len];
        const public_key = server_ecdhe_params[4..];
        const sig = skx.key[4 + public_len ..];
        if (sig.len < 2) {
            return error.InvalidServerKeyExchangeMessage;
        }

        // TODO: implement check curve_id is supported curve

        std.log.debug("processServerKeyExchange curve_id={}", .{curve_id});
        const params = try EcdheParameters.generate(allocator, curve_id, std.crypto.random.*);
        self.params = params;

        self.pre_master_secret = try params.sharedKey(allocator, public_key);

        const our_public_key = params.publicKey();
        var ciphertext = try allocator.alloc(u8, 1 + our_public_key.len);
        ciphertext[0] = @intCast(u8, our_public_key.len);
        mem.copy(u8, ciphertext[1..], our_public_key);
        self.ckx = ClientKeyExchangeMsg{ .ciphertext = ciphertext };

        // TODO: implement
        _ = cert;
        _ = client_hello;
        _ = server_hello;
    }

    // The generated result can be obtained from self.pre_master_secret and
    // self.ckx.
    pub fn generateClientKeyExchange(
        self: *EcdheKeyAgreement,
        allocator: mem.Allocator,
        client_hello: *const ClientHelloMsg,
        cert: *const x509.Certificate,
        out_pre_master_secret: *[]const u8,
        out_ckx: *ClientKeyExchangeMsg,
    ) !void {
        _ = allocator;
        _ = client_hello;
        _ = cert;

        if (self.ckx) |ckx| {
            out_pre_master_secret.* = self.pre_master_secret.?;
            self.pre_master_secret = null;

            out_ckx.* = ckx;
            self.ckx = null;
        } else {
            return error.MissingServerKeyExchange;
        }
    }

    pub fn processClientKeyExchange(
        self: *EcdheKeyAgreement,
        allocator: mem.Allocator,
        cert_chain: *const CertificateChain,
        ckx: *const ClientKeyExchangeMsg,
        version: ProtocolVersion,
    ) ![]const u8 {
        _ = cert_chain;
        _ = version;
        if (ckx.ciphertext.len == 0 or ckx.ciphertext[0] != ckx.ciphertext.len - 1) {
            return error.InvalidClientKeyExchangeMessage;
        }
        return try self.params.?.sharedKey(allocator, ckx.ciphertext[1..]);
    }
};

// hashForServerKeyExchange hashes the given slices and returns their digest
// using the given hash function (for >= TLS 1.2) or using a default based on
// the sig_type (for earlier TLS versions). For Ed25519 signatures, which don't
// do pre-hashing, it returns the concatenation of the slices.
fn hashForServerKeyExchange(
    allocator: mem.Allocator,
    sig_type: SignatureType,
    sig_hash_type: HashType,
    version: ProtocolVersion,
    slices: []const []const u8,
) ![]const u8 {
    if (sig_type == .ed25519) {
        var signed_len: usize = 0;
        for (slices) |s| {
            signed_len += s.len;
        }
        var signed = try allocator.alloc(u8, signed_len);
        var pos: usize = 0;
        for (slices) |s| {
            mem.copy(u8, signed[pos..], s);
            pos += s.len;
        }
        return signed;
    }
    if (@enumToInt(version) >= @enumToInt(ProtocolVersion.v1_2)) {
        var h = crypto.Hash.init(sig_hash_type);
        for (slices) |s| {
            h.update(s);
        }
        return try h.allocFinal(allocator);
        // switch (sig_hash_type) {
        //     .sha1 => {
        //         var h = std.crypto.hash.Sha1.init(.{});
        //         for (slices) |s| {
        //             h.update(s);
        //         }
        //         var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        //         h.final(&digest);
        //         return try allocator.dupe(u8, &digest);
        //     },
        //     .sha256 => {
        //         var h = std.crypto.hash.sha2.Sha256.init(.{});
        //         for (slices) |s| {
        //             h.update(s);
        //         }
        //         var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        //         h.final(&digest);
        //         return try allocator.dupe(u8, &digest);
        //     },
        //     .sha384 => {
        //         var h = std.crypto.hash.sha2.Sha384.init(.{});
        //         for (slices) |s| {
        //             h.update(s);
        //         }
        //         var digest: [std.crypto.hash.sha2.Sha384.digest_length]u8 = undefined;
        //         h.final(&digest);
        //         return try allocator.dupe(u8, &digest);
        //     },
        //     .sha512 => {
        //         var h = std.crypto.hash.sha2.Sha512.init(.{});
        //         for (slices) |s| {
        //             h.update(s);
        //         }
        //         var digest: [std.crypto.hash.sha2.Sha512.digest_length]u8 = undefined;
        //         h.final(&digest);
        //         return try allocator.dupe(u8, &digest);
        //     },
        //     else => unreachable,
        // }
    }
    _ = sig_hash_type;
    _ = version;
    @panic("not implemented");
}
