const std = @import("std");
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const KeyAgreement = @import("key_agreement.zig").KeyAgreement;
const RsaKeyAgreement = @import("key_agreement.zig").RsaKeyAgreement;
const EcdheKeyAgreement = @import("key_agreement.zig").EcdheKeyAgreement;

pub const CipherSuite = union(ProtocolVersion) {
    v1_3: CipherSuite13,
    v1_2: CipherSuite12,
    v1_0: CipherSuite12,
};

pub const CipherSuite13 = struct {};

pub const CipherSuite12 = struct {
    pub const Flags = packed struct {
        ecdhe: bool = false,
        ec_sign: bool = false,
        tls12: bool = false,
        sha384: bool = false,
    };

    id: CipherSuiteId,
    // the lengths, in bytes, of the key material needed for each component.
    key_len: usize,
    mac_len: usize,
    iv_len: usize,

    flags: Flags = .{},
    ka: fn (version: ProtocolVersion) KeyAgreement,
};

pub const cipher_suites12 = [_]CipherSuite12{
    .{
        .id = .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 12,
        .flags = .{ .ecdhe = true, .tls12 = true },
        .ka = ecdheRsaKa,
    },
    .{
        .id = .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .key_len = 16,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .tls12 = true },
        .ka = ecdheRsaKa,
    },
    .{
        .id = .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .ec_sign = true, .tls12 = true, .sha384 = true },
        .ka = ecdheEcdsaKa,
    },
};

fn rsaKa(_: ProtocolVersion) KeyAgreement {
    return .{ .rsa = RsaKeyAgreement{} };
}

fn ecdheEcdsaKa(version: ProtocolVersion) KeyAgreement {
    return .{ .ecdhe = EcdheKeyAgreement{ .is_rsa = false, .version = version } };
}

fn ecdheRsaKa(version: ProtocolVersion) KeyAgreement {
    return .{ .ecdhe = EcdheKeyAgreement{ .is_rsa = true, .version = version } };
}

pub fn mutualCipherSuite12(have: []const CipherSuiteId, want: CipherSuiteId) ?*const CipherSuite12 {
    for (have) |id| {
        if (id == want) {
            return cipherSuite12ById(id);
        }
    }
    return null;
}

pub fn cipherSuite12ById(id: CipherSuiteId) ?*const CipherSuite12 {
    for (cipher_suites12) |*suite| {
        if (suite.id == id) {
            return suite;
        }
    }
    return null;
}

const testing = std.testing;

test "mutualCipherSuite12" {
    const have = [_]CipherSuiteId{
        .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    };

    try testing.expectEqual(
        @as(?*const CipherSuite12, &cipher_suites12[2]),
        mutualCipherSuite12(&have, .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    );

    try testing.expectEqual(
        @as(?*const CipherSuite12, null),
        mutualCipherSuite12(&have, .TLS_AES_128_GCM_SHA256),
    );
}
