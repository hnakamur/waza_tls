const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const mem = std.mem;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const KeyAgreement = @import("key_agreement.zig").KeyAgreement;
const RsaKeyAgreement = @import("key_agreement.zig").RsaKeyAgreement;
const EcdheKeyAgreement = @import("key_agreement.zig").EcdheKeyAgreement;
const HashType = @import("auth.zig").HashType;
const crypto = @import("crypto.zig");
const hkdf = @import("hkdf.zig");
const memx = @import("../memx.zig");

// Keep in sync with Zig standard library lib/std/crypto/aes.zig
const has_aesni = std.Target.x86.featureSetHas(builtin.cpu.features, .aes);
const has_avx = std.Target.x86.featureSetHas(builtin.cpu.features, .avx);
const has_armaes = std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes);

pub const has_aes_gcm_hardware_support =
    (builtin.cpu.arch == .x86_64 and has_aesni and has_avx) or
    (builtin.cpu.arch == .aarch64 and has_armaes);

pub const aes_gcm_ciphers = [_]CipherSuiteId{
    // TLS 1.2
    .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
    .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
    .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    // TLS 1.3
    .tls_aes_128_gcm_sha256,
    .tls_aes_256_gcm_sha384,
};

pub const non_aes_gcm_ciphers = [_]CipherSuiteId{
    // TLS 1.2
    .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
    .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    // TLS 1.3
    .tls_chacha20_poly1305_sha256,
};

// aesgcmPreferred returns whether the first known cipher in the preference list
// is an AES-GCM cipher, implying the peer has hardware support for it.
pub fn aesgcmPreferred(ciphers: []const CipherSuiteId) bool {
    for (ciphers) |cipher_id| {
        if (cipherSuiteTls12ById(cipher_id)) |_| {
            return true;
        }
        if (cipherSuiteTls13ById(cipher_id)) |_| {
            return true;
        }
    }
    return false;
}

pub const CipherSuite = union(ProtocolVersion) {
    v1_3: CipherSuiteTls13,
    v1_2: CipherSuiteTls12,
    v1_1: void,
    v1_0: void,
};

// A cipherSuiteTLS13 defines only the pair of the AEAD algorithm and hash
// algorithm to be used with HKDF. See RFC 8446, Appendix B.4.
pub const CipherSuiteTls13 = struct {
    id: CipherSuiteId,
    key_len: usize,
    aead: fn (key: []const u8, fixed_nonce: []const u8) Aead,
    hash_type: HashType,

    // expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
    fn expandLabel(
        self: *const CipherSuiteTls13,
        allocator: mem.Allocator,
        secret: []const u8,
        label: []const u8,
        context: []const u8,
        length: u16,
    ) ![]const u8 {
        _ = self;
        std.log.debug("expandLabel start, secret={}, label={s}, context={}, length={}", .{
            std.fmt.fmtSliceHexLower(secret),
            label,
            std.fmt.fmtSliceHexLower(context),
            length,
        });
        const tls13_prefix_label = "tls13 ";
        const tls13_and_label_len = tls13_prefix_label.len + label.len;
        const capacity = @sizeOf(u16) + @sizeOf(u8) + tls13_and_label_len +
            @sizeOf(u8) + context.len;

        var hkdf_label = blk: {
            var buf = try std.ArrayListUnmanaged(u8).initCapacity(allocator, capacity);
            errdefer buf.deinit(allocator);
            var writer = buf.writer(allocator);
            try writer.writeIntBig(u16, length);
            try writer.writeIntBig(u8, @intCast(u8, tls13_and_label_len));
            try writer.writeAll(tls13_prefix_label);
            try writer.writeAll(label);
            try writer.writeIntBig(u8, @intCast(u8, context.len));
            try writer.writeAll(context);
            break :blk buf.toOwnedSlice(allocator);
        };
        defer allocator.free(hkdf_label);

        var got_err: bool = false;
        var n: usize = undefined;
        var out = try allocator.alloc(u8, length);
        errdefer allocator.free(out);
        switch (self.hash_type) {
            .sha256 => {
                var hdkf_reader = hkdf.Hkdf(std.crypto.hash.sha2.Sha256).expand(secret, hkdf_label);
                if (hdkf_reader.read(out)) |n2| {
                    n = n2;
                } else |_| {
                    got_err = true;
                }
            },
            .sha384 => {
                var hdkf_reader = hkdf.Hkdf(std.crypto.hash.sha2.Sha384).expand(secret, hkdf_label);
                if (hdkf_reader.read(out)) |n2| {
                    n = n2;
                } else |_| {
                    got_err = true;
                }
            },
            else => @panic("unsupported hash_type"),
        }
        if (got_err or n != length) {
            @panic("tls: HKDF-Expand-Label invocation failed unexpectedly");
        }
        return out;
    }

    // deriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
    pub fn deriveSecret(
        self: *const CipherSuiteTls13,
        allocator: mem.Allocator,
        secret: []const u8,
        label: []const u8,
        transcript: ?crypto.Hash,
    ) ![]const u8 {
        var ts = transcript orelse crypto.Hash.init(self.hash_type);
        var context = try ts.allocFinal(allocator);
        defer allocator.free(context);
        return self.expandLabel(allocator, secret, label, context, self.hash_type.digestLength());
    }

    // extract implements HKDF-Extract with the cipher suite hash.
    pub fn extract(
        self: *const CipherSuiteTls13,
        allocator: mem.Allocator,
        new_secret: ?[]const u8,
        current_secret: ?[]const u8,
    ) ![]const u8 {
        var new_secret2 = new_secret orelse blk: {
            var s = try allocator.alloc(u8, self.hash_type.digestLength());
            mem.set(u8, s, 0);
            break :blk s;
        };
        defer if (new_secret == null) allocator.free(new_secret2);

        return try hkdf.extract(self.hash_type, allocator, new_secret2, current_secret);
    }

    // trafficKey generates traffic keys according to RFC 8446, Section 7.3.
    pub fn trafficKey(
        self: *const CipherSuiteTls13,
        allocator: mem.Allocator,
        traffic_secret: []const u8,
        key_out: *[]const u8,
        iv_out: *[]const u8,
    ) !void {
        key_out.* = self.expandLabel(allocator, traffic_secret, "key", "", self.key_len);
        errdefer allocator.free(key_out.*);
        iv_out.* = self.expandLabel(allocator, traffic_secret, "iv", "", aead_nonce_length);
        errdefer allocator.free(iv_out.*);
    }
};

test "CipherSuiteTls13.expandLabel" {
    testing.log_level = .debug;
    const test_cases = [_]struct {
        secret: []const u8,
        label: []const u8,
        context: []const u8,
        length: u16,
        want: []const u8,
    }{
        .{
            .secret = "\x56\xbc\x08\x69\xe1\x4d\xd4\x00\xca\x53\x9f\x09\x04\x66\x62\xb8\x24\x63\x66\xf9\xfd\x41\xf4\x11\x80\xde\x07\xab\x5b\x50\x4c\x70",
            .label = "c hs traffic",
            .context = "\x41\x44\x4f\x05\x04\x2e\x45\x58\xd3\x9c\x02\x0a\xb3\x49\x33\x08\x79\x75\x4b\xf8\x7a\xab\x30\x88\x3b\xa3\x70\xee\x2f\xad\x31\x2b",
            .length = 32,
            .want = "\x82\x05\x2b\xb2\x02\x21\xf4\x1b\x89\x5b\xd6\xb4\x9f\xd1\x67\x9f\xe8\x38\xde\x55\xc8\xab\x3f\x9c\x17\xc4\x50\x56\x15\xe9\x7b\x61",
        },
        .{
            .secret = "\x82\x05\x2b\xb2\x02\x21\xf4\x1b\x89\x5b\xd6\xb4\x9f\xd1\x67\x9f\xe8\x38\xde\x55\xc8\xab\x3f\x9c\x17\xc4\x50\x56\x15\xe9\x7b\x61",
            .label = "key",
            .context = "",
            .length = 16,
            .want = "\xf2\x11\x66\xd1\xdd\xc5\x11\x45\x64\x7a\x8b\xed\x90\x65\x83\xdb",
        },
        .{
            .secret = "\x82\x05\x2b\xb2\x02\x21\xf4\x1b\x89\x5b\xd6\xb4\x9f\xd1\x67\x9f\xe8\x38\xde\x55\xc8\xab\x3f\x9c\x17\xc4\x50\x56\x15\xe9\x7b\x61",
            .label = "iv",
            .context = "",
            .length = 12,
            .want = "\xd3\xef\x7f\x99\x93\x16\xd5\xdb\x7e\xdd\x3a\xab",
        },
    };
    for (test_cases) |c| {
        const allocator = testing.allocator;
        var suite = cipherSuiteTls13ById(.tls_aes_128_gcm_sha256).?;
        var got = try suite.expandLabel(allocator, c.secret, c.label, c.context, c.length);
        defer allocator.free(got);
        try testing.expectEqualSlices(u8, c.want, got);
    }
}

test "CipherSuiteTls13.extract" {
    testing.log_level = .debug;
    const f = struct {
        fn f(
            new_secret: ?[]const u8,
            current_secret: ?[]const u8,
            want: []const u8,
        ) !void {
            const allocator = testing.allocator;
            var suite = cipherSuiteTls13ById(.tls_aes_128_gcm_sha256).?;
            var got = try suite.extract(allocator, new_secret, current_secret);
            defer allocator.free(got);
            try testing.expectEqualSlices(u8, want, got);
        }
    }.f;

    try f(
        null,
        null,
        "\x33\xad\x0a\x1c\x60\x7e\xc0\x3b\x09\xe6\xcd\x98\x93\x68\x0c\xe2\x10\xad\xf3\x00\xaa\x1f\x26\x60\xe1\xb2\x2e\x10\xf1\x70\xf9\x2a",
    );
    try f(
        "\x0b\x03\x4d\x80\x1b\x3d\x39\x9c\xbc\xb6\x10\x78\x44\xb0\xf9\x1e\xff\x99\x8b\x64\xa3\x39\xcb\x21\x72\x43\x74\x26\x93\x47\x92\x38",
        "\x6f\x26\x15\xa1\x08\xc7\x02\xc5\x67\x8f\x54\xfc\x9d\xba\xb6\x97\x16\xc0\x76\x18\x9c\x48\x25\x0c\xeb\xea\xc3\x57\x6c\x36\x11\xba",
        "\x57\x55\x23\xbb\xcc\x5b\x2c\x05\xc4\x14\x7b\xe6\x4f\x5d\x4a\xbe\x49\x8b\xd5\x3a\x96\xa4\xfb\xa1\xad\xfd\x47\x58\x53\x48\xf4\xc1",
    );
    try f(
        null,
        "\xb6\x00\xae\x09\x4c\x43\x9d\xcd\x01\xb1\xff\x96\x58\x85\x6d\xe8\x72\x4e\x3f\x45\xc0\x66\x56\xe8\xe3\xdd\x20\x87\xf4\x98\x7d\xf8",
        "\xe2\x68\x30\xf9\xc9\xef\x5a\x62\x60\x09\xac\xa2\xec\x93\x38\xdc\xa9\x37\xa1\xca\xdb\x70\x65\x8f\x78\x4b\x29\xa9\x51\x9c\x8f\x9e",
    );
}

test "hmacsha256" {
    testing.log_level = .debug;
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var out: [HmacSha256.mac_length]u8 = undefined;
    const msg = &[_]u8{0} ** HmacSha256.mac_length;
    const key = &[_]u8{0} ** HmacSha256.mac_length;
    HmacSha256.create(&out, msg, key);
    const want = "\x33\xad\x0a\x1c\x60\x7e\xc0\x3b\x09\xe6\xcd\x98\x93\x68\x0c\xe2\x10\xad\xf3\x00\xaa\x1f\x26\x60\xe1\xb2\x2e\x10\xf1\x70\xf9\x2a";
    try testing.expectEqualSlices(u8, want, &out);
}

const cipher_suites_tls13 = [_]CipherSuiteTls13{
    .{
        .id = .tls_aes_128_gcm_sha256,
        .key_len = 16,
        .aead = Aead.initXorNonceAeadAes128Gcm,
        .hash_type = .sha256,
    },
    .{
        .id = .tls_chacha20_poly1305_sha256,
        .key_len = 32,
        .aead = Aead.initXorNonceAeadChaCha20Poly1305,
        .hash_type = .sha256,
    },
    .{
        .id = .tls_aes_256_gcm_sha384,
        .key_len = 32,
        .aead = Aead.initXorNonceAeadAes256Gcm,
        .hash_type = .sha384,
    },
};

pub fn mutualCipherSuiteTls13(
    have: []const CipherSuiteId,
    want: CipherSuiteId,
) ?*const CipherSuiteTls13 {
    return if (memx.containsScalar(CipherSuiteId, have, want)) cipherSuiteTls13ById(want) else null;
}

fn cipherSuiteTls13ById(id: CipherSuiteId) ?*const CipherSuiteTls13 {
    for (cipher_suites_tls13) |*suite| {
        if (suite.id == id) {
            return suite;
        }
    }
    return null;
}

// defaultCipherSuitesTLS13 is also the preference order, since there are no
// disabled by default TLS 1.3 cipher suites. The same AES vs ChaCha20 logic as
// cipherSuitesPreferenceOrder applies.
pub const default_cipher_suites_tls13 = [_]CipherSuiteId{
    .tls_aes_128_gcm_sha256,
    .tls_aes_256_gcm_sha384,
    .tls_chacha20_poly1305_sha256,
};

pub const default_cipher_suites_tls13_no_aes = [_]CipherSuiteId{
    .tls_chacha20_poly1305_sha256,
    .tls_aes_128_gcm_sha256,
    .tls_aes_256_gcm_sha384,
};

pub const CipherSuiteTls12 = struct {
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
    aead: ?fn (key: []const u8, nonce_prefix: []const u8) Aead,
};

pub const default_cipher_suites = cipher_suites_preference_order;

pub const cipher_suites_preference_order = [_]CipherSuiteId{
    .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
    .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
    .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
};

pub const cipher_suites_preference_order_no_aes = [_]CipherSuiteId{
    .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
    .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
    .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
    .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
};

pub const cipher_suites_tls12 = [_]CipherSuiteTls12{
    .{
        .id = .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 12,
        .flags = .{ .ecdhe = true, .tls12 = true },
        .ka = ecdheRsaKa,
        .aead = Aead.initXorNonceAeadChaCha20Poly1305,
    },
    .{
        .id = .tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 12,
        .flags = .{ .ecdhe = true, .ec_sign = true, .tls12 = true },
        .ka = ecdheEcdsaKa,
        .aead = Aead.initXorNonceAeadChaCha20Poly1305,
    },
    .{
        .id = .tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .key_len = 16,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .ec_sign = true, .tls12 = true },
        .ka = ecdheEcdsaKa,
        .aead = Aead.initPrefixNonceAeadAes128Gcm,
    },
    .{
        .id = .tls_ecdhe_rsa_with_aes_128_gcm_sha256,
        .key_len = 16,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .tls12 = true },
        .ka = ecdheRsaKa,
        .aead = Aead.initPrefixNonceAeadAes128Gcm,
    },
    .{
        .id = .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .ec_sign = true, .tls12 = true, .sha384 = true },
        .ka = ecdheEcdsaKa,
        .aead = Aead.initPrefixNonceAeadAes256Gcm,
    },
    .{
        .id = .tls_ecdhe_rsa_with_aes_256_gcm_sha384,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .tls12 = true, .sha384 = true },
        .ka = ecdheRsaKa,
        .aead = Aead.initPrefixNonceAeadAes256Gcm,
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

pub fn makeCipherPreferenceList(
    allocator: mem.Allocator,
    max_supported_version: ProtocolVersion,
    config_cipher_suites: []const CipherSuiteId,
) ![]const CipherSuiteId {
    var cipher_suites = try std.ArrayListUnmanaged(CipherSuiteId).initCapacity(
        allocator,
        config_cipher_suites.len,
    );
    errdefer cipher_suites.deinit(allocator);

    const preference_order = if (has_aes_gcm_hardware_support)
        &cipher_suites_preference_order
    else
        &cipher_suites_preference_order_no_aes;
    for (preference_order) |suite_id| {
        if (mutualCipherSuiteTls12(config_cipher_suites, suite_id)) |_| {
            try cipher_suites.append(allocator, suite_id);
        }
    }

    if (max_supported_version == .v1_3) {
        const suite_tls13 = if (has_aes_gcm_hardware_support)
            &default_cipher_suites_tls13
        else
            &default_cipher_suites_tls13_no_aes;
        try cipher_suites.appendSlice(allocator, suite_tls13);
    }

    return cipher_suites.toOwnedSlice(allocator);
}

pub fn mutualCipherSuiteTls12(
    have: []const CipherSuiteId,
    want: CipherSuiteId,
) ?*const CipherSuiteTls12 {
    return if (memx.containsScalar(CipherSuiteId, have, want)) cipherSuiteTls12ById(want) else null;
}

// selectCipherSuiteTls12 returns the first TLS 1.0–1.2 cipher suite from ids which
// is also in supportedIDs and passes the ok filter.
pub fn selectCipherSuiteTls12(
    ids: []const CipherSuiteId,
    supported_ids: []const CipherSuiteId,
    context: anytype,
    ok: fn (@TypeOf(context), *const CipherSuiteTls12) bool,
) ?*const CipherSuiteTls12 {
    for (ids) |id| {
        if (cipherSuiteTls12ById(id)) |candidate| {
            if (!ok(context, candidate)) {
                continue;
            }

            if (memx.containsScalar(CipherSuiteId, supported_ids, id)) {
                return candidate;
            }
        }
    }
    return null;
}

pub fn cipherSuiteTls12ById(id: CipherSuiteId) ?*const CipherSuiteTls12 {
    for (cipher_suites_tls12) |*suite| {
        if (suite.id == id) {
            return suite;
        }
    }
    return null;
}

pub const Aead = union(enum) {
    prefix_nonce_aead_aes128_gcm: PrefixNonceAeadAes128Gcm,
    prefix_nonce_aead_aes256_gcm: PrefixNonceAeadAes256Gcm,
    xor_nonce_aead_aes128_gcm: XorNonceAeadAes128Gcm,
    xor_nonce_aead_aes256_gcm: XorNonceAeadAes256Gcm,
    xor_nonce_aead_cha_cha20_poly1305: XorNonceAeadChaCha20Poly1305,

    pub fn initPrefixNonceAeadAes128Gcm(key: []const u8, nonce_prefix: []const u8) Aead {
        return .{
            .prefix_nonce_aead_aes128_gcm = PrefixNonceAeadAes128Gcm.init(key, nonce_prefix),
        };
    }

    pub fn initPrefixNonceAeadAes256Gcm(key: []const u8, nonce_prefix: []const u8) Aead {
        return .{
            .prefix_nonce_aead_aes256_gcm = PrefixNonceAeadAes256Gcm.init(key, nonce_prefix),
        };
    }

    pub fn initXorNonceAeadAes128Gcm(key: []const u8, nonce_mask: []const u8) Aead {
        return .{
            .xor_nonce_aead_aes128_gcm = XorNonceAeadAes128Gcm.init(key, nonce_mask),
        };
    }

    pub fn initXorNonceAeadAes256Gcm(key: []const u8, nonce_mask: []const u8) Aead {
        return .{
            .xor_nonce_aead_aes256_gcm = XorNonceAeadAes256Gcm.init(key, nonce_mask),
        };
    }

    pub fn initXorNonceAeadChaCha20Poly1305(key: []const u8, nonce_mask: []const u8) Aead {
        return .{
            .xor_nonce_aead_cha_cha20_poly1305 = XorNonceAeadChaCha20Poly1305.init(key, nonce_mask),
        };
    }

    pub fn explicitNonceLen(self: *const Aead) usize {
        return switch (self.*) {
            .prefix_nonce_aead_aes128_gcm => PrefixNonceAeadAes128Gcm.explicit_nonce_length,
            .prefix_nonce_aead_aes256_gcm => PrefixNonceAeadAes256Gcm.explicit_nonce_length,
            .xor_nonce_aead_aes128_gcm => XorNonceAeadAes128Gcm.explicit_nonce_length,
            .xor_nonce_aead_aes256_gcm => XorNonceAeadAes256Gcm.explicit_nonce_length,
            .xor_nonce_aead_cha_cha20_poly1305 => XorNonceAeadChaCha20Poly1305.explicit_nonce_length,
        };
    }

    pub fn overhead(self: *const Aead) usize {
        return switch (self.*) {
            .prefix_nonce_aead_aes128_gcm => PrefixNonceAeadAes128Gcm.tag_length,
            .prefix_nonce_aead_aes256_gcm => PrefixNonceAeadAes256Gcm.tag_length,
            .xor_nonce_aead_aes128_gcm => XorNonceAeadAes128Gcm.tag_length,
            .xor_nonce_aead_aes256_gcm => XorNonceAeadAes256Gcm.tag_length,
            .xor_nonce_aead_cha_cha20_poly1305 => XorNonceAeadChaCha20Poly1305.tag_length,
        };
    }

    pub fn encrypt(
        self: *Aead,
        allocator: mem.Allocator,
        dest: *std.ArrayListUnmanaged(u8),
        nonce: []const u8,
        plaintext: []const u8,
        additional_data: []const u8,
    ) !void {
        switch (self.*) {
            .prefix_nonce_aead_aes128_gcm => |*c| try c.encrypt(
                allocator,
                dest,
                nonce,
                plaintext,
                additional_data,
            ),
            .prefix_nonce_aead_aes256_gcm => |*c| try c.encrypt(
                allocator,
                dest,
                nonce,
                plaintext,
                additional_data,
            ),
            .xor_nonce_aead_aes128_gcm => |*c| try c.encrypt(
                allocator,
                dest,
                nonce,
                plaintext,
                additional_data,
            ),
            .xor_nonce_aead_aes256_gcm => |*c| try c.encrypt(
                allocator,
                dest,
                nonce,
                plaintext,
                additional_data,
            ),
            .xor_nonce_aead_cha_cha20_poly1305 => |*c| try c.encrypt(
                allocator,
                dest,
                nonce,
                plaintext,
                additional_data,
            ),
        }
    }

    pub fn decrypt(
        self: *Aead,
        allocator: mem.Allocator,
        dest: *std.ArrayListUnmanaged(u8),
        nonce: []const u8,
        chiphertext_and_tag: []const u8,
        additional_data: []const u8,
    ) !void {
        switch (self.*) {
            .prefix_nonce_aead_aes128_gcm => |*c| try c.decrypt(
                allocator,
                dest,
                nonce,
                chiphertext_and_tag,
                additional_data,
            ),
            .prefix_nonce_aead_aes256_gcm => |*c| try c.decrypt(
                allocator,
                dest,
                nonce,
                chiphertext_and_tag,
                additional_data,
            ),
            .xor_nonce_aead_aes128_gcm => |*c| try c.decrypt(
                allocator,
                dest,
                nonce,
                chiphertext_and_tag,
                additional_data,
            ),
            .xor_nonce_aead_aes256_gcm => |*c| try c.decrypt(
                allocator,
                dest,
                nonce,
                chiphertext_and_tag,
                additional_data,
            ),
            .xor_nonce_aead_cha_cha20_poly1305 => |*c| try c.decrypt(
                allocator,
                dest,
                nonce,
                chiphertext_and_tag,
                additional_data,
            ),
        }
    }
};

const aead_nonce_length = 12;
pub const nonce_prefix_length = 4;

pub const PrefixNonceAeadAes128Gcm = PrefixNonceAead(std.crypto.aead.aes_gcm.Aes128Gcm);
pub const PrefixNonceAeadAes256Gcm = PrefixNonceAead(std.crypto.aead.aes_gcm.Aes256Gcm);

// prefixNonceAEAD wraps an AEAD and prefixes a fixed portion of the nonce to
// each call.
fn PrefixNonceAead(comptime AesGcm: type) type {
    return struct {
        const Self = @This();
        pub const key_length = AesGcm.key_length;
        pub const tag_length = AesGcm.tag_length;
        pub const nonce_length = aead_nonce_length - nonce_prefix_length;
        pub const explicit_nonce_length = aead_nonce_length - nonce_prefix_length;

        // nonce contains the fixed part of the nonce in the first four bytes.
        nonce: [aead_nonce_length]u8 = [_]u8{0} ** aead_nonce_length,
        key: [key_length]u8,

        pub fn init(key: []const u8, nonce_prefix: []const u8) Self {
            assert(key.len == key_length);
            assert(nonce_prefix.len == nonce_prefix_length);
            var self = Self{ .key = key[0..key_length].* };
            mem.copy(u8, &self.nonce, nonce_prefix[0..]);
            return self;
        }

        pub fn encrypt(
            self: *Self,
            allocator: mem.Allocator,
            dest: *std.ArrayListUnmanaged(u8),
            nonce: []const u8,
            plaintext: []const u8,
            additional_data: []const u8,
        ) !void {
            assert(nonce.len == explicit_nonce_length);

            // Note: we have to copy explicit_nonce before resizing dest
            // because HalfConn.encrypt put nonce in dest.items.
            // After resizing dest, accessing nonce's data causes a segment fault
            // if dest.items.ptr is changed.
            var explicit_nonce: [explicit_nonce_length]u8 = undefined;
            mem.copy(u8, &explicit_nonce, nonce);

            const old_len = dest.items.len;
            const tag_start = old_len + plaintext.len;
            const new_len = tag_start + tag_length;
            try dest.resize(allocator, new_len);
            self.doEncrypt(
                dest.items[old_len..tag_start],
                dest.items[tag_start..new_len][0..tag_length],
                plaintext,
                additional_data,
                explicit_nonce,
            );
        }

        fn doEncrypt(
            self: *Self,
            out_ciphertext: []u8,
            out_tag: *[tag_length]u8,
            plaintext: []const u8,
            additional_data: []const u8,
            explicit_nonce: [explicit_nonce_length]u8,
        ) void {
            mem.copy(u8, self.nonce[nonce_prefix_length..], &explicit_nonce);
            AesGcm.encrypt(
                out_ciphertext,
                out_tag,
                plaintext,
                additional_data,
                self.nonce,
                self.key,
            );
        }

        pub fn decrypt(
            self: *Self,
            allocator: mem.Allocator,
            dest: *std.ArrayListUnmanaged(u8),
            nonce: []const u8,
            chiphertext_and_tag: []const u8,
            additional_data: []const u8,
        ) !void {
            assert(nonce.len == explicit_nonce_length);
            assert(chiphertext_and_tag.len >= tag_length);
            const old_len = dest.items.len;
            const ciphertext_len = chiphertext_and_tag.len - tag_length;
            const new_len = old_len + ciphertext_len;
            try dest.ensureTotalCapacityPrecise(allocator, new_len);
            dest.expandToCapacity();
            try self.doDecrypt(
                dest.items[old_len..new_len],
                chiphertext_and_tag[0..ciphertext_len],
                chiphertext_and_tag[ciphertext_len..][0..tag_length].*,
                additional_data,
                nonce[0..explicit_nonce_length].*,
            );
        }

        pub fn doDecrypt(
            self: *Self,
            out_plaintext: []u8,
            ciphertext: []const u8,
            tag: [tag_length]u8,
            additional_data: []const u8,
            explicit_nonce: [explicit_nonce_length]u8,
        ) !void {
            mem.copy(u8, self.nonce[nonce_prefix_length..], &explicit_nonce);
            try AesGcm.decrypt(
                out_plaintext,
                ciphertext,
                tag,
                additional_data,
                self.nonce,
                self.key,
            );
        }
    };
}

pub const XorNonceAeadAes128Gcm = XorNonceAead(std.crypto.aead.aes_gcm.Aes128Gcm);
pub const XorNonceAeadAes256Gcm = XorNonceAead(std.crypto.aead.aes_gcm.Aes256Gcm);
pub const XorNonceAeadChaCha20Poly1305 = XorNonceAead(std.crypto.aead.chacha_poly.ChaCha20Poly1305);

// XorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
fn XorNonceAead(comptime InnerAead: type) type {
    return struct {
        const Self = @This();
        pub const key_length = InnerAead.key_length;
        pub const tag_length = InnerAead.tag_length;
        pub const nonce_length = 8; // 64-bit sequence number
        pub const explicit_nonce_length = 0;

        nonce_mask: [aead_nonce_length]u8,
        key: [key_length]u8,

        pub fn init(key: []const u8, nonce_mask: []const u8) Self {
            assert(key.len == key_length);
            assert(nonce_mask.len == aead_nonce_length);
            return .{
                .key = key[0..key_length].*,
                .nonce_mask = nonce_mask[0..aead_nonce_length].*,
            };
        }

        pub fn encrypt(
            self: *Self,
            allocator: mem.Allocator,
            dest: *std.ArrayListUnmanaged(u8),
            nonce: []const u8,
            plaintext: []const u8,
            additional_data: []const u8,
        ) !void {
            assert(nonce.len == nonce_length);

            // Note: we have to copy nonce before resizing dest
            // because HalfConn.encrypt put nonce in dest.items.
            // After resizing dest, accessing nonce's data causes a segment fault
            // if dest.items.ptr is changed.
            var nonce_copy: [nonce_length]u8 = undefined;
            mem.copy(u8, &nonce_copy, nonce);

            const old_len = dest.items.len;
            const tag_start = old_len + plaintext.len;
            const new_len = tag_start + tag_length;
            try dest.resize(allocator, new_len);
            self.doEncrypt(
                dest.items[old_len..tag_start],
                dest.items[tag_start..new_len][0..tag_length],
                plaintext,
                additional_data,
                nonce_copy,
            );
        }

        fn doEncrypt(
            self: *Self,
            out_ciphertext: []u8,
            out_tag: *[tag_length]u8,
            plaintext: []const u8,
            additional_data: []const u8,
            nonce: [nonce_length]u8,
        ) void {
            self.updateNonceMask(nonce);
            InnerAead.encrypt(
                out_ciphertext,
                out_tag,
                plaintext,
                additional_data,
                self.nonce_mask,
                self.key,
            );
            self.updateNonceMask(nonce);
        }

        pub fn decrypt(
            self: *Self,
            allocator: mem.Allocator,
            dest: *std.ArrayListUnmanaged(u8),
            nonce: []const u8,
            chiphertext_and_tag: []const u8,
            additional_data: []const u8,
        ) !void {
            assert(nonce.len == nonce_length);
            assert(chiphertext_and_tag.len >= tag_length);
            const old_len = dest.items.len;
            const ciphertext_len = chiphertext_and_tag.len - tag_length;
            const new_len = old_len + ciphertext_len;
            try dest.ensureTotalCapacityPrecise(allocator, new_len);
            dest.expandToCapacity();
            try self.doDecrypt(
                dest.items[old_len..new_len],
                chiphertext_and_tag[0..ciphertext_len],
                chiphertext_and_tag[ciphertext_len..][0..tag_length].*,
                additional_data,
                nonce[0..nonce_length].*,
            );
        }

        fn doDecrypt(
            self: *Self,
            out_plaintext: []u8,
            ciphertext: []const u8,
            tag: [tag_length]u8,
            additional_data: []const u8,
            nonce: [nonce_length]u8,
        ) !void {
            self.updateNonceMask(nonce);
            try InnerAead.decrypt(
                out_plaintext,
                ciphertext,
                tag,
                additional_data,
                self.nonce_mask,
                self.key,
            );
            self.updateNonceMask(nonce);
        }

        inline fn updateNonceMask(
            self: *Self,
            nonce: [nonce_length]u8,
        ) void {
            var i: usize = 0;
            while (i < nonce.len) : (i += 1) {
                self.nonce_mask[aead_nonce_length - nonce_length + i] ^= nonce[i];
            }
        }
    };
}

const testing = std.testing;
const fmtx = @import("../fmtx.zig");

test "mutualCipherSuiteTls12" {
    const have = [_]CipherSuiteId{
        .tls_ecdhe_rsa_with_chacha20_poly1305_sha256,
        .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    };

    try testing.expectEqual(
        cipherSuiteTls12ById(.tls_ecdhe_ecdsa_with_aes_256_gcm_sha384),
        mutualCipherSuiteTls12(&have, .tls_ecdhe_ecdsa_with_aes_256_gcm_sha384),
    );

    try testing.expectEqual(
        @as(?*const CipherSuiteTls12, null),
        mutualCipherSuiteTls12(&have, .tls_aes_128_gcm_sha256),
    );
}

test "Aes128Gcm - Message and associated data" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const key: [Aes128Gcm.key_length]u8 = [_]u8{'k'} ** Aes128Gcm.key_length;
    const nonce: [Aes128Gcm.nonce_length]u8 = [_]u8{'n'} ** Aes128Gcm.nonce_length;
    const m = "exampleplaintext";
    const ad = "additionaldata";
    var c: [m.len]u8 = undefined;
    var m2: [m.len]u8 = undefined;
    var tag: [Aes128Gcm.tag_length]u8 = undefined;

    Aes128Gcm.encrypt(&c, &tag, m, ad, nonce, key);
    try Aes128Gcm.decrypt(&m2, &c, tag, ad, nonce, key);
    try testing.expectEqualSlices(u8, m[0..], m2[0..]);

    try testing.expectEqualSlices(
        u8,
        "\x5e\x84\x2b\xcb\x73\x09\x9c\xcf\xdd\x8e\x7e\x27\x1c\x07\x14\xef",
        &c,
    );
    try testing.expectEqualSlices(
        u8,
        "\x74\xe2\xdf\xb3\x6e\x31\x90\x6f\xd5\xd1\x17\xd4\xa1\x7a\x14\x2d",
        &tag,
    );
}

test "PrefixNonceAeadAes128Gcm" {
    testing.log_level = .err;

    const allocator = testing.allocator;

    const key = [_]u8{'k'} ** PrefixNonceAeadAes128Gcm.key_length;
    const nonce_prefix = [_]u8{'p'} ** nonce_prefix_length;
    var aead = PrefixNonceAeadAes128Gcm.init(&key, &nonce_prefix);

    const m = "exampleplaintext";
    const ad = "additionaldata";
    const explicit_nonce = [_]u8{'n'} ** PrefixNonceAeadAes128Gcm.explicit_nonce_length;

    var c = std.ArrayListUnmanaged(u8){};
    defer c.deinit(allocator);
    try aead.encrypt(allocator, &c, &explicit_nonce, m, ad);
    try testing.expectEqualSlices(
        u8,
        "\x4b\x94\x1c\x11\x1c\xc9\xe9\xdb\x4d\xa6\xdb\xf7\x69\xda\x42\x81" ++
            "\x07\xb4\x8a\x4c\x64\xda\x24\x62\xfc\xbc\xab\xb7\xfd\x76\x5e\x62",
        c.items,
    );

    var m2 = std.ArrayListUnmanaged(u8){};
    defer m2.deinit(allocator);
    try aead.decrypt(allocator, &m2, &explicit_nonce, c.items, ad);
    try testing.expectEqualStrings(m, m2.items);
}

test "PrefixNonceAeadAes256Gcm" {
    testing.log_level = .err;

    const allocator = testing.allocator;

    const key = [_]u8{'k'} ** PrefixNonceAeadAes256Gcm.key_length;
    const nonce_prefix = [_]u8{'p'} ** nonce_prefix_length;
    var aead = PrefixNonceAeadAes256Gcm.init(&key, &nonce_prefix);

    const m = "exampleplaintext";
    const ad = "additionaldata";
    const explicit_nonce = [_]u8{'n'} ** PrefixNonceAeadAes256Gcm.explicit_nonce_length;

    var c = std.ArrayListUnmanaged(u8){};
    defer c.deinit(allocator);
    try aead.encrypt(allocator, &c, &explicit_nonce, m, ad);
    try testing.expectEqualSlices(
        u8,
        "\x1a\xd2\x36\x15\xdd\xe3\x47\xec\xa5\x7d\xf1\x73\xef\xe8\xfa\x10" ++
            "\x9d\x47\x5e\x0a\x47\x05\xcb\x51\xd3\xba\x47\x31\xe8\x79\xad\xb9",
        c.items,
    );

    var m2 = std.ArrayListUnmanaged(u8){};
    defer m2.deinit(allocator);
    try aead.decrypt(allocator, &m2, &explicit_nonce, c.items, ad);
    try testing.expectEqualStrings(m, m2.items);
}

test "XorNonceAeadAes128Gcm" {
    testing.log_level = .err;

    const allocator = testing.allocator;

    const key = [_]u8{'k'} ** XorNonceAeadAes128Gcm.key_length;
    const nonce_mask = [_]u8{'m'} ** aead_nonce_length;
    var aead = XorNonceAeadAes128Gcm.init(&key, &nonce_mask);

    const m = "exampleplaintext";
    const ad = "additionaldata";
    const nonce = [_]u8{'n'} ** XorNonceAeadAes128Gcm.nonce_length;

    var c = std.ArrayListUnmanaged(u8){};
    defer c.deinit(allocator);
    try aead.encrypt(allocator, &c, &nonce, m, ad);
    try testing.expectEqualSlices(
        u8,
        "\x58\x92\x14\xf9\x47\x1f\x36\xc4\x95\x25\xe3\x16\x45\xc5\xbe\x39" ++
            "\xbc\xfa\xd7\x22\x79\xe1\xff\x3f\xcb\x1a\x51\x0d\x92\x2b\xbd\x8f",
        c.items,
    );

    var m2 = std.ArrayListUnmanaged(u8){};
    defer m2.deinit(allocator);
    try aead.decrypt(allocator, &m2, &nonce, c.items, ad);
    try testing.expectEqualStrings(m, m2.items);
}

test "XorNonceAeadAes256Gcm" {
    testing.log_level = .err;

    const allocator = testing.allocator;

    const key = [_]u8{'k'} ** XorNonceAeadAes256Gcm.key_length;
    const nonce_mask = [_]u8{'m'} ** aead_nonce_length;
    var aead = XorNonceAeadAes256Gcm.init(&key, &nonce_mask);

    const m = "exampleplaintext";
    const ad = "additionaldata";
    const nonce = [_]u8{'n'} ** XorNonceAeadAes256Gcm.nonce_length;

    var c = std.ArrayListUnmanaged(u8){};
    defer c.deinit(allocator);
    try aead.encrypt(allocator, &c, &nonce, m, ad);
    try testing.expectEqualSlices(
        u8,
        "\x61\x91\xb6\x55\xb7\x04\x54\xbf\xf5\x94\x4e\x7d\xbd\x83\x6b\x84" ++
            "\x90\xcc\x27\x9a\xb8\x5d\x84\xf4\xcf\x67\x05\x27\x22\x27\xd4\x58",
        c.items,
    );

    var m2 = std.ArrayListUnmanaged(u8){};
    defer m2.deinit(allocator);
    try aead.decrypt(allocator, &m2, &nonce, c.items, ad);
    try testing.expectEqualStrings(m, m2.items);
}

test "XorNonceAeadChaCha20Poly1305" {
    testing.log_level = .err;

    const allocator = testing.allocator;

    const key = [_]u8{'k'} ** XorNonceAeadChaCha20Poly1305.key_length;
    const nonce_prefix = [_]u8{'m'} ** aead_nonce_length;
    var aead = XorNonceAeadChaCha20Poly1305.init(&key, &nonce_prefix);

    const m = "exampleplaintext";
    const ad = "additionaldata";
    const nonce = [_]u8{'n'} ** XorNonceAeadChaCha20Poly1305.nonce_length;

    var c = std.ArrayListUnmanaged(u8){};
    defer c.deinit(allocator);
    try aead.encrypt(allocator, &c, &nonce, m, ad);
    try testing.expectEqualSlices(
        u8,
        "\xdf\x39\x03\x0c\xb1\x2f\xe4\xf9\x24\xeb\x76\x15\x80\x4c\x40\xed" ++
            "\xd8\x1f\x15\x82\xfc\x6c\x15\x62\x12\x9c\x8f\x77\x77\x11\x91\x60",
        c.items,
    );

    var m2 = std.ArrayListUnmanaged(u8){};
    defer m2.deinit(allocator);
    try aead.decrypt(allocator, &m2, &nonce, c.items, ad);
    try testing.expectEqualStrings(m, m2.items);
}

test "AeadXorNonceAeadChaCha20Poly1305" {
    testing.log_level = .err;

    const allocator = testing.allocator;

    const key = [_]u8{'k'} ** XorNonceAeadChaCha20Poly1305.key_length;
    const nonce_prefix = [_]u8{'m'} ** aead_nonce_length;
    var aead = Aead.initXorNonceAeadChaCha20Poly1305(&key, &nonce_prefix);

    const m = "exampleplaintext";
    const ad = "additionaldata";
    const nonce = [_]u8{'n'} ** XorNonceAeadChaCha20Poly1305.nonce_length;

    var c = std.ArrayListUnmanaged(u8){};
    defer c.deinit(allocator);
    try aead.encrypt(allocator, &c, &nonce, m, ad);
    try testing.expectEqualSlices(
        u8,
        "\xdf\x39\x03\x0c\xb1\x2f\xe4\xf9\x24\xeb\x76\x15\x80\x4c\x40\xed" ++
            "\xd8\x1f\x15\x82\xfc\x6c\x15\x62\x12\x9c\x8f\x77\x77\x11\x91\x60",
        c.items,
    );

    var m2 = std.ArrayListUnmanaged(u8){};
    defer m2.deinit(allocator);
    try aead.decrypt(allocator, &m2, &nonce, c.items, ad);
    try testing.expectEqualStrings(m, m2.items);
}
