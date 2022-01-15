const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const KeyAgreement = @import("key_agreement.zig").KeyAgreement;
const RsaKeyAgreement = @import("key_agreement.zig").RsaKeyAgreement;
const EcdheKeyAgreement = @import("key_agreement.zig").EcdheKeyAgreement;
const memx = @import("../memx.zig");

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
    aead: ?fn (key: []const u8, nonce_prefix: []const u8) Aead,
};

pub const default_cipher_suites = cipher_suites_preference_order;

const cipher_suites_preference_order = [_]CipherSuiteId{
    .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};

pub const cipher_suites12 = [_]CipherSuite12{
    .{
        .id = .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 12,
        .flags = .{ .ecdhe = true, .tls12 = true },
        .ka = ecdheRsaKa,
        .aead = Aead.initXorNonceAeadChaCha20Poly1305,
    },
    .{
        .id = .TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 12,
        .flags = .{ .ecdhe = true, .ec_sign = true, .tls12 = true },
        .ka = ecdheEcdsaKa,
        .aead = Aead.initXorNonceAeadChaCha20Poly1305,
    },
    .{
        .id = .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .key_len = 16,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .ec_sign = true, .tls12 = true },
        .ka = ecdheEcdsaKa,
        .aead = Aead.initPrefixNonceAeadAes128Gcm,
    },
    .{
        .id = .TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .key_len = 16,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .tls12 = true },
        .ka = ecdheRsaKa,
        .aead = Aead.initPrefixNonceAeadAes128Gcm,
    },
    .{
        .id = .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .key_len = 32,
        .mac_len = 0,
        .iv_len = 4,
        .flags = .{ .ecdhe = true, .ec_sign = true, .tls12 = true, .sha384 = true },
        .ka = ecdheEcdsaKa,
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

pub fn makeCipherPreferenceList12(
    allocator: mem.Allocator,
    config_cipher_suites: []const CipherSuiteId,
) ![]const CipherSuiteId {
    var cipher_suites = try std.ArrayListUnmanaged(CipherSuiteId).initCapacity(
        allocator,
        config_cipher_suites.len,
    );
    errdefer cipher_suites.deinit(allocator);

    for (cipher_suites_preference_order) |suite_id| {
        if (mutualCipherSuite12(config_cipher_suites, suite_id)) |_| {
            try cipher_suites.append(allocator, suite_id);
        }
    }
    return cipher_suites.toOwnedSlice(allocator);
}

pub fn mutualCipherSuite12(have: []const CipherSuiteId, want: CipherSuiteId) ?*const CipherSuite12 {
    return if (memx.containsScalar(CipherSuiteId, have, want)) cipherSuite12ById(want) else null;
}

// selectCipherSuite12 returns the first TLS 1.0–1.2 cipher suite from ids which
// is also in supportedIDs and passes the ok filter.
pub fn selectCipherSuite12(
    ids: []const CipherSuiteId,
    supported_ids: []const CipherSuiteId,
    context: anytype,
    ok: fn (@TypeOf(context), *const CipherSuite12) bool,
) ?*const CipherSuite12 {
    for (ids) |id| {
        if (cipherSuite12ById(id)) |candidate| {
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

pub fn cipherSuite12ById(id: CipherSuiteId) ?*const CipherSuite12 {
    for (cipher_suites12) |*suite| {
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

    pub fn initXorNonceAeadAes128Gcm(key: []const u8, nonce_prefix: []const u8) Aead {
        return .{
            .xor_nonce_aead_aes128_gcm = XorNonceAeadAes128Gcm.init(key, nonce_prefix),
        };
    }

    pub fn initXorNonceAeadAes256Gcm(key: []const u8, nonce_prefix: []const u8) Aead {
        return .{
            .xor_nonce_aead_aes256_gcm = XorNonceAeadAes256Gcm.init(key, nonce_prefix),
        };
    }

    pub fn initXorNonceAeadChaCha20Poly1305(key: []const u8, nonce_prefix: []const u8) Aead {
        return .{
            .xor_nonce_aead_cha_cha20_poly1305 = XorNonceAeadChaCha20Poly1305.init(key, nonce_prefix),
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
            self.do_encrypt(
                dest.items[old_len..tag_start],
                dest.items[tag_start..new_len][0..tag_length],
                plaintext,
                additional_data,
                explicit_nonce,
            );
        }

        fn do_encrypt(
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
            try self.do_decrypt(
                dest.items[old_len..new_len],
                chiphertext_and_tag[0..ciphertext_len],
                chiphertext_and_tag[ciphertext_len..][0..tag_length].*,
                additional_data,
                nonce[0..explicit_nonce_length].*,
            );
        }

        pub fn do_decrypt(
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
            self.do_encrypt(
                dest.items[old_len..tag_start],
                dest.items[tag_start..new_len][0..tag_length],
                plaintext,
                additional_data,
                nonce_copy,
            );
        }

        fn do_encrypt(
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
            try self.do_decrypt(
                dest.items[old_len..new_len],
                chiphertext_and_tag[0..ciphertext_len],
                chiphertext_and_tag[ciphertext_len..][0..tag_length].*,
                additional_data,
                nonce[0..nonce_length].*,
            );
        }

        fn do_decrypt(
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

test "mutualCipherSuite12" {
    const have = [_]CipherSuiteId{
        .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    };

    try testing.expectEqual(
        cipherSuite12ById(.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        mutualCipherSuite12(&have, .TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    );

    try testing.expectEqual(
        @as(?*const CipherSuite12, null),
        mutualCipherSuite12(&have, .TLS_AES_128_GCM_SHA256),
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
    testing.log_level = .debug;

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
    testing.log_level = .debug;

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
    testing.log_level = .debug;

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
    testing.log_level = .debug;

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
    testing.log_level = .debug;

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
    testing.log_level = .debug;

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
