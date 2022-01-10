const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
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

pub const Aead = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        encrypt: fn (
            ptr: *anyopaque,
            allocator: mem.Allocator,
            dest: *std.ArrayListUnmanaged(u8),
            nonce: []const u8,
            plaintext: []const u8,
            additional_data: []const u8,
        ) anyerror!void,

        decrypt: fn (
            ptr: *anyopaque,
            allocator: mem.Allocator,
            dest: *std.ArrayListUnmanaged(u8),
            nonce: []const u8,
            chiphertext_and_tag: []const u8,
            additional_data: []const u8,
        ) anyerror!void,
    };

    pub fn init(
        pointer: anytype,
        comptime encryptFn: fn (
            ptr: @TypeOf(pointer),
            allocator: mem.Allocator,
            dest: *std.ArrayListUnmanaged(u8),
            nonce: []const u8,
            plaintext: []const u8,
            additional_data: []const u8,
        ) anyerror!void,
        comptime decryptFn: fn (
            ptr: @TypeOf(pointer),
            allocator: mem.Allocator,
            dest: *std.ArrayListUnmanaged(u8),
            nonce: []const u8,
            chiphertext_and_tag: []const u8,
            additional_data: []const u8,
        ) anyerror!void,
    ) Aead {
        const Ptr = @TypeOf(pointer);
        const ptr_info = @typeInfo(Ptr);

        assert(ptr_info == .Pointer); // Must be a pointer
        assert(ptr_info.Pointer.size == .One); // Must be a single-item pointer

        const alignment = ptr_info.Pointer.alignment;

        const gen = struct {
            fn encryptImpl(
                ptr: *anyopaque,
                allocator: mem.Allocator,
                dest: *std.ArrayListUnmanaged(u8),
                nonce: []const u8,
                plaintext: []const u8,
                additional_data: []const u8,
            ) anyerror!void {
                const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                return @call(
                    .{ .modifier = .always_inline },
                    encryptFn,
                    .{ self, allocator, dest, nonce, plaintext, additional_data },
                );
            }
            fn decryptImpl(
                ptr: *anyopaque,
                allocator: mem.Allocator,
                dest: *std.ArrayListUnmanaged(u8),
                nonce: []const u8,
                chiphertext_and_tag: []const u8,
                additional_data: []const u8,
            ) anyerror!void {
                const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                return @call(
                    .{ .modifier = .always_inline },
                    decryptFn,
                    .{ self, allocator, dest, nonce, chiphertext_and_tag, additional_data },
                );
            }

            const vtable = VTable{
                .encrypt = encryptImpl,
                .decrypt = decryptImpl,
            };
        };

        return .{
            .ptr = pointer,
            .vtable = &gen.vtable,
        };
    }

    pub fn encrypt(
        self: Aead,
        allocator: mem.Allocator,
        dest: *std.ArrayListUnmanaged(u8),
        nonce: []const u8,
        plaintext: []const u8,
        additional_data: []const u8,
    ) !void {
        try self.vtable.encrypt(
            self.ptr,
            allocator,
            dest,
            nonce,
            plaintext,
            additional_data,
        );
    }

    pub fn decrypt(
        self: Aead,
        allocator: mem.Allocator,
        dest: *std.ArrayListUnmanaged(u8),
        nonce: []const u8,
        chiphertext_and_tag: []const u8,
        additional_data: []const u8,
    ) !void {
        try self.vtable.decrypt(
            self.ptr,
            allocator,
            dest,
            nonce,
            chiphertext_and_tag,
            additional_data,
        );
    }
};

const aead_nonce_length = 12;
const nonce_prefix_length = 4;

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

        pub fn init(key: [key_length]u8, nonce_prefix: [nonce_prefix_length]u8) Self {
            var self = Self{ .key = key };
            mem.copy(u8, &self.nonce, nonce_prefix[0..]);
            return self;
        }

        pub fn initAead(key: [key_length]u8, nonce_prefix: [nonce_prefix_length]u8) Aead {
            return init(key, nonce_prefix).aead();
        }

        pub fn aead(self: *Self) Aead {
            return Aead.init(self, encrypt, decrypt);
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
            const old_len = dest.items.len;
            const tag_start = old_len + plaintext.len;
            const new_len = tag_start + tag_length;
            try dest.resize(allocator, new_len);
            self.do_encrypt(
                dest.items[old_len..tag_start],
                dest.items[tag_start..new_len][0..tag_length],
                plaintext,
                additional_data,
                nonce[0..explicit_nonce_length].*,
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
            try dest.resize(allocator, new_len);
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

        pub fn init(key: [key_length]u8, nonce_mask: [aead_nonce_length]u8) Self {
            return .{ .key = key, .nonce_mask = nonce_mask };
        }

        pub fn initAead(key: [key_length]u8, nonce_prefix: [nonce_prefix_length]u8) Aead {
            return init(key, nonce_prefix).aead();
        }

        pub fn aead(self: *Self) Aead {
            return Aead.init(self, encrypt, decrypt);
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
            const old_len = dest.items.len;
            const tag_start = old_len + plaintext.len;
            const new_len = tag_start + tag_length;
            try dest.resize(allocator, new_len);
            self.do_encrypt(
                dest.items[old_len..tag_start],
                dest.items[tag_start..new_len][0..tag_length],
                plaintext,
                additional_data,
                nonce[0..nonce_length].*,
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
            try dest.resize(allocator, new_len);
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
        @as(?*const CipherSuite12, &cipher_suites12[2]),
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

test "PrefixNonceAeadAes128Gcm Aead" {
    testing.log_level = .debug;

    const allocator = testing.allocator;

    const key = [_]u8{'k'} ** PrefixNonceAeadAes128Gcm.key_length;
    const nonce_prefix = [_]u8{'p'} ** nonce_prefix_length;
    var concrete_aead = PrefixNonceAeadAes128Gcm.init(key, nonce_prefix);
    var aead = concrete_aead.aead();

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

test "PrefixNonceAeadAes128Gcm" {
    testing.log_level = .debug;

    const allocator = testing.allocator;

    const key = [_]u8{'k'} ** PrefixNonceAeadAes128Gcm.key_length;
    const nonce_prefix = [_]u8{'p'} ** nonce_prefix_length;
    var aead = PrefixNonceAeadAes128Gcm.init(key, nonce_prefix);

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
    var aead = PrefixNonceAeadAes256Gcm.init(key, nonce_prefix);

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
    var aead = XorNonceAeadAes128Gcm.init(key, nonce_mask);

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
    var aead = XorNonceAeadAes256Gcm.init(key, nonce_mask);

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
    var aead = XorNonceAeadChaCha20Poly1305.init(key, nonce_prefix);

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
