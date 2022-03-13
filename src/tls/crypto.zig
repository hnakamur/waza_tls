const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const asn1 = @import("asn1.zig");
const rsa = @import("rsa.zig");
const ecdsa = @import("ecdsa.zig");
const parsePkcs1PrivateKey = @import("pkcs1.zig").parsePkcs1PrivateKey;
const HashType = @import("auth.zig").HashType;

pub const Hash = union(HashType) {
    pub const max_digest_length = std.crypto.hash.sha2.Sha512.digest_length;
    pub const DigestArray = std.BoundedArray(u8, max_digest_length);

    sha256: Sha256Hash,
    sha384: Sha384Hash,
    sha512: Sha512Hash,
    sha1: Sha1Hash,
    direct_signing: void,

    pub fn init(hash_type: HashType) Hash {
        return switch (hash_type) {
            .sha256 => .{ .sha256 = Sha256Hash.init(.{}) },
            .sha384 => .{ .sha384 = Sha384Hash.init(.{}) },
            .sha512 => .{ .sha512 = Sha512Hash.init(.{}) },
            .sha1 => .{ .sha1 = Sha1Hash.init(.{}) },
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn update(self: *Hash, b: []const u8) void {
        switch (self.*) {
            .sha256 => |*s| s.update(b),
            .sha384 => |*s| s.update(b),
            .sha512 => |*s| s.update(b),
            .sha1 => |*s| s.update(b),
            else => @panic("Unsupported HashType"),
        }
    }

    pub fn writeFinal(self: *const Hash, writer: anytype) !usize {
        return switch (self.*) {
            .sha256 => |*s| try s.writeFinal(writer),
            .sha384 => |*s| try s.writeFinal(writer),
            .sha512 => |*s| try s.writeFinal(writer),
            .sha1 => |*s| try s.writeFinal(writer),
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn finalToSlice(self: *const Hash, out: []u8) void {
        switch (self.*) {
            .sha256 => |*s| s.finalToSlice(out),
            .sha384 => |*s| s.finalToSlice(out),
            .sha512 => |*s| s.finalToSlice(out),
            .sha1 => |*s| s.finalToSlice(out),
            else => @panic("Unsupported HashType"),
        }
    }

    pub fn digestLength(self: *const Hash) usize {
        return switch (self.*) {
            .sha256 => |s| @TypeOf(s).digest_length,
            .sha384 => |s| @TypeOf(s).digest_length,
            .sha512 => |s| @TypeOf(s).digest_length,
            .sha1 => |s| @TypeOf(s).digest_length,
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn allocFinal(self: *const Hash, allocator: mem.Allocator) ![]const u8 {
        return switch (self.*) {
            .sha256 => |*s| try s.allocFinal(allocator),
            .sha384 => |*s| try s.allocFinal(allocator),
            .sha512 => |*s| try s.allocFinal(allocator),
            .sha1 => |*s| try s.allocFinal(allocator),
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn clone(self: *const Hash) Hash {
        return switch (self.*) {
            .sha256 => |s| Hash{ .sha256 = s.clone() },
            .sha384 => |s| Hash{ .sha384 = s.clone() },
            .sha512 => |s| Hash{ .sha512 = s.clone() },
            .sha1 => |s| Hash{ .sha1 = s.clone() },
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn logFinal(self: *const Hash, label: []const u8) void {
        var out = DigestArray.init(self.digestLength()) catch unreachable;
        var out_slice = out.slice();
        self.finalToSlice(out_slice);
        std.log.info("{s}{}", .{ label, std.fmt.fmtSliceHexLower(out_slice) });
    }
};

pub const Sha256Hash = HashAdapter(std.crypto.hash.sha2.Sha256);
pub const Sha384Hash = HashAdapter(std.crypto.hash.sha2.Sha384);
pub const Sha512Hash = HashAdapter(std.crypto.hash.sha2.Sha512);
pub const Sha1Hash = HashAdapter(std.crypto.hash.Sha1);

fn HashAdapter(comptime HashImpl: type) type {
    return struct {
        const Self = @This();
        const WriteError = error{};
        const Writer = std.io.Writer(*Self, WriteError, write);

        pub const digest_length = HashImpl.digest_length;
        inner_hash: HashImpl,

        pub fn init(options: HashImpl.Options) Self {
            return .{ .inner_hash = HashImpl.init(options) };
        }

        pub fn update(self: *Self, b: []const u8) void {
            self.inner_hash.update(b);
        }

        /// Same as `update` except it returns the number of bytes written, which is always the same
        /// as `b.len`. The purpose of this function existing is to match `std.io.Writer` API.
        fn write(self: *Self, b: []const u8) WriteError!usize {
            self.update(b);
            return b.len;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn writeFinal(self: *const Self, out_stream: anytype) !usize {
            var d_out: [HashImpl.digest_length]u8 = undefined;
            var inner_hash_copy = self.inner_hash;
            inner_hash_copy.final(&d_out);
            try out_stream.writeAll(&d_out);
            return d_out.len;
        }

        pub fn finalToSlice(self: *const Self, out: []u8) void {
            const len = HashImpl.digest_length;
            var inner_hash_copy = self.inner_hash;
            inner_hash_copy.final(out[0..len]);
        }

        pub fn allocFinal(self: *const Self, allocator: mem.Allocator) ![]const u8 {
            var sum = try allocator.alloc(u8, digest_length);
            self.finalToSlice(sum);
            return sum;
        }

        pub fn clone(self: *const Self) Self {
            return .{ .inner_hash = self.inner_hash };
        }
    };
}

pub const PublicKeyAlgorithm = enum(u8) {
    unknown,
    rsa,
    dsa, // Unsupported.
    ecdsa,
    ed25519,

    pub fn fromOid(oid: asn1.ObjectIdentifier) PublicKeyAlgorithm {
        return if (oid.eql(asn1.ObjectIdentifier.public_key_ed25519))
            PublicKeyAlgorithm.ed25519
        else if (oid.eql(asn1.ObjectIdentifier.public_key_ecdsa))
            PublicKeyAlgorithm.ecdsa
        else if (oid.eql(asn1.ObjectIdentifier.public_key_rsa))
            PublicKeyAlgorithm.rsa
        else if (oid.eql(asn1.ObjectIdentifier.public_key_dsa))
            PublicKeyAlgorithm.dsa
        else
            PublicKeyAlgorithm.unknown;
    }
};

pub const PublicKey = union(PublicKeyAlgorithm) {
    unknown: void,
    rsa: rsa.PublicKey,
    dsa: void,
    ecdsa: ecdsa.PublicKey,
    ed25519: void,

    pub fn deinit(self: *PublicKey, allocator: mem.Allocator) void {
        switch (self.*) {
            .rsa => |*k| k.deinit(allocator),
            else => {},
        }
    }

    pub fn format(
        self: PublicKey,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .rsa => |k| {
                _ = try writer.write("PublicKey{ .rsa = ");
                try k.format(fmt, options, writer);
                _ = try writer.write(" }");
            },
            .ecdsa => |k| {
                try std.fmt.format(writer, "PublicKey{{ .ecdsa = {} }}", .{k});
            },
            else => {
                try std.fmt.format(writer, "PublicKey{{ .{s} = ... }}", .{@tagName(self)});
            },
        }
    }
};

pub const SignOpts = struct {
    // salt_length controls the length of the salt used in the PSS
    // signature. It can either be a number of bytes, or one of the special
    // PSSSaltLength constants.
    salt_length: ?rsa.PssSaltLength = null,

    // hash_type is the hash function used to generate the message digest. If not
    // zero, it overrides the hash function passed to SignPss. It's required
    // when using PrivateKey.Sign.
    hash_type: HashType = undefined,
};

pub const PrivateKey = union(PublicKeyAlgorithm) {
    unknown: void,
    rsa: rsa.PrivateKey,
    dsa: void,
    ecdsa: ecdsa.PrivateKey,
    ed25519: Ed25519PrivateKey,

    pub fn parse(allocator: mem.Allocator, der: []const u8) !PrivateKey {
        if (parsePkcs1PrivateKey(allocator, der)) |rsa_key| {
            return PrivateKey{ .rsa = rsa_key };
        } else |_| {}

        // TODO: implement parsePkcs8PrivateKey

        return PrivateKey{ .ecdsa = try ecdsa.PrivateKey.parseAsn1(allocator, der, null) };
    }

    pub fn deinit(self: *PrivateKey, allocator: mem.Allocator) void {
        switch (self.*) {
            .rsa => |*k| k.deinit(allocator),
            else => {},
        }
    }

    pub fn public(self: *const PrivateKey) PublicKey {
        return switch (self.*) {
            .rsa => |*k| PublicKey{ .rsa = k.public_key },
            .ecdsa => |*k| PublicKey{ .ecdsa = k.publicKey() },
            else => @panic("not implemented yet"),
        };
    }

    pub fn sign(
        self: *const PrivateKey,
        allocator: mem.Allocator,
        digest: []const u8,
        opts: SignOpts,
    ) ![]const u8 {
        return switch (self.*) {
            .rsa => |*k| try k.sign(allocator, std.crypto.random, digest, opts),
            .ecdsa => |*k| try k.sign(allocator, std.crypto.random, digest, opts),
            .ed25519 => |*k| try k.sign(allocator, null, digest, opts),
            else => @panic("not implemented yet"),
        };
    }
};

const Ed25519PrivateKey = struct {
    raw: []const u8,

    pub fn sign(
        self: *const Ed25519PrivateKey,
        allocator: mem.Allocator,
        random: ?std.rand.Random,
        digest: []const u8,
        opts: SignOpts,
    ) ![]const u8 {
        _ = random;
        _ = opts;
        const private_key_bytes = self.raw[0..std.crypto.sign.Ed25519.secret_length];
        const key_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(private_key_bytes.*);
        const sig = try std.crypto.sign.Ed25519.sign(digest, key_pair, null);
        return try allocator.dupe(u8, &sig);
    }
};

const testing = std.testing;

test "Hash.Sha256" {
    var h = Hash{ .sha256 = Sha256Hash.init(.{}) };
    h.update("hello");
    const digest_len = Sha256Hash.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(digest_len, bytes_written);
    std.log.debug("Sha256Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});

    var h2 = Hash{ .sha256 = Sha256Hash.init(.{}) };
    h2.update("hello");
    var out2 = [_]u8{0} ** (digest_len + 4);
    h2.finalToSlice(&out2);
    std.log.debug("Sha256Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out2)});
}

test "Hash.Sha384" {
    var h = Hash{ .sha384 = Sha384Hash.init(.{}) };
    h.update("hello");
    const digest_len = Sha384Hash.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(digest_len, bytes_written);
    std.log.debug("Sha384Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});
}

test "PrivateKey.sign" {
    testing.log_level = .debug;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;
    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const allocator = testing.allocator;

    const cert_pem = @embedFile("../../tests/p256-self-signed.crt.pem");
    const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");
    var cert = try x509KeyPair(allocator, cert_pem, key_pem);
    defer cert.deinit(allocator);

    const signed = "\x0d\x7a\x45\xfc\x76\xfe\xd7\xde\x30\xa5\xbb\x93\x71\x61\x16\x9f\x96\x20\x26\x59\x7f\x70\x8a\x1c\xb9\x2b\x7d\xff\xac\x15\xad\x43";
    const want = "\x30\x45\x02\x20\x4b\x33\xe6\x66\x13\xd2\x30\xd6\xe0\x7a\x2c\xc4\x03\x0e\xcc\xbc\xad\x41\xd4\x81\x57\x9b\x33\xb0\x99\x10\x04\x5f\x2d\xb8\x19\x91\x02\x21\x00\xe0\xe7\x1f\x24\x51\xcb\xc1\xc3\x08\xaf\xad\x3b\xb0\x4a\x7f\x3b\x6d\xdb\x58\x72\xae\x3a\xf2\x18\x93\xc5\x6e\xcc\x12\x83\x23\x3b";

    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);
    const sig = try cert.private_key.?.ecdsa.sign(allocator, rand.random(), signed, .{});
    defer allocator.free(sig);
    try testing.expectEqualSlices(u8, want, sig);
}
