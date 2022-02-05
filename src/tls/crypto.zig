const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const asn1 = @import("asn1.zig");
const rsa = @import("rsa.zig");
const ecdsa = @import("ecdsa.zig");
const parsePkcs1PrivateKey = @import("pkcs1.zig").parsePkcs1PrivateKey;
const HashType = @import("auth.zig").HashType;

pub const Hash = union(HashType) {
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

    pub fn writeFinal(self: *Hash, writer: anytype) !usize {
        return switch (self.*) {
            .sha256 => |*s| try s.writeFinal(writer),
            .sha384 => |*s| try s.writeFinal(writer),
            .sha512 => |*s| try s.writeFinal(writer),
            .sha1 => |*s| try s.writeFinal(writer),
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn finalToSlice(self: *Hash, out: []u8) usize {
        return switch (self.*) {
            .sha256 => |*s| s.finalToSlice(out),
            .sha384 => |*s| s.finalToSlice(out),
            .sha512 => |*s| s.finalToSlice(out),
            .sha1 => |*s| s.finalToSlice(out),
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn digestLength(self: *const Hash) usize {
        return switch (self.*) {
            .sha256 => |s| s.digestLength(),
            .sha384 => |s| s.digestLength(),
            .sha512 => |s| s.digestLength(),
            .sha1 => |s| s.digestLength(),
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn allocFinal(self: *Hash, allocator: mem.Allocator) ![]const u8 {
        return switch (self.*) {
            .sha256 => |*s| try s.allocFinal(allocator),
            .sha384 => |*s| try s.allocFinal(allocator),
            .sha512 => |*s| try s.allocFinal(allocator),
            .sha1 => |*s| try s.allocFinal(allocator),
            else => @panic("Unsupported HashType"),
        };
    }
};

pub const Sha256Hash = HashAdapter(std.crypto.hash.sha2.Sha256);
pub const Sha384Hash = HashAdapter(std.crypto.hash.sha2.Sha384);
pub const Sha512Hash = HashAdapter(std.crypto.hash.sha2.Sha512);
pub const Sha1Hash = HashAdapter(std.crypto.hash.Sha1);

fn HashAdapter(comptime HashImpl: type) type {
    return struct {
        const Self = @This();

        pub const digest_length = HashImpl.digest_length;
        inner_hash: HashImpl,

        pub fn init(options: HashImpl.Options) Self {
            return .{ .inner_hash = HashImpl.init(options) };
        }

        pub fn update(self: *Self, b: []const u8) void {
            self.inner_hash.update(b);
        }

        pub fn writeFinal(self: *Self, writer: anytype) !usize {
            var d_out: [HashImpl.digest_length]u8 = undefined;
            self.inner_hash.final(&d_out);
            try writer.writeAll(&d_out);
            return d_out.len;
        }

        pub fn finalToSlice(self: *Self, out: []u8) usize {
            const len = HashImpl.digest_length;
            self.inner_hash.final(out[0..len]);
            return len;
        }

        pub fn digestLength(self: *const Self) usize {
            _ = self;
            return digest_length;
        }

        pub fn allocFinal(self: *Self, allocator: mem.Allocator) ![]const u8 {
            var sum = try allocator.alloc(u8, digest_length);
            const sum_len = self.finalToSlice(sum);
            assert(sum_len == digest_length);
            return sum;
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
    hash_type: HashType,
};

pub const PrivateKey = union(PublicKeyAlgorithm) {
    unknown: void,
    rsa: rsa.PrivateKey,
    dsa: void,
    ecdsa: void,
    ed25519: Ed25519PrivateKey,

    pub fn parse(allocator: mem.Allocator, der: []const u8) !PrivateKey {
        if (parsePkcs1PrivateKey(allocator, der)) |rsa_key| {
            return PrivateKey{ .rsa = rsa_key };
        } else |_| {}

        @panic("not implemented yet");
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
            .rsa => |*k| try k.sign(allocator, digest, opts),
            .ed25519 => |*k| try k.sign(allocator, digest, opts),
            else => @panic("not implemented yet"),
        };
    }
};

const Ed25519PrivateKey = struct {
    raw: []const u8,

    pub fn sign(
        self: *const Ed25519PrivateKey,
        allocator: mem.Allocator,
        digest: []const u8,
        opts: SignOpts,
    ) ![]const u8 {
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
    const bytes_written2 = h2.finalToSlice(&out2);
    try testing.expectEqual(digest_len, bytes_written2);
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
