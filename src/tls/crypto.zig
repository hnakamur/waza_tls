const std = @import("std");
const mem = std.mem;
const asn1 = @import("asn1.zig");
const rsa = @import("rsa.zig");
const parsePkcs1PrivateKey = @import("pkcs1.zig").parsePkcs1PrivateKey;
const HashType = @import("auth.zig").HashType;

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
    ecdsa: void,
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
        try std.fmt.format(writer, "PublicKey{{ type = {s} }}", .{@tagName(self)});
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
        } else |_| {
            @panic("not implemented yet");
        }
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
