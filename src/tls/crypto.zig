const std = @import("std");
const mem = std.mem;
const asn1 = @import("asn1.zig");
const rsa = @import("rsa.zig");

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
};

pub const PrivateKey = union(PublicKeyAlgorithm) {
    unknown: void,
    rsa: rsa.PrivateKey,
    dsa: void,
    ecdsa: void,
    ed25519: Ed25519PrivateKey,

    pub fn deinit(self: *PublicKey, allocator: mem.Allocator) void {
        switch (self.*) {
            .rsa => |*k| k.deinit(allocator),
            else => {},
        }
    }
};

const Ed25519PrivateKey = struct {
    raw: []const u8,
};
