const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const CurveId = @import("handshake_msg.zig").CurveId;

pub const EcdheParameters = union(enum) {
    x25519: X25519Parameters,
    nist: NistParameters,

    pub fn generate(curve: CurveId) !EcdheParameters {
        switch (curve) {
            .x25519 => return EcdheParameters{
                .x25519 = try X25519Parameters.generate(),
            },
            // else => @panic("not implemented yet"),
        }
    }

    pub fn sharedKey(self: *const EcdheParameters, allocator: mem.Allocator, peer_public_key: []const u8) ![]const u8 {
        switch (self.*) {
            .x25519 => |*x| return try x.sharedKey(allocator, peer_public_key),
            else => @panic("not implemented yet"),
        }
    }

    pub fn publicKey(self: *const EcdheParameters) []const u8 {
        switch (self.*) {
            .x25519 => |*x| return &x.public_key,
            else => @panic("not implemented yet"),
        }
    }
};

const X25519Parameters = struct {
    const key_len = 32;
    const Curve25519 = crypto.ecc.Curve25519;

    private_key: [key_len]u8,
    public_key: [key_len]u8,
    shared_key: [key_len]u8 = undefined,
    curve: CurveId = .x25519,

    fn generate() !X25519Parameters {
        var priv_key: [key_len]u8 = undefined;
        crypto.random.bytes(&priv_key);
        const priv_key_curve = Curve25519.fromBytes(priv_key);
        const pub_key_curve = try priv_key_curve.clampedMul(Curve25519.basePoint.toBytes());
        const pub_key = pub_key_curve.toBytes();
        return X25519Parameters{
            .private_key = priv_key,
            .public_key = pub_key,
        };
    }

    fn sharedKey(self: *const X25519Parameters, allocator: mem.Allocator, peer_public_key: []const u8) ![]const u8 {
        const priv_key_curve = Curve25519.fromBytes(self.private_key);
        const curve = try priv_key_curve.clampedMul(peer_public_key[0..key_len].*);
        return try allocator.dupe(u8, &curve.toBytes());
    }
};

const testing = std.testing;
const fmt = std.fmt;

test "X25519Parameters" {
    testing.log_level = .debug;

    const params = try X25519Parameters.generate();

    var pub_key: [X25519Parameters.key_len]u8 = undefined;
    crypto.random.bytes(&pub_key);

    const allocator = testing.allocator;
    const shared_key = try params.sharedKey(allocator, &pub_key);
    defer allocator.free(shared_key);

    std.log.debug("shared_key={}", .{fmt.fmtSliceHexLower(shared_key)});
}

const NistParameters = struct {
    curve: CurveId,
};
