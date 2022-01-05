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
            else => @panic("not implemented yet"),
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
        const base_point_curve = Curve25519.fromBytes(Curve25519.basePoint.toBytes());
        const pub_key_curve = try base_point_curve.clampedMul(priv_key);
        const pub_key = pub_key_curve.toBytes();
        return X25519Parameters{
            .private_key = priv_key,
            .public_key = pub_key,
        };
    }

    fn sharedKey(self: *const X25519Parameters, allocator: mem.Allocator, peer_public_key: []const u8) ![]const u8 {
        const peer_public_key_curve = Curve25519.fromBytes(peer_public_key[0..key_len].*);
        const curve = try peer_public_key_curve.clampedMul(self.private_key);
        return try allocator.dupe(u8, &curve.toBytes());
    }
};

const testing = std.testing;
const fmtx = @import("../fmtx.zig");

test "X25519Parameters.sharedKey" {
    const f = struct {
        fn f(want_shared_key: []const u8, private_key: []const u8, peer_public_key: []const u8) !void {
            const allocator = testing.allocator;

            const params = X25519Parameters{
                .private_key = private_key[0..X25519Parameters.key_len].*,
                .public_key = [_]u8{0} ** X25519Parameters.key_len,
            };
            const got_shared_key = try params.sharedKey(allocator, peer_public_key);
            defer allocator.free(got_shared_key);

            if (!mem.eql(u8, want_shared_key, got_shared_key)) {
                std.debug.print("shared_key mismatch for private_key={}, peer_public_key={}", .{
                    fmtx.fmtSliceHexEscapeLower(private_key),
                    fmtx.fmtSliceHexEscapeLower(peer_public_key),
                });
            }
            try testing.expectEqualSlices(u8, want_shared_key, got_shared_key);
        }
    }.f;

    try f(
        "\xaf\x6a\x4a\xfb\x0c\xc2\xb9\x5b\xd6\x14\x10\xc4\xcc\xe0\x9d\xc2\x64\xd8\x5f\x2b\x68\x97\x22\x5f\xcb\x43\xd0\x2e\x26\x14\x16\x64",
        "\x33\x45\x74\x4f\x10\x07\xcb\x25\x7b\x17\xe8\xea\xd7\x0d\x61\x7b\x4f\x8d\x35\x4e\xe3\x31\x25\x89\x70\x39\x50\x67\xb2\x33\x05\x01",
        "\xdf\x97\xc2\x1b\xf5\xef\xc0\x54\xe5\x49\x1c\x1f\xac\xfa\x20\x46\x7d\x3b\xf9\x29\x46\x47\x9a\x1e\x2a\xb4\x71\xec\x2f\x27\x26\x6b",
    );
    try f(
        "\xaf\x6a\x4a\xfb\x0c\xc2\xb9\x5b\xd6\x14\x10\xc4\xcc\xe0\x9d\xc2\x64\xd8\x5f\x2b\x68\x97\x22\x5f\xcb\x43\xd0\x2e\x26\x14\x16\x64",
        "\x2b\x22\xe2\xee\x83\xd6\xed\xa0\x75\x91\xe0\xff\xaf\xc7\xb6\x6c\xd1\x7c\x3e\xf6\x2c\xd3\x42\x89\x5d\x95\xb5\xa5\xdc\x5f\x5e\x5d",
        "\x92\x70\x74\x87\x14\x66\xbe\x34\x78\xdb\xab\x9d\x86\x08\x5e\xc2\xb7\x66\xda\x51\xa6\x24\x85\x24\x93\x09\xc3\xf1\x0f\x87\x10\x36",
    );
}

const NistParameters = struct {
    curve: CurveId,
};
