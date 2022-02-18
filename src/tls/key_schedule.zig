const std = @import("std");
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const P256 = std.crypto.ecc.P256;
const CurveId = @import("handshake_msg.zig").CurveId;
const elliptic = @import("elliptic.zig");
const ecdsa = @import("ecdsa.zig");
const bigint = @import("big_int.zig");

pub const EcdheParameters = union(enum) {
    x25519: X25519Parameters,
    nist: NistParameters,

    pub fn generate(
        allocator: mem.Allocator,
        curve_id: CurveId,
        random: std.rand.Random,
    ) !EcdheParameters {
        return switch (curve_id) {
            .x25519 => EcdheParameters{
                .x25519 = try X25519Parameters.generate(random),
            },
            else => EcdheParameters{
                .nist = try NistParameters.generate(allocator, curve_id, random),
            },
        };
    }

    pub fn deinit(self: *EcdheParameters, allocator: mem.Allocator) void {
        switch (self.*) {
            .nist => |*p| p.deinit(allocator),
            else => {},
        }
    }

    pub fn sharedKey(self: *const EcdheParameters, allocator: mem.Allocator, peer_public_key: []const u8) ![]const u8 {
        return switch (self.*) {
            .x25519 => |*k| try k.sharedKey(allocator, peer_public_key),
            .nist => |*k| try k.sharedKey(allocator, peer_public_key),
        };
    }

    pub fn publicKey(self: *const EcdheParameters) []const u8 {
        return switch (self.*) {
            .x25519 => |*k| k.publicKey(),
            .nist => |*k| k.publicKey(),
        };
    }
};

const X25519Parameters = struct {
    const key_len = 32;
    const Curve25519 = crypto.ecc.Curve25519;

    private_key: [key_len]u8,
    public_key: [key_len]u8,
    shared_key: [key_len]u8 = undefined,
    curve: CurveId = .x25519,

    fn generate(random: std.rand.Random) !X25519Parameters {
        var priv_key: [key_len]u8 = undefined;
        random.bytes(&priv_key);
        const base_point_curve = Curve25519.fromBytes(Curve25519.basePoint.toBytes());
        const pub_key_curve = try base_point_curve.clampedMul(priv_key);
        const pub_key = pub_key_curve.toBytes();
        return X25519Parameters{
            .private_key = priv_key,
            .public_key = pub_key,
        };
    }

    fn sharedKey(
        self: *const X25519Parameters,
        allocator: mem.Allocator,
        peer_public_key: []const u8,
    ) ![]const u8 {
        const peer_public_key_curve = Curve25519.fromBytes(peer_public_key[0..key_len].*);
        const curve = try peer_public_key_curve.clampedMul(self.private_key);
        return try allocator.dupe(u8, &curve.toBytes());
    }

    fn publicKey(self: *const X25519Parameters) []const u8 {
        return &self.public_key;
    }
};

const NistParameters = struct {
    curve_id: CurveId,
    priv: []const u8,
    x: math.big.int.Managed,
    y: math.big.int.Managed,
    public_key: []const u8,

    pub fn generate(
        allocator: mem.Allocator,
        curve_id: CurveId,
        random: std.rand.Random,
    ) !NistParameters {
        var x = try math.big.int.Managed.init(allocator);
        errdefer x.deinit();
        var y = try math.big.int.Managed.init(allocator);
        errdefer y.deinit();
        var priv = try elliptic.generateKey(allocator, curve_id, random, &x, &y);
        errdefer allocator.free(priv);
        const public_key = try marshalCurve(allocator, curve_id, x, y);
        return NistParameters{
            .curve_id = curve_id,
            .priv = priv,
            .x = x,
            .y = y,
            .public_key = public_key,
        };
    }

    pub fn deinit(self: *NistParameters, allocator: mem.Allocator) void {
        allocator.free(self.priv);
        self.x.deinit();
        self.y.deinit();
        allocator.free(self.public_key);
    }

    fn sharedKey(
        self: *const NistParameters,
        allocator: mem.Allocator,
        peer_public_key: []const u8,
    ) ![]const u8 {
        switch (self.curve_id) {
            .secp256r1 => {
                const pub_key = try ecdsa.PublicKeyP256.init(peer_public_key);
                const p = try pub_key.point.mul(self.priv[0..P256.scalar.encoded_length].*, .Big);
                return try allocator.dupe(u8, &p.affineCoordinates().x.toBytes(.Big));
            },
            else => @panic("not implemented yet"),
        }
    }

    fn publicKey(self: *const NistParameters) []const u8 {
        return self.public_key;
    }
};

fn marshalCurve(
    allocator: mem.Allocator,
    curve_id: CurveId,
    x: math.big.int.Managed,
    y: math.big.int.Managed,
) mem.Allocator.Error![]const u8 {
    const byte_len: usize = switch (curve_id) {
        .secp256r1 => P256.scalar.encoded_length,
        else => @panic("not implemented yet"),
    };

    var ret = try allocator.alloc(u8, 1 + 2 * byte_len);
    ret[0] = 4; // uncompressed
    bigint.fillBytes(x.toConst(), ret[1 .. 1 + byte_len]);
    bigint.fillBytes(y.toConst(), ret[1 + byte_len .. 1 + 2 * byte_len]);
    return ret;
}

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

test "NistParameters.sharedKey" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    var p1 = try NistParameters.generate(allocator, .secp256r1, std.crypto.random);
    defer p1.deinit(allocator);
    var p2 = try NistParameters.generate(allocator, .secp256r1, std.crypto.random);
    defer p2.deinit(allocator);

    var k1 = try p1.sharedKey(allocator, p2.publicKey());
    defer allocator.free(k1);
    var k2 = try p2.sharedKey(allocator, p1.publicKey());
    defer allocator.free(k2);
    try testing.expectEqualSlices(u8, k1, k2);
}
