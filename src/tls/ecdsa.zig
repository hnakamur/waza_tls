const std = @import("std");
const mem = std.mem;
const P256 = std.crypto.ecc.P256;

const CurveId = @import("handshake_msg.zig").CurveId;
const asn1 = @import("asn1.zig");
const bigint = @import("big_int.zig");
const crypto = @import("crypto.zig");
const pem = @import("pem.zig");
const fmtx = @import("../fmtx.zig");

pub const PublicKey = union(CurveId) {
    secp256r1: PublicKeyP256,
    secp384r1: void,
    secp521r1: void,
    x25519: void,

    pub fn init(curve_id: CurveId, data: []const u8) !PublicKey {
        // std.log.debug(
        //     "ecdsa.PublicKey.init curve_id={}, data={}",
        //     .{ curve_id, fmtx.fmtSliceHexColonLower(data) },
        // );
        switch (curve_id) {
            .secp256r1 => return PublicKey{ .secp256r1 = try PublicKeyP256.init(data) },
            .secp384r1 => return PublicKey{ .secp384r1 = .{} },
            else => @panic("not implemented yet"),
        }
    }
};

pub const PrivateKey = union(CurveId) {
    secp256r1: PrivateKeyP256,
    secp384r1: void,
    secp521r1: void,
    x25519: void,

    pub fn parseAsn1(
        allocator: mem.Allocator,
        der: []const u8,
        oid: ?asn1.ObjectIdentifier,
    ) !PrivateKey {
        var input = asn1.String.init(der);
        var s = try input.readAsn1(.sequence);

        const version = try s.readAsn1Uint64();
        const ec_priv_key_version = 1;
        if (version != ec_priv_key_version) {
            return error.UnsupportedEcPrivateKeyVersion;
        }

        var tag: asn1.TagAndClass = undefined;
        var s2 = try s.readAnyAsn1(&tag);
        const private_key_bytes = s2.bytes;

        const curve_id = if (oid) |oid2| blk: {
            break :blk CurveId.fromOid(oid2) orelse return error.UnsupportedEcPrivateKeyCurveOid;
        } else blk: {
            if (s.empty()) {
                return error.EcPrivateKeyCurveOidMissing;
            }
            s2 = try s.readAnyAsn1(&tag);
            var oid2 = try asn1.ObjectIdentifier.parse(allocator, &s2);
            defer oid2.deinit(allocator);
            break :blk CurveId.fromOid(oid2) orelse return error.UnsupportedEcPrivateKeyCurveOid;
        };

        return try PrivateKey.init(curve_id, private_key_bytes);
    }

    pub fn init(curve_id: CurveId, data: []const u8) !PrivateKey {
        switch (curve_id) {
            .secp256r1 => {
                if (data.len != P256.Fe.encoded_length) {
                    return error.InvalidPrivateKey;
                }
                return PrivateKey{
                    .secp256r1 = try PrivateKeyP256.init(data[0..P256.Fe.encoded_length].*),
                };
            },
            else => @panic("not implemented yet"),
        }
    }

    pub fn publicKey(self: *const PrivateKey) PublicKey {
        return switch (self.*) {
            .secp256r1 => |*k| PublicKey{ .secp256r1 = k.public_key },
            else => @panic("not implemented yet"),
        };
    }

    pub fn sign(
        self: *const PrivateKey,
        allocator: mem.Allocator,
        digest: []const u8,
        opts: crypto.SignOpts,
    ) ![]const u8 {
        return switch (self.*) {
            .secp256r1 => |*k| k.sign(allocator, digest, opts),
            else => @panic("not implemented yet"),
        };
    }
};

const PublicKeyP256 = struct {
    point: P256,

    pub fn init(data: []const u8) !PublicKeyP256 {
        const s = mem.trimLeft(u8, data, "\x00");
        const p = try P256.fromSec1(s);
        return PublicKeyP256{ .point = p };
    }

    pub fn format(
        self: PublicKeyP256,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        var x_bytes: []const u8 = undefined;
        x_bytes.ptr = @intToPtr([*]const u8, @ptrToInt(&self.point.x));
        x_bytes.len = P256.Fe.encoded_length;
        var y_bytes: []const u8 = undefined;
        y_bytes.ptr = @intToPtr([*]const u8, @ptrToInt(&self.point.y));
        y_bytes.len = P256.Fe.encoded_length;
        try std.fmt.format(writer, "PublicKeyP256{{ x = {}, y = {} }} }}", .{
            fmtx.fmtSliceHexColonLower(x_bytes),
            fmtx.fmtSliceHexColonLower(y_bytes),
        });
    }
};

const PrivateKeyP256 = struct {
    public_key: PublicKeyP256,
    d: [P256.Fe.encoded_length]u8,

    pub fn init(d: [P256.Fe.encoded_length]u8) !PrivateKeyP256 {
        const pub_key_point = try P256.basePoint.mulPublic(d, .Big);
        return PrivateKeyP256{ .public_key = .{ .point = pub_key_point }, .d = d };
    }

    pub fn sign(
        self: *const PrivateKeyP256,
        allocator: mem.Allocator,
        digest: []const u8,
        opts: crypto.SignOpts,
    ) ![]const u8 {
        _ = self;
        _ = allocator;
        _ = digest;
        _ = opts;
        @panic("not implemented yet");
    }

    pub fn format(
        self: PrivateKeyP256,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        var d_bytes: []const u8 = undefined;
        d_bytes.ptr = @intToPtr([*]const u8, @ptrToInt(&self.d));
        d_bytes.len = P256.Fe.encoded_length;
        try std.fmt.format(writer, "PrivateKeyP256{{ public_key = {}, d = {} }} }}", .{
            self.public_key,
            fmtx.fmtSliceHexColonLower(d_bytes),
        });
    }
};

const PublicKeyP384 = struct {
    not_implemented_yet: usize = 1,
};

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
fn randFieldElement(
    allocator: mem.Allocator,
    curve_id: CurveId,
    rand: std.rand.Random,
) !std.math.big.int.Const {
    const encoded_length = switch (curve_id) {
        .secp256r1 => P256.Fe.encoded_length,
        else => @panic("not implemented yet"),
    };

    // Note that for P-521 this will actually be 63 bits more than the order, as
    // division rounds down, but the extra bit is inconsequential.
    var b = try allocator.alloc(u8, encoded_length + 8);
    defer allocator.free(b);

    try rand.bytes(b);
    // bigint

    // params := c.Params()
    // b := make([]byte, params.BitSize/8+8) // TODO: use params.N.BitLen()
    // _, err = io.ReadFull(rand, b)
    // if err != nil {
    // 	return
    // }

    // k = new(big.Int).SetBytes(b)
    // n := new(big.Int).Sub(params.N, one)
    // k.Mod(k, n)
    // k.Add(k, one)
    // return
}

const testing = std.testing;

test "ecdsa.PrivateKey.parseAsn1" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");
    var offset: usize = 0;
    var key_block = try pem.Block.decode(allocator, key_pem, &offset);
    defer key_block.deinit(allocator);
    const key_der = key_block.bytes;
    const key = try PrivateKey.parseAsn1(allocator, key_der, null);
    std.log.debug("key={}", .{key});
}
