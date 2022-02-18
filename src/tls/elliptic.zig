const std = @import("std");
const P256 = std.crypto.ecc.P256;
const math = std.math;
const mem = std.mem;
const bigint = @import("big_int.zig");
const CurveId = @import("handshake_msg.zig").CurveId;

// value is copied from Fe.field_order in pcurves/p256/scalar.zig
pub const p256_param_n = 115792089210356248762697446949407573529996955224135760342422259061068512044369;

pub fn p256ParamN(allocator: mem.Allocator) !math.big.int.Managed {
    return try math.big.int.Managed.initSet(allocator, p256_param_n);
}

pub fn generateKey(
    allocator: mem.Allocator,
    curve_id: CurveId,
    rand: std.rand.Random,
    out_x: *math.big.int.Managed,
    out_y: *math.big.int.Managed,
) ![]const u8 {
    const mask = [_]u8{ 0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f };

    var n = try math.big.int.Managed.init(allocator);
    defer n.deinit();
    switch (curve_id) {
        .secp256r1 => try n.set(p256_param_n),
        else => @panic("not implemented yet"),
    }

    const bit_size = n.bitCountTwosComp();
    const byte_len = math.divCeil(usize, bit_size, @bitSizeOf(u8)) catch unreachable;
    std.log.debug("elliptic.generateKey, bit_size={}, byte_len={}", .{ bit_size, byte_len });

    var priv = try allocator.alloc(u8, byte_len);
    errdefer allocator.free(priv);

    while (true) {
        rand.bytes(priv);

        // We have to mask off any excess bits in the case that the size of the
        // underlying field is not a whole number of bytes.
        priv[0] &= mask[bit_size % 8];
        // This is because, in tests, rand will return all zeros and we don't
        // want to get the point at infinity and loop forever.
        priv[1] ^= 0x42;
        std.log.debug("elliptic.generateKey, priv={}", .{std.fmt.fmtSliceHexLower(priv)});

        // If the scalar is out of range, sample another random number.
        var priv_int = try bigint.managedFromBytes(allocator, priv, .Big);
        defer priv_int.deinit();

        // If the scalar is out of range, sample another random number.
        if (priv_int.order(n).compare(.gte)) {
            continue;
        }

        switch (curve_id) {
            .secp256r1 => {
                const p = try P256.basePoint.mulPublic(priv[0..P256.scalar.encoded_length].*, .Big);
                const pa = p.affineCoordinates();
                try bigint.setManagedBytes(out_x, &pa.x.toBytes(.Little), .Little);
                try bigint.setManagedBytes(out_y, &pa.y.toBytes(.Little), .Little);
            },
            else => @panic("not implemented yet"),
        }
        break;
    }

    return priv;
}

pub const Curve = union(CurveId) {
    secp256r1: P256,
    secp384r1: P384,
    secp521r1: void,
    x25519: void,

    pub fn init(curve_id: CurveId, data: []const u8) error{InvalidCurvePoints}!Curve {
        switch (curve_id) {
            .secp256r1 => {
                if (data.len != 2 * P256.Fe.encoded_length) {
                    return error.InvalidCurvePoints;
                }
                const c = P256.fromSerializedAffineCoordinates(
                    data[0..P256.Fe.encoded_length].*,
                    data[P256.Fe.encoded_length..][0..P256.Fe.encoded_length].*,
                    .Big,
                ) catch return error.InvalidCurvePoints;
                return Curve{ .secp256r1 = c };
            },
            .secp384r1 => return Curve{ .secp384r1 = .{} },
            else => @panic("not implemented yet"),
        }
    }

    pub fn format(
        self: Curve,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        switch (self) {
            .secp256r1 => |c| {
                var x_bytes: []const u8 = undefined;
                x_bytes.ptr = @intToPtr([*]const u8, @ptrToInt(&c.x));
                x_bytes.len = P256.Fe.encoded_length;
                var y_bytes: []const u8 = undefined;
                y_bytes.ptr = @intToPtr([*]const u8, @ptrToInt(&c.y));
                y_bytes.len = P256.Fe.encoded_length;
                try std.fmt.format(writer, "Curve{{ .secp256r1 = P256{{ x = {}, y = {} }} }}", .{
                    std.fmt.fmtSliceHexLower(x_bytes),
                    std.fmt.fmtSliceHexLower(y_bytes),
                });
            },
            else => {
                try std.fmt.format(writer, "Curve{{ .{s} = ... }}", .{@tagName(self)});
            },
        }
    }
};

const P384 = struct {
    not_implemented: usize = 0,
};

const testing = std.testing;
const assert = std.debug.assert;

test "elliptic.generateKey" {
    testing.log_level = .err;
    const allocator = testing.allocator;
    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);

    var x = try math.big.int.Managed.init(allocator);
    defer x.deinit();
    var y = try math.big.int.Managed.init(allocator);
    defer y.deinit();
    var priv = try generateKey(allocator, .secp256r1, rand.random(), &x, &y);
    defer allocator.free(priv);

    const want_priv = "\xc4\x9a\x67\x64\x3b\xf8\xdc\x07\xd4\xb0\x0b\x3b\x4c\x36\x21\x1b\x57\xa6\x9d\xf9\x78\x78\x6a\xfd\xe9\xea\x94\x88\x85\xfd\x59\xfd";
    const want_x = "\xb8\xe1\xb9\x07\xbd\x87\xf9\xdb\x37\x26\x63\x37\x40\x4a\x46\x1e\x18\x80\x16\xb8\x4c\x8c\x86\x39\xff\x38\xba\xe6\xee\xcd\x35\x43";
    const want_y = "\x5a\x7f\x1e\x42\xce\x56\x76\x01\xf7\x7d\x1f\xc1\x8a\xa4\x0d\x64\x5f\x03\x89\x5c\x15\x20\x43\xb1\x5d\x42\x3a\xb1\xa5\xf9\xb5\x19";

    try testing.expectEqualSlices(u8, want_priv, priv);

    const got_x = try bigint.managedToBytesBig(allocator, x);
    defer allocator.free(got_x);
    try testing.expectEqualSlices(u8, want_x, got_x);

    const got_y = try bigint.managedToBytesBig(allocator, y);
    defer allocator.free(got_y);
    try testing.expectEqualSlices(u8, want_y, got_y);
}

test "p256mult" {
    const f = struct {
        fn f(
            hex_k: []const u8,
            hex_x_in: []const u8,
            hex_y_in: []const u8,
            hex_x_out: []const u8,
            hex_y_out: []const u8,
        ) !void {
            assert(hex_k.len == 64 and hex_x_in.len == 64 and hex_y_in.len == 64 and
                hex_x_out.len == 64 and hex_y_out.len == 64);

            var k: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&k, hex_k);
            var x_in: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&x_in, hex_x_in);
            var y_in: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&y_in, hex_y_in);
            var x_out: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&x_out, hex_x_out);
            var y_out: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&y_out, hex_y_out);

            var p = try P256.fromSerializedAffineCoordinates(x_in, y_in, .Big);
            const r = try p.mulPublic(k, .Big);

            var want = try P256.fromSerializedAffineCoordinates(x_out, y_out, .Big);
            try testing.expect(r.equivalent(want));

            const r_c = r.affineCoordinates();
            try testing.expectEqualSlices(u8, &x_out, &r_c.x.toBytes(.Big));
            try testing.expectEqualSlices(u8, &y_out, &r_c.y.toBytes(.Big));
        }
    }.f;

    try f(
        "2a265f8bcbdcaf94d58519141e578124cb40d64a501fba9c11847b28965bc737",
        "023819813ac969847059028ea88a1f30dfbcde03fc791d3a252c6b41211882ea",
        "f93e4ae433cc12cf2a43fc0ef26400c0e125508224cdb649380f25479148a4ad",
        "4d4de80f1534850d261075997e3049321a0864082d24a917863366c0724f5ae3",
        "a22d2b7f7818a3563e0f7a76c9bf0921ac55e06e2e4d11795b233824b1db8cc0",
    );
    try f(
        "313f72ff9fe811bf573176231b286a3bdb6f1b14e05c40146590727a71c3bccd",
        "cc11887b2d66cbae8f4d306627192522932146b42f01d3c6f92bd5c8ba739b06",
        "a2f08a029cd06b46183085bae9248b0ed15b70280c7ef13a457f5af382426031",
        "831c3f6b5f762d2f461901577af41354ac5f228c2591f84f8a6e51e2e3f17991",
        "93f90934cd0ef2c698cc471c60a93524e87ab31ca2412252337f364513e43684",
    );
}
