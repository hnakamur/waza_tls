const std = @import("std");
const P256 = std.crypto.ecc.P256;
const math = std.math;
const mem = std.mem;
const bigint = @import("big_int.zig");
const CurveId = @import("handshake_msg.zig").CurveId;

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
