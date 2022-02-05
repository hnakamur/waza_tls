const std = @import("std");
const elliptic = @import("elliptic.zig");
const CurveId = @import("handshake_msg.zig").CurveId;

pub const PublicKey = struct {
    curve: elliptic.Curve,

    pub fn init(curve_id: CurveId, data: []const u8) error{InvalidCurvePoints}!PublicKey {
        return PublicKey{ .curve = try elliptic.Curve.init(curve_id, data) };
    }
};
