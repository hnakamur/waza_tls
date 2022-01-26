const std = @import("std");
const math = std.math;
const mem = std.mem;
const bigint = @import("big_int.zig");
const CurveId = @import("handshake_msg.zig").CurveId;

pub const Curve = struct {
    pub const Params = struct {
        // p: math.big.int.Const,
        // n: math.big.int.Const,
        // b: math.big.int.Const,
        // gx: math.big.int.Const,
        // gy: math.big.int.Const,
        bit_size: usize,
        name: []const u8 = "",
        curve_id: ?CurveId,
    };
    params: Params,

    pub fn deinit(self: *Curve, allocator: mem.Allocator) void {
        // bigint.deinitConst(self.p);
        // bigint.deinitConst(self.n);
        // bigint.deinitConst(self.b);
        // bigint.deinitConst(self.gx);
        // bigint.deinitConst(self.gy);
        if (self.name.len > 0) allocator.free(self.name);
    }
};

pub fn p256() Curve {
    return .{
        .params = .{
            .curve_id = .secp256r1,
            .bit_size = 256,
        },
    };
}

pub fn p384() Curve {
    return .{
        .params = .{
            .curve_id = .secp384r1,
            .bit_size = 384,
        },
    };
}

pub fn p521() Curve {
    return .{
        .params = .{
            .curve_id = .secp521r1,
            .bit_size = 521,
        },
    };
}
