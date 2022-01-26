const std = @import("std");
const math = std.math;
const mem = std.mem;
const bigint = @import("big_int.zig");
const elliptic = @import("elliptic.zig");
const CurveId = @import("handshake_msg.zig").CurveId; 

pub const PublicKey = struct {
    curve: elliptic.Curve,
    x: math.big.int.Const,
    y: math.big.int.Const,

    pub fn deinit(self: *PublicKey, allocator: mem.Allocator) void {
        // self.curve.deinit(allocator);
        bigint.deinitConst(self.x, allocator);
        bigint.deinitConst(self.y, allocator);
    }

    pub fn format(
        self: PublicKey,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = try writer.write("PublicKey{ curve = ");
        try std.fmt.format(writer, "{}", .{self.curve});
        _ = try writer.write(", x = ");
        try bigint.formatConst(self.x, fmt, options, writer);
        _ = try writer.write(", y = ");
        try bigint.formatConst(self.x, fmt, options, writer);
        _ = try writer.write(" }");
    }
};
