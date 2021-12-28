const std = @import("std");
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;

pub const FinishedHash = struct {

    // In TLS 1.2, a full buffer is sadly required.
    buffer: ?[]const u8 = null,

    version: ProtocolVersion,
};

test "FinishedHash" {
    std.debug.print("FinishedHash test\n", .{});
}
