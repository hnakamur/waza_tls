const std = @import("std");

const _ = @import("client_handler.zig");

comptime {
    std.testing.refAllDecls(@This());
}
