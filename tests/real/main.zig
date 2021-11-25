const std = @import("std");

const @"error" = @import("error/main.zig");
const success = @import("success/main.zig");

comptime {
    std.testing.refAllDecls(@This());
}
