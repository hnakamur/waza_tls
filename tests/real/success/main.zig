const std = @import("std");

const _ = @import("simple_get.zig");

comptime {
    std.testing.refAllDecls(@This());
}
