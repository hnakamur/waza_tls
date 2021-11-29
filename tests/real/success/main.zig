const std = @import("std");

const simple_get = @import("simple_get.zig");
const long_content = @import("long_content.zig");
const long_header = @import("long_header.zig");

comptime {
    std.testing.refAllDecls(@This());
}
