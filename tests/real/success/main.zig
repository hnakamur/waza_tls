const std = @import("std");

const graceful_shutdown = @import("graceful_shutdown.zig");
const long_content = @import("long_content.zig");
const long_header = @import("long_header.zig");
const simple_get = @import("simple_get.zig");

comptime {
    std.testing.refAllDecls(@This());
}
