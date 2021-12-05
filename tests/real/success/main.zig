const std = @import("std");

const graceful_shutdown = @import("graceful_shutdown.zig");
const long_content = @import("long_content.zig");
const long_header = @import("long_header.zig");
const reuse_conn_slot = @import("reuse_conn_slot.zig");
const simple_get = @import("simple_get.zig");

const proxy_simple_get = @import("proxy_simple_get.zig");
const proxy_two_reqs = @import("proxy_two_reqs.zig");

comptime {
    std.testing.refAllDecls(@This());
}
