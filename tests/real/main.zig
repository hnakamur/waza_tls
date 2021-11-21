const std = @import("std");

const _ = @import("client_server.zig");

comptime {
    std.testing.refAllDecls(@This());
}
