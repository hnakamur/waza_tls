const std = @import("std");

const client_recv_timeout = @import("client_recv_timeout.zig");
const connection_refused = @import("connection_refused.zig");
const connection_timedout = @import("connection_timedout.zig");

const drop_server_recv = @import("drop_server_recv.zig");
const too_long_req_hdr = @import("too_long_req_hdr.zig");
const too_long_req_method = @import("too_long_req_method.zig");
const too_long_req_uri = @import("too_long_req_uri.zig");

comptime {
    std.testing.refAllDecls(@This());
}
