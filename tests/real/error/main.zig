const std = @import("std");

const client_recv_timeout = @import("client_recv_timeout.zig");
const connection_refused = @import("connection_refused.zig");
const connection_timedout = @import("connection_timedout.zig");

const bad_req_content_len = @import("bad_req_content_len.zig");
const bad_req_http_version = @import("bad_req_http_version.zig");
const bad_resp_content_len = @import("bad_resp_content_len.zig");
const bad_resp_http_version = @import("bad_resp_http_version.zig");
const drop_server_recv = @import("drop_server_recv.zig");
const http09_unsupported = @import("http09_unsupported.zig");
const http2_unsupported = @import("http2_unsupported.zig");
const too_long_req_hdr = @import("too_long_req_hdr.zig");
const too_long_req_method = @import("too_long_req_method.zig");
const too_long_req_uri = @import("too_long_req_uri.zig");

comptime {
    std.testing.refAllDecls(@This());
}
