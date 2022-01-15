const std = @import("std");
const mem = std.mem;
const ClientHandshakeState = @import("handshake_client.zig").ClientHandshakeState;
const ServerHandshakeState = @import("handshake_server.zig").ServerHandshakeState;

pub const Role = enum {
    client,
    server,
};

pub const HandshakeState = union(Role) {
    client: ClientHandshakeState,
    server: ServerHandshakeState,

    pub fn deinit(self: *HandshakeState, allocator: mem.Allocator) void {
        switch(self.*) {
            .client => |*hs| hs.deinit(allocator),
            .server => |*hs| hs.deinit(allocator),
        }
    }
};
