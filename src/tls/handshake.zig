const std = @import("std");
const mem = std.mem;
const ClientHandshake = @import("handshake_client.zig").ClientHandshake;
const ServerHandshake = @import("handshake_server.zig").ServerHandshake;

pub const Role = enum {
    client,
    server,
};

pub const Handshake = union(Role) {
    client: ClientHandshake,
    server: ServerHandshake,

    pub fn deinit(self: *Handshake, allocator: mem.Allocator) void {
        switch(self.*) {
            .client => |*hs| hs.deinit(allocator),
            .server => |*hs| hs.deinit(allocator),
        }
    }
};
