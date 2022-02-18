const std = @import("std");
const mem = std.mem;
const Conn = @import("conn.zig").Conn;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const EcdheParameters = @import("key_schedule.zig").EcdheParameters;
const CipherSuiteTls13 = @import("cipher_suites.zig").CipherSuiteTls13;

pub const ClientHandshakeStateTls13 = struct {
    conn: *Conn,
    hello: ClientHelloMsg,
    server_hello: ServerHelloMsg,
    ecdhe_params: EcdheParameters,

    suite: ?*const CipherSuiteTls13 = null,
    master_secret: ?[]const u8 = null,

    pub fn init(
        conn: *Conn,
        client_hello: ClientHelloMsg,
        server_hello: ServerHelloMsg,
        ecdhe_params: EcdheParameters,
    ) ClientHandshakeStateTls13 {
        return .{
            .hello = client_hello,
            .server_hello = server_hello,
            .conn = conn,
            .ecdhe_params = ecdhe_params,
        };
    }

    pub fn deinit(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) void {
        self.hello.deinit(allocator);
        self.server_hello.deinit(allocator);
        if (self.master_secret) |s| allocator.free(s);
    }

    pub fn handshake(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        _ = self;
        _ = allocator;
        @panic("not implemented yet");
    }
};
