const std = @import("std");
const mem = std.mem;
const Conn = @import("conn.zig").Conn;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;

pub const ServerHandshakeStateTls13 = struct {
    conn: *Conn,
    client_hello: ClientHelloMsg,
    hello: ?ServerHelloMsg = null,
    master_secret: ?[]const u8 = null,
    cert_chain: ?*CertificateChain = null,

    pub fn init(conn: *Conn, client_hello: ClientHelloMsg) ServerHandshakeStateTls13 {
        return .{ .conn = conn, .client_hello = client_hello };
    }

    pub fn deinit(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) void {
        self.client_hello.deinit(allocator);
        if (self.hello) |*hello| hello.deinit(allocator);
        if (self.master_secret) |s| allocator.free(s);
    }

    pub fn handshake(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        _ = self;
        _ = allocator;
        @panic("not implemented yet");
    }
};
