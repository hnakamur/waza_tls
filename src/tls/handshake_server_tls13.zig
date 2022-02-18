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
        // For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
        try self.processClientHello(allocator);
    }

    pub fn processClientHello(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        // if (self.client_hello.supported_versions) {

        // }
        _ = self;
        _ = allocator;
        // self.hello = ServerHelloMsg{
        //     // TLS 1.3 froze the ServerHello.legacy_version field, and uses
        //     // supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
        //     .vers = .v1_2,
        //     .supported_version = self.conn.version.?,
        // };
        @panic("not implemented yet");
    }
};
