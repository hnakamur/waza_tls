const std = @import("std");
const mem = std.mem;
const HandshakeMsg = @import("handshake_msg.zig").HandshakeMsg;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const freeOptionalField = @import("handshake_msg.zig").freeOptionalField;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const ClientKeyExchangeMsg = @import("handshake_msg.zig").ClientKeyExchangeMsg;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const cipherSuiteById = @import("cipher_suites.zig").cipherSuiteById;
const FakeConnection = @import("fake_connection.zig").FakeConnection;
const x509 = @import("x509.zig");
const prfForVersion = @import("prf.zig").prfForVersion;
const master_secret_length = @import("prf.zig").master_secret_length;
const master_secret_label = @import("prf.zig").master_secret_label;
const masterFromPreMasterSecret = @import("prf.zig").masterFromPreMasterSecret;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const Conn = @import("conn.zig").Conn;

pub const ClientHandshakeState = struct {
    server_hello: *ServerHelloMsg,
    hello: *ClientHelloMsg,
    suite: ?*const CipherSuite12 = null,
    finished_hash: ?FinishedHash = null,
    master_secret: ?[]const u8 = null,
    fake_con: ?*FakeConnection = null,

    pub fn deinit(self: *ClientHandshakeState, allocator: mem.Allocator) void {
        self.hello.deinit(allocator);
        if (self.finished_hash) |*fh| fh.deinit();
        if (self.master_secret) |s| allocator.free(s);
    }

    fn handshake(self: *ClientHandshakeState, allocator: mem.Allocator) !void {
        var suite = cipherSuiteById(.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).?;
        self.suite = suite;

        var finished_hash = FinishedHash.new(allocator, .v1_2, suite);
        try finished_hash.write(try self.hello.marshal(allocator));
        try finished_hash.write(try self.server_hello.marshal(allocator));

        self.finished_hash = finished_hash;
        try self.doFullHandshake(allocator);
    }

    fn doFullHandshake(self: *ClientHandshakeState, allocator: mem.Allocator) !void {
        const conn_protocol_vers = .v1_2;

        if (self.fake_con) |con| {
            try self.finished_hash.?.write(try con.cert_msg.?.marshal(allocator));

            var key_agreement = self.suite.?.ka(conn_protocol_vers);
            defer key_agreement.deinit(allocator);

            try self.finished_hash.?.write(try con.skx_msg.?.marshal(allocator));

            var cert_chain = CertificateChain{
                .certificate_chain = try allocator.dupe([]const u8, con.cert_msg.?.certificates),
            };
            defer cert_chain.deinit(allocator);

            try key_agreement.processServerKeyExchange(
                allocator,
                self.hello,
                self.server_hello,
                &cert_chain,
                &con.skx_msg.?,
            );

            try self.finished_hash.?.write(try con.hello_done_msg.?.marshal(allocator));

            var pre_master_secret: []const u8 = undefined;
            var ckx: ClientKeyExchangeMsg = undefined;
            try key_agreement.generateClientKeyExchange(
                allocator,
                self.hello,
                &cert_chain,
                &pre_master_secret,
                &ckx,
            );
            defer allocator.free(pre_master_secret);
            con.ckx_msg = ckx;
            try self.finished_hash.?.write(try con.ckx_msg.?.marshal(allocator));

            self.master_secret = try masterFromPreMasterSecret(
                allocator,
                conn_protocol_vers,
                self.suite.?,
                pre_master_secret,
                self.hello.random,
                self.server_hello.random,
            );

            self.finished_hash.?.discardHandshakeBuffer();
        }
    }
};

pub const ClientHandshake = union(ProtocolVersion) {
    v1_3: void,
    v1_2: ClientHandshakeTls12,
    v1_0: ClientHandshakeTls12,

    pub fn init(ver: ProtocolVersion, conn: *Conn, client_hello: ClientHelloMsg) ClientHandshake {
        return switch (ver) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2 => ClientHandshake{ .v1_2 = ClientHandshakeTls12.init(conn, client_hello) },
            .v1_0 => ClientHandshake{ .v1_0 = ClientHandshakeTls12.init(conn, client_hello) },
        };
    }

    pub fn deinit(self: *ClientHandshake, allocator: mem.Allocator) void {
        switch (self.*) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2, .v1_0 => |*hs| hs.deinit(allocator),
        }
    }

    pub fn handshake(self: *ClientHandshake, allocator: mem.Allocator) !void {
        switch (self.*) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2, .v1_0 => |*hs| try hs.handshake(allocator),
        }
    }
};

pub const ClientHandshakeTls12 = struct {
    state: ClientHandshakeState,
    conn: *Conn,

    pub fn init(conn: *Conn, client_hello: ClientHelloMsg) ClientHandshakeTls12 {
        return .{ .state = .{ .client_hello = client_hello }, .conn = conn };
    }

    pub fn deinit(self: *ClientHandshakeTls12, allocator: mem.Allocator) void {
        self.state.deinit(allocator);
    }

    pub fn handshake(self: *ClientHandshakeTls12, allocator: mem.Allocator) !void {
        _ = self;
        _ = allocator;
    }
};

const testing = std.testing;

test "ClientHandshakeState" {
    const generateRandom = @import("handshake_msg.zig").generateRandom;
    const random_length = @import("handshake_msg.zig").random_length;
    const ServerHandshakeState = @import("handshake_server.zig").ServerHandshakeState;

    testing.log_level = .debug;
    const allocator = testing.allocator;

    var client_hello: ClientHelloMsg = blk: {
        const random = try generateRandom(allocator);
        errdefer allocator.free(random);
        const session_id = try generateRandom(allocator);
        errdefer allocator.free(session_id);
        const cipher_suites = try allocator.dupe(
            CipherSuiteId,
            &[_]CipherSuiteId{.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
        );
        errdefer allocator.free(cipher_suites);
        const compression_methods = try allocator.dupe(
            CompressionMethod,
            &[_]CompressionMethod{.none},
        );
        errdefer allocator.free(compression_methods);
        break :blk ClientHelloMsg{
            .vers = .v1_3,
            .random = random[0..random_length],
            .session_id = session_id[0..random_length],
            .cipher_suites = cipher_suites,
            .compression_methods = compression_methods,
        };
    };

    var fake_con = FakeConnection{};
    defer fake_con.deinit(allocator);

    const client_hello_bytes = try client_hello.marshal(allocator);
    var client_hello_for_server = blk: {
        var msg = try HandshakeMsg.unmarshal(allocator, client_hello_bytes);
        break :blk msg.ClientHello;
    };

    var srv_hs = ServerHandshakeState{
        .client_hello = client_hello_for_server,
        .ecdhe_ok = true,
        .fake_con = &fake_con,
    };
    defer srv_hs.deinit(allocator);
    try srv_hs.processClientHello(allocator);
    try srv_hs.pickCipherSuite();
    try srv_hs.doFullHandshake(allocator);

    var cli_hs = ClientHandshakeState{
        .server_hello = &srv_hs.hello.?,
        .hello = &client_hello,
        .fake_con = &fake_con,
    };
    defer cli_hs.deinit(allocator);

    try cli_hs.handshake(allocator);
    try srv_hs.doFullHandshake2(allocator, &fake_con.server_key_agreement.?, .v1_2);

    try testing.expectEqualSlices(u8, cli_hs.master_secret.?, srv_hs.master_secret.?);
}
