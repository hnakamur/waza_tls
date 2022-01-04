const std = @import("std");
const mem = std.mem;
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
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const ServerHandshakeState = @import("handshake_server.zig").ServerHandshakeState;

pub const ClientHandshakeState = struct {
    server_hello: *ServerHelloMsg,
    hello: *ClientHelloMsg,
    suite: ?*const CipherSuite12 = null,
    finished_hash: ?FinishedHash = null,
    master_secret: ?[]const u8 = null,
    fake_con: ?*FakeConnection = null,

    pub fn deinit(self: *ClientHandshakeState, allocator: mem.Allocator) void {
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
            std.log.debug(
                "ClientHandshakeState.doFullHandshake key_agreement={}",
                .{key_agreement},
            );

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
            var ckx: *const ClientKeyExchangeMsg = undefined;
            try key_agreement.generateClientKeyExchange(
                allocator,
                self.hello,
                &cert_chain,
                &pre_master_secret,
                &ckx,
            );

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

fn masterFromPreMasterSecret(
    allocator: mem.Allocator,
    version: ProtocolVersion,
    suite: *const CipherSuite12,
    pre_master_secret: []const u8,
    client_random: []const u8,
    server_random: []const u8,
) ![]const u8 {
    var seed = try allocator.alloc(u8, client_random.len + server_random.len);
    defer allocator.free(seed);
    mem.copy(u8, seed, client_random);
    mem.copy(u8, seed[client_random.len..], server_random);

    var master_secret = try allocator.alloc(u8, master_secret_length);
    const prf = prfForVersion(version, suite);
    try prf(allocator, pre_master_secret, master_secret_label, seed, master_secret);
    return master_secret;
}

const testing = std.testing;
const fmtx = @import("../fmtx.zig");

test "ClientHandshakeState" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    var client_hello: ClientHelloMsg = undefined;
    {
        const cipher_suites = try allocator.dupe(
            CipherSuiteId,
            &[_]CipherSuiteId{.TLS_AES_128_GCM_SHA256},
        );
        errdefer allocator.free(cipher_suites);
        const compression_methods = try allocator.dupe(
            CompressionMethod,
            &[_]CompressionMethod{.none},
        );
        errdefer allocator.free(compression_methods);
        client_hello = ClientHelloMsg{
            .vers = .v1_3,
            .random = &[_]u8{0} ** 32,
            .session_id = &[_]u8{0} ** 32,
            .cipher_suites = cipher_suites,
            .compression_methods = compression_methods,
        };
    }
    defer client_hello.deinit(allocator);

    var fake_con = FakeConnection{};
    defer fake_con.deinit(allocator);

    var srv_hs = ServerHandshakeState{
        .client_hello = &client_hello,
        .ecdhe_ok = true,
        .fake_con = &fake_con,
    };
    defer srv_hs.deinit(allocator);
    try srv_hs.processClientHello(allocator);
    try srv_hs.pickCipherSuite();
    try srv_hs.doFullHandshake(allocator);

    var hs = ClientHandshakeState{
        .server_hello = &srv_hs.hello.?,
        .hello = &client_hello,
        .fake_con = &fake_con,
    };
    defer hs.deinit(allocator);

    try hs.handshake(allocator);

    std.debug.print("hs={}\n", .{hs});
    std.log.debug("hs.master_secret={}", .{fmtx.fmtSliceHexEscapeLower(hs.master_secret.?)});
}
