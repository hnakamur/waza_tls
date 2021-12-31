const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const mem = std.mem;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CertificateMsg = @import("handshake_msg.zig").CertificateMsg;
const ServerHelloDoneMsg = @import("handshake_msg.zig").ServerHelloDoneMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const EcPointFormat = @import("handshake_msg.zig").EcPointFormat;
const generateRandom = @import("handshake_msg.zig").generateRandom;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const cipherSuiteById = @import("cipher_suites.zig").cipherSuiteById;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const SessionState = @import("ticket.zig").SessionState;
const ClientHandshakeState = @import("handshake_client.zig").ClientHandshakeState;
const FakeConnection = @import("fake_connection.zig").FakeConnection;

// ServerHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
pub const ServerHandshakeState = struct {
    client_hello: *ClientHelloMsg,
    hello: ?ServerHelloMsg = null,
    suite: ?*const CipherSuite12 = null,
    ecdhe_ok: bool = false,
    ec_sign_ok: bool = false,
    rsa_decrypt_ok: bool = false,
    rsa_sign_ok: bool = false,
    session_state: ?SessionState = null,
    finished_hash: ?FinishedHash = null,
    master_secret: ?[]const u8 = null,
    cert_chain: ?CertificateChain = null,
    fake_con: ?*FakeConnection = null,

    fn deinit(self: *ServerHandshakeState, allocator: mem.Allocator) void {
        if (self.hello) |*hello| hello.deinit(allocator);
        if (self.finished_hash) |*fh| fh.deinit();
        if (self.cert_chain) |*cc| cc.deinit(allocator);
    }

    fn processClientHello(self: *ServerHandshakeState, allocator: mem.Allocator) !void {
        const random = try generateRandom(allocator);
        // TODO: stop hardcoding field values.
        var hello = ServerHelloMsg{
            .vers = .v1_2,
            .random = random,
            .session_id = &[_]u8{0} ** 32,
            .cipher_suite = .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            .compression_method = .none,
            .ocsp_stapling = false,
            .supported_version = .v1_2,
        };
        if (self.ecdhe_ok) {
            // Although omitting the ec_point_formats extension is permitted, some
            // old OpenSSL version will refuse to handshake if not present.
            //
            // Per RFC 4492, section 5.1.2, implementations MUST support the
            // uncompressed point format. See golang.org/issue/31943.
            hello.supported_points = try allocator.dupe(
                EcPointFormat,
                &[_]EcPointFormat{.uncompressed},
            );
        }

        self.hello = hello;

        const certificate_chain = try allocator.dupe(
            []const u8,
            &[_][]const u8{testEd25519Certificate},
        );
        self.cert_chain = CertificateChain{
            .certificate_chain = certificate_chain,
            .private_key = .{ .raw = testEd25519PrivateKey },
        };
    }

    fn pickCipherSuite(self: *ServerHandshakeState) !void {
        // TODO: stop hardcoding.
        self.suite = cipherSuiteById(.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    }

    fn doFullHandshake(self: *ServerHandshakeState, allocator: mem.Allocator) !void {
        const conn_protocol_vers = .v1_2;
        var finished_hash = FinishedHash.new(allocator, conn_protocol_vers, self.suite.?);

        if (false) { // TODO: stop hardcoding
            // No need to keep a full record of the handshake if client
            // certificates won't be used.
            finished_hash.discardHandshakeBuffer();
        }

        try finished_hash.write(try self.client_hello.marshal(allocator));
        try finished_hash.write(try self.hello.?.marshal(allocator));
        // TODO: implement write record self.hello.marshal()
        if (self.fake_con) |con| {
            con.server_hello_msg = self.hello.?;
        }

        {
            const certificates = try allocator.dupe(
                []const u8,
                &[_][]const u8{testEd25519Certificate},
            );
            var cert_msg = CertificateMsg{
                .certificates = certificates,
            };
            defer cert_msg.deinit(allocator);

            try finished_hash.write(try cert_msg.marshal(allocator));
            // TODO: implement write record cert_msg.marshal()
            if (self.fake_con) |con| {
                con.cert_msg = cert_msg;
            }
        }

        if (self.hello.?.ocsp_stapling) {
            // TODO: implement
        }

        var key_agreement = self.suite.?.ka(conn_protocol_vers);
        var skx = try key_agreement.generateServerKeyExchange(
            allocator,
            &self.cert_chain.?,
            self.client_hello,
            &self.hello.?,
        );
        defer skx.deinit(allocator);
        // std.log.debug("skx={}", .{skx});
        try finished_hash.write(try skx.marshal(allocator));
        // TODO: implement write record skx.marshal()
        if (self.fake_con) |con| {
            con.skx_msg = skx;
        }

        var hello_done = ServerHelloDoneMsg{};
        defer hello_done.deinit(allocator);
        try finished_hash.write(try hello_done.marshal(allocator));
        // TODO: implement write record hello_done.marshal()
        if (self.fake_con) |con| {
            con.hello_done_msg = hello_done;
        }

        // TODO: implement
        self.finished_hash = finished_hash;
    }
};

const testing = std.testing;

const testEd25519Certificate = "\x30\x82\x01\x2e\x30\x81\xe1\xa0\x03\x02\x01\x02\x02\x10\x0f\x43\x1c\x42\x57\x93\x94\x1d\xe9\x87\xe4\xf1\xad\x15\x00\x5d\x30\x05\x06\x03\x2b\x65\x70\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x1e\x17\x0d\x31\x39\x30\x35\x31\x36\x32\x31\x33\x38\x30\x31\x5a\x17\x0d\x32\x30\x30\x35\x31\x35\x32\x31\x33\x38\x30\x31\x5a\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00\x3f\xe2\x15\x2e\xe6\xe3\xef\x3f\x4e\x85\x4a\x75\x77\xa3\x64\x9e\xed\xe0\xbf\x84\x2c\xcc\x92\x26\x8f\xfa\x6f\x34\x83\xaa\xec\x8f\xa3\x4d\x30\x4b\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa0\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30\x16\x06\x03\x55\x1d\x11\x04\x0f\x30\x0d\x82\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x30\x05\x06\x03\x2b\x65\x70\x03\x41\x00\x63\x44\xed\x9c\xc4\xbe\x53\x24\x53\x9f\xd2\x10\x8d\x9f\xe8\x21\x08\x90\x95\x39\xe5\x0d\xc1\x55\xff\x2c\x16\xb7\x1d\xfc\xab\x7d\x4d\xd4\xe0\x93\x13\xd0\xa9\x42\xe0\xb6\x6b\xfe\x5d\x67\x48\xd7\x9f\x50\xbc\x6c\xcd\x4b\x03\x83\x7c\xf2\x08\x58\xcd\xac\xcf\x0c";
const testEd25519PrivateKey = "\x3a\x88\x49\x65\xe7\x6b\x3f\x55\xe5\xfa\xf9\x61\x54\x58\xa9\x23\x54\x89\x42\x34\xde\x3e\xc9\xf6\x84\xd4\x6d\x55\xce\xbf\x3d\xc6\x3f\xe2\x15\x2e\xe6\xe3\xef\x3f\x4e\x85\x4a\x75\x77\xa3\x64\x9e\xed\xe0\xbf\x84\x2c\xcc\x92\x26\x8f\xfa\x6f\x34\x83\xaa\xec\x8f";

test "Ed25519.sign" {
    try testing.expectEqual(@as(usize, crypto.sign.Ed25519.secret_length), testEd25519PrivateKey.len);

    const key_pair = crypto.sign.Ed25519.KeyPair.fromSecretKey(testEd25519PrivateKey.*);
    const message = "\xf0\x8d\x1b\x90\x67\x3b\x23\x46\xac\xf7\x79\xf2\xf9\xe8\x90\x98\xb3\x52\xb2\x55\x2a\xfb\x0f\x1e\xdd\x4f\xb3\x75\x4b\x9b\x88\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x44\x4f\x57\x4e\x47\x52\x44\x01\x03\x00\x1d\x20\x2f\xe5\x7d\xa3\x47\xcd\x62\x43\x15\x28\xda\xac\x5f\xbb\x29\x07\x30\xff\xf6\x84\xaf\xc4\xcf\xc2\xed\x90\x99\x5f\x58\xcb\x3b\x74";
    const sig = try crypto.sign.Ed25519.sign(message, key_pair, null);
    const want = "\x1f\x56\x21\x8a\x44\x04\x69\x65\xee\xf8\x93\x52\x4c\xf0\x49\x42\x57\x4c\x5b\xf5\x1a\xef\x43\xad\x39\x93\x03\xa3\x64\x84\xda\xe5\x82\x32\xfc\x77\x12\x61\xf3\xf4\x2c\xd8\x61\x9e\x86\x01\x1f\xc0\xa0\x98\x94\xa3\x7f\x15\x75\xc8\xe6\x2f\x20\xbd\xaf\x7c\xbe\x0e";
    try testing.expectEqualSlices(u8, want, &sig);
}

test "ServerHandshakeState" {
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
    var srv_hs = ServerHandshakeState{
        .client_hello = &client_hello,
        .ecdhe_ok = true,
        .fake_con = &fake_con,
    };
    defer srv_hs.deinit(allocator);
    try srv_hs.processClientHello(allocator);
    try srv_hs.pickCipherSuite();
    try srv_hs.doFullHandshake(allocator);

    var cli_hs = ClientHandshakeState{
        .server_hello = &fake_con.server_hello_msg.?,
        .hello = &client_hello,
    };
    defer cli_hs.deinit(allocator);

    std.log.debug("ClientHandshakeState={}\n", .{cli_hs});
    std.log.debug("ServerHandshakeState={}\n", .{srv_hs});
}
