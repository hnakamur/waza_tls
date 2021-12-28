const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const mem = std.mem;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const generateRandom = @import("handshake_msg.zig").generateRandom;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const SessionState = @import("ticket.zig").SessionState;

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
    finished_hash: ?*FinishedHash = null,
    master_secret: ?[]const u8 = null,
    cert_chain: ?*CertificateChain = null,

    fn deinit(self: *ServerHandshakeState, allocator: mem.Allocator) void {
        if (self.hello) |*hello| hello.deinit(allocator);
    }

    fn processClientHello(self: *ServerHandshakeState, allocator: mem.Allocator) !void {
        const random = try generateRandom(allocator);
        // TODO: stop hardcoding field values.
        self.hello = ServerHelloMsg{
            .vers = .v1_2,
            .random = random,
            .cipher_suite = .TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            .compression_method = .none,
            .ocsp_stapling = false,
            .supported_version = .v1_2,
        };
    }
};

const testing = std.testing;

test "ServerHandshakeState" {
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

    var s = ServerHandshakeState{
        .client_hello = &client_hello,
    };
    defer s.deinit(allocator);
    std.debug.print("ServerHandshakeState={}\n", .{s});
    try s.processClientHello(allocator);
}
