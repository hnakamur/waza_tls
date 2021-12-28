const std = @import("std");
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const cipherSuiteById = @import("cipher_suites.zig").cipherSuiteById;

const ClientHandshakeState = struct {
    server_hello: *ServerHelloMsg,
    hello: *ClientHelloMsg,
    suite: *const CipherSuite12,
    finished_hash: *FinishedHash,
    master_secret: ?[]const u8 = null,
};

const testing = std.testing;

test "ClientHandshakeState" {
    const allocator = testing.allocator;

    var server_hello = ServerHelloMsg{
        .vers = .v1_3,
        .random = &[_]u8{0} ** 32,
        .session_id = &[_]u8{0} ** 32,
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .compression_method = .none,
        .ocsp_stapling = false,
    };

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

    var suite = cipherSuiteById(.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).?;
    var finished_hash = FinishedHash.new(allocator, .v1_2, suite);
    defer finished_hash.deinit();

    var hs = ClientHandshakeState{
        .server_hello = &server_hello,
        .hello = &client_hello,
        .suite = suite,
        .finished_hash = &finished_hash,
    };

    std.debug.print("hs={}\n", .{hs});
}
