const std = @import("std");
const mem = std.mem;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const freeOptionalField = @import("handshake_msg.zig").freeOptionalField;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const cipherSuiteById = @import("cipher_suites.zig").cipherSuiteById;
const FakeConnection = @import("fake_connection.zig").FakeConnection;

pub const ClientHandshakeState = struct {
    server_hello: *ServerHelloMsg,
    hello: *ClientHelloMsg,
    suite: ?*const CipherSuite12 = null,
    finished_hash: ?FinishedHash = null,
    master_secret: ?[]const u8 = null,
    fake_con: ?*FakeConnection = null,

    pub fn deinit(self: *ClientHandshakeState, allocator: mem.Allocator) void {
        _ = allocator;
        if (self.finished_hash) |*fh| fh.deinit();
    }

    fn handshake(self: *ClientHandshakeState, allocator: mem.Allocator) !void {
        var suite = cipherSuiteById(.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).?;
        self.suite = suite;

        var finished_hash = FinishedHash.new(allocator, .v1_2, suite);

        if (self.fake_con) |con| {
            finished_hash.write(con.hello.marshal());
            finished_hash.write(con.server_hello.marshal());
        }

        self.finished_hash = finished_hash;
        try self.doFullHandshake(allocator);
    }

    fn doFullHandshake(self: *ClientHandshakeState, allocator: mem.Allocator) !void {
        const conn_protocol_vers = .v1_2;

        if (self.fake_con) |con| {
            self.finished_hash.?.write(con.cert_msg.?.marshal());

            self.finished_hash.?.write(con.skx_msg.?.marshal());
            var key_agreement = self.suite.?.ka(conn_protocol_vers);
            std.log.debug(
                "ClientHandshakeState.doFullHandshake key_agreement={}",
                .{key_agreement},
            );

            self.finished_hash.?.write(con.hello_done_msg.?.marshal());
        }

        _ = allocator;
    }
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

    var fake_con = FakeConnection{};

    var hs = ClientHandshakeState{
        .server_hello = &server_hello,
        .hello = &client_hello,
        .fake_con = &fake_con,
    };
    defer hs.deinit(allocator);

    std.debug.print("hs={}\n", .{hs});
}
