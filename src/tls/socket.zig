const std = @import("std");
const mem = std.mem;
const net = std.net;
const Conn = @import("conn.zig").Conn;
const CertPool = @import("cert_pool.zig").CertPool;
const default_cipher_suites_tls13 = @import("cipher_suites.zig").default_cipher_suites_tls13;

const Server = struct {
    server: net.StreamServer,
    connections: std.ArrayListUnmanaged(Conn),
    allocator: mem.Allocator,
    conn_config: Conn.Config,

    pub fn init(
        allocator: mem.Allocator,
        address: net.Address,
        options: net.StreamServer.Options,
        conn_config: Conn.Config,
    ) !Server {
        var server = net.StreamServer.init(options);
        try server.listen(address);
        return Server{
            .server = server,
            .connections = try std.ArrayListUnmanaged(Conn).initCapacity(allocator, 1),
            .allocator = allocator,
            .conn_config = conn_config,
        };
    }

    pub fn deinit(self: *Server) void {
        self.connections.deinit(self.allocator);
    }

    pub fn accept(self: *Server) !Conn {
        var conn = try self.server.accept();
        const c = Conn.init(
            self.allocator,
            .server,
            conn.address,
            conn.stream,
            .{},
            .{},
            self.conn_config,
        );
        try self.connections.append(self.allocator, c);
        return c;
    }
};

const Client = struct {
    conn: Conn,

    pub fn init(allocator: mem.Allocator, addr: net.Address, conn_config: Conn.Config) !Client {
        var stream = try net.tcpConnectToAddress(addr);
        return Client{
            .conn = Conn.init(allocator, .client, addr, stream, .{}, .{}, conn_config),
        };
    }

    pub fn deinit(self: *Client, allocator: mem.Allocator) void {
        self.conn.deinit(allocator);
    }

    pub fn close(self: *Client) !void {
        try self.conn.close();
    }
};

const testing = std.testing;

test "ClientServer_tls12_rsa2048" {
    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;

    testing.log_level = .warn;

    try struct {
        fn testServer(server: *Server) !void {
            var conn = try server.accept();
            const allocator = server.allocator;
            defer conn.deinit(allocator);
            defer conn.close() catch {};
            std.log.debug(
                "testServer &conn=0x{x} &conn.in=0x{x}, &conn.out=0x{x}",
                .{ @ptrToInt(&conn), @ptrToInt(&conn.in), @ptrToInt(&conn.out) },
            );
            var buffer = [_]u8{0} ** 1024;
            const n = try conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), conn.version);
            try testing.expectEqualStrings("hello", buffer[0..n]);

            _ = try conn.write("How do you do?");
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(allocator, addr, .{
                .max_version = .v1_2,
                .insecure_skip_verify = true,
            });
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("hello");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), client.conn.version);
            try testing.expectEqualStrings("How do you do?", buffer[0..n]);
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const cert_pem = @embedFile("../../tests/rsa2048.crt.pem");
            const key_pem = @embedFile("../../tests/rsa2048.key.pem");

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var certificates = try allocator.alloc(CertificateChain, 1);
            certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
            var server = try Server.init(
                allocator,
                listen_addr,
                .{},
                .{
                    .certificates = certificates,
                    .max_version = .v1_2,
                },
            );
            defer server.deinit();

            const t = try std.Thread.spawn(
                .{},
                testClient,
                .{ server.server.listen_address, allocator },
            );
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "ClientServer_tls12_p256_no_client_certificate" {
    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;

    testing.log_level = .err;

    try struct {
        fn testServer(server: *Server) !void {
            var conn = try server.accept();
            const allocator = server.allocator;
            defer conn.deinit(allocator);
            defer conn.close() catch {};
            std.log.debug(
                "testServer &conn=0x{x} &conn.in=0x{x}, &conn.out=0x{x}",
                .{ @ptrToInt(&conn), @ptrToInt(&conn.in), @ptrToInt(&conn.out) },
            );
            var buffer = [_]u8{0} ** 1024;
            const n = try conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), conn.version);
            try testing.expectEqualStrings("hello", buffer[0..n]);

            _ = try conn.write("How do you do?");
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(allocator, addr, .{
                .max_version = .v1_2,
                .insecure_skip_verify = true,
            });
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("hello");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), client.conn.version);
            try testing.expectEqualStrings("How do you do?", buffer[0..n]);
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const cert_pem = @embedFile("../../tests/p256-self-signed.crt.pem");
            const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var certificates = try allocator.alloc(CertificateChain, 1);
            certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
            var server = try Server.init(
                allocator,
                listen_addr,
                .{},
                .{
                    .certificates = certificates,
                    .max_version = .v1_2,
                },
            );
            defer server.deinit();

            const t = try std.Thread.spawn(
                .{},
                testClient,
                .{ server.server.listen_address, allocator },
            );
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "ClientServer_tls12_p256_client_certificate" {
    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;

    testing.log_level = .info;

    try struct {
        fn testServer(server: *Server) !void {
            var conn = try server.accept();
            const allocator = server.allocator;
            defer conn.deinit(allocator);
            defer conn.close() catch {};
            std.log.debug(
                "testServer &conn=0x{x} &conn.in=0x{x}, &conn.out=0x{x}",
                .{ @ptrToInt(&conn), @ptrToInt(&conn.in), @ptrToInt(&conn.out) },
            );
            var buffer = [_]u8{0} ** 1024;
            const n = try conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), conn.version);
            try testing.expectEqualStrings("hello", buffer[0..n]);

            _ = try conn.write("How do you do?");
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = blk: {
                const cert_pem = @embedFile("../../tests/client_cert/my-client.crt");
                const key_pem = @embedFile("../../tests/client_cert/my-client.key");
                var certificates = try allocator.alloc(CertificateChain, 1);
                errdefer allocator.free(certificates);
                certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
                errdefer certificates[0].deinit(allocator);

                break :blk try Client.init(allocator, addr, .{
                    .max_version = .v1_2,
                    .insecure_skip_verify = true,
                    .certificates = certificates,
                });
            };
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("hello");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), client.conn.version);
            try testing.expectEqualStrings("How do you do?", buffer[0..n]);
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const cert_pem = @embedFile("../../tests/p256-self-signed.crt.pem");
            const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");

            const ca_pem = @embedFile("../../tests/client_cert/my-root-ca.crt");

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var server = blk: {
                var certificates = try allocator.alloc(CertificateChain, 1);
                errdefer allocator.free(certificates);
                certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
                errdefer certificates[0].deinit(allocator);

                var client_cas = try CertPool.init(allocator, false);
                errdefer client_cas.deinit();
                try client_cas.appendCertsFromPem(ca_pem);

                break :blk try Server.init(
                    allocator,
                    listen_addr,
                    .{},
                    .{
                        .certificates = certificates,
                        .max_version = .v1_2,
                        .client_auth = .request_client_cert,
                        .client_cas = client_cas,
                    },
                );
            };
            defer server.deinit();

            const t = try std.Thread.spawn(
                .{},
                testClient,
                .{ server.server.listen_address, allocator },
            );
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "ClientServer_tls13_rsa2048" {
    // if (true) return error.SkipZigTest;

    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;

    testing.log_level = .info;

    try struct {
        fn testServer(server: *Server) !void {
            var conn = try server.accept();
            const allocator = server.allocator;
            defer conn.deinit(allocator);
            defer conn.close() catch {};
            std.log.debug(
                "testServer &conn=0x{x} &conn.in=0x{x}, &conn.out=0x{x}",
                .{ @ptrToInt(&conn), @ptrToInt(&conn.in), @ptrToInt(&conn.out) },
            );
            var buffer = [_]u8{0} ** 1024;
            const n = try conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_3), conn.version);
            try testing.expectEqualStrings("hello", buffer[0..n]);

            _ = try conn.write("How do you do?");
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(allocator, addr, .{
                .max_version = .v1_3,
                .insecure_skip_verify = true,
            });
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("hello");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_3), client.conn.version);
            try testing.expectEqualStrings("How do you do?", buffer[0..n]);
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const cert_pem = @embedFile("../../tests/rsa2048.crt.pem");
            const key_pem = @embedFile("../../tests/rsa2048.key.pem");

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var certificates = try allocator.alloc(CertificateChain, 1);
            certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
            var server = try Server.init(
                allocator,
                listen_addr,
                .{},
                .{
                    .certificates = certificates,
                    .max_version = .v1_3,
                    .session_tickets_disabled = true,
                },
            );
            defer server.deinit();

            const t = try std.Thread.spawn(
                .{},
                testClient,
                .{ server.server.listen_address, allocator },
            );
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "ClientServer_tls13_p256_no_client_certificate_one_request" {
    // if (true) return error.SkipZigTest;

    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;

    testing.log_level = .info;

    try struct {
        fn testServer(server: *Server) !void {
            var conn = try server.accept();
            const allocator = server.allocator;
            defer conn.deinit(allocator);
            defer conn.close() catch {};
            std.log.debug(
                "testServer &conn=0x{x} &conn.in=0x{x}, &conn.out=0x{x}",
                .{ @ptrToInt(&conn), @ptrToInt(&conn.in), @ptrToInt(&conn.out) },
            );
            var buffer = [_]u8{0} ** 1024;
            const n = try conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_3), conn.version);
            try testing.expectEqualStrings("hello", buffer[0..n]);

            _ = try conn.write("How do you do?");
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(allocator, addr, .{
                .max_version = .v1_3,
                .insecure_skip_verify = true,
                .cipher_suites = &default_cipher_suites_tls13,
            });
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("hello");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_3), client.conn.version);
            try testing.expectEqualStrings("How do you do?", buffer[0..n]);
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const cert_pem = @embedFile("../../tests/p256-self-signed.crt.pem");
            const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var certificates = try allocator.alloc(CertificateChain, 1);
            certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
            var server = try Server.init(
                allocator,
                listen_addr,
                .{},
                .{
                    .certificates = certificates,
                    .max_version = .v1_3,
                    .session_tickets_disabled = true,
                },
            );
            defer server.deinit();

            const t = try std.Thread.spawn(
                .{},
                testClient,
                .{ server.server.listen_address, allocator },
            );
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "ClientServer_tls13_p256_no_client_certificate_two_requests" {
    // if (true) return error.SkipZigTest;

    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;
    const LruSessionCache = @import("session.zig").LruSessionCache;

    testing.log_level = .info;

    try struct {
        fn testServer(server: *Server) !void {
            var i: usize = 0;
            while (i < 2) : (i += 1) {
                var conn = try server.accept();
                const allocator = server.allocator;
                defer conn.deinit(allocator);
                defer conn.close() catch {};
                std.log.debug(
                    "testServer &conn=0x{x} &conn.in=0x{x}, &conn.out=0x{x}",
                    .{ @ptrToInt(&conn), @ptrToInt(&conn.in), @ptrToInt(&conn.out) },
                );
                var buffer = [_]u8{0} ** 1024;
                const n = try conn.read(&buffer);
                try testing.expectEqual(@as(?ProtocolVersion, .v1_3), conn.version);
                try testing.expectEqualStrings("hello", buffer[0..n]);

                _ = try conn.write("How do you do?");
            }
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var cache = try LruSessionCache.init(allocator, 1);
            defer cache.deinit();
            var client_config = Conn.Config{
                .max_version = .v1_3,
                .insecure_skip_verify = true,
                .cipher_suites = &default_cipher_suites_tls13,
                .client_session_cache = cache,
            };

            var i: usize = 0;
            while (i < 2) : (i += 1) {
                std.log.info("testClient loop start, i={}", .{i});
                var client = try Client.init(allocator, addr, client_config);
                defer client.deinit(allocator);
                defer client.close() catch {};

                std.log.debug(
                    "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                    .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
                );
                _ = try client.conn.write("hello");

                var buffer = [_]u8{0} ** 1024;
                const n = try client.conn.read(&buffer);
                try testing.expectEqual(@as(?ProtocolVersion, .v1_3), client.conn.version);
                try testing.expectEqualStrings("How do you do?", buffer[0..n]);
            }
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const cert_pem = @embedFile("../../tests/p256-self-signed.crt.pem");
            const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var certificates = try allocator.alloc(CertificateChain, 1);
            certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
            var server = try Server.init(
                allocator,
                listen_addr,
                .{},
                .{
                    .certificates = certificates,
                    .max_version = .v1_3,
                    .session_tickets_disabled = false,
                },
            );
            defer server.deinit();

            const t = try std.Thread.spawn(
                .{},
                testClient,
                .{ server.server.listen_address, allocator },
            );
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "ClientServer_tls13_p256_client_certificate" {
    // if (true) return error.SkipZigTest;

    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;

    testing.log_level = .info;

    try struct {
        fn testServer(server: *Server) !void {
            var conn = try server.accept();
            const allocator = server.allocator;
            defer conn.deinit(allocator);
            defer conn.close() catch {};
            std.log.debug(
                "testServer &conn=0x{x} &conn.in=0x{x}, &conn.out=0x{x}",
                .{ @ptrToInt(&conn), @ptrToInt(&conn.in), @ptrToInt(&conn.out) },
            );
            var buffer = [_]u8{0} ** 1024;
            const n = try conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_3), conn.version);
            try testing.expectEqualStrings("hello", buffer[0..n]);

            _ = try conn.write("How do you do?");
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = blk: {
                const cert_pem = @embedFile("../../tests/client_cert/my-client.crt");
                const key_pem = @embedFile("../../tests/client_cert/my-client.key");
                var certificates = try allocator.alloc(CertificateChain, 1);
                errdefer allocator.free(certificates);
                certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
                errdefer certificates[0].deinit(allocator);

                var c = try Client.init(allocator, addr, .{
                    .max_version = .v1_3,
                    .insecure_skip_verify = true,
                    .cipher_suites = &default_cipher_suites_tls13,
                    .certificates = certificates,
                });
                break :blk c;
            };
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("hello");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_3), client.conn.version);
            try testing.expectEqualStrings("How do you do?", buffer[0..n]);
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const cert_pem = @embedFile("../../tests/p256-self-signed.crt.pem");
            const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");

            const ca_pem = @embedFile("../../tests/client_cert/my-root-ca.crt");

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var server = blk: {
                var certificates = try allocator.alloc(CertificateChain, 1);
                errdefer allocator.free(certificates);
                certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
                errdefer certificates[0].deinit(allocator);

                var client_cas = try CertPool.init(allocator, false);
                errdefer client_cas.deinit();
                try client_cas.appendCertsFromPem(ca_pem);

                var s = try Server.init(
                    allocator,
                    listen_addr,
                    .{},
                    .{
                        .certificates = certificates,
                        .max_version = .v1_3,
                        .session_tickets_disabled = true,
                        .client_auth = .request_client_cert,
                        .client_cas = client_cas,
                    },
                );
                break :blk s;
            };
            defer server.deinit();

            const t = try std.Thread.spawn(
                .{},
                testClient,
                .{ server.server.listen_address, allocator },
            );
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "ServerOnly_tls13_p256" {
    if (true) return error.SkipZigTest;

    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;

    testing.log_level = .info;

    try struct {
        fn testServer(server: *Server) !void {
            var conn = try server.accept();
            const allocator = server.allocator;
            defer conn.deinit(allocator);
            defer conn.close() catch {};
            std.log.debug(
                "testServer &conn=0x{x} &conn.in=0x{x}, &conn.out=0x{x}",
                .{ @ptrToInt(&conn), @ptrToInt(&conn.in), @ptrToInt(&conn.out) },
            );
            var buffer = [_]u8{0} ** 1024;
            _ = try conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_3), conn.version);

            var resp = std.ArrayList(u8).init(allocator);
            defer resp.deinit();
            var resp_writer = resp.writer();
            _ = try resp_writer.write("HTTP/1.1 200 OK\r\n");
            _ = try resp_writer.write("Content-Type: text/plain\r\n");
            _ = try resp_writer.write("Date: Thu, 24 Feb 2022 14:03:28 GMT\r\n");
            _ = try resp_writer.write("Content-Length: 27\r\n");
            _ = try resp_writer.write("\r\n");
            _ = try resp_writer.write("This is an example server.\n");

            _ = try conn.write(resp.items);
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const cert_pem = @embedFile("../../tests/p256-self-signed.crt.pem");
            const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");

            const listen_addr = try net.Address.parseIp("127.0.0.1", 8443);
            var certificates = try allocator.alloc(CertificateChain, 1);
            certificates[0] = try x509KeyPair(allocator, cert_pem, key_pem);
            var server = try Server.init(
                allocator,
                listen_addr,
                .{},
                .{
                    .certificates = certificates,
                    .max_version = .v1_3,
                    .session_tickets_disabled = true,
                },
            );
            defer server.deinit();

            try testServer(&server);
        }
    }.runTest();
}

const skip_communicate_to_outside = true;

test "Connect to localhost TLS 1.3" {
    if (skip_communicate_to_outside) return error.SkipZigTest;

    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;

    testing.log_level = .info;

    try struct {
        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(allocator, addr, .{
                .max_version = .v1_3,
                .server_name = "naruh.dev",
                .insecure_skip_verify = false,
            });
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("GET / HTTP/1.1\r\nHost: naruh.dev\r\n\r\n");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_3), client.conn.version);
            std.log.debug("response:\n{s}", .{buffer[0..n]});
            try testing.expect(mem.startsWith(u8, buffer[0..n], "HTTP/1.1 200 OK\r\n"));
        }

        fn runTest() !void {
            const allocator = testing.allocator;
            const addr = try std.net.Address.parseIp("127.0.0.1", 8443);
            try testClient(addr, allocator);
        }
    }.runTest();
}

test "Connect to localhost TLS 1.2" {
    if (skip_communicate_to_outside) return error.SkipZigTest;

    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;

    testing.log_level = .err;

    try struct {
        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(allocator, addr, .{
                .max_version = .v1_2,
                .server_name = "naruh.dev",
                .insecure_skip_verify = false,
            });
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("GET / HTTP/1.1\r\nHost: naruh.dev\r\n\r\n");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), client.conn.version);
            std.log.debug("response:\n{s}", .{buffer[0..n]});
            try testing.expect(mem.startsWith(u8, buffer[0..n], "HTTP/1.1 200 OK\r\n"));
        }

        fn runTest() !void {
            const allocator = testing.allocator;
            const addr = try std.net.Address.parseIp("127.0.0.1", 8443);
            try testClient(addr, allocator);
        }
    }.runTest();
}

test "Connect to Internet" {
    if (skip_communicate_to_outside) return error.SkipZigTest;

    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;

    testing.log_level = .err;

    try struct {
        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(allocator, addr, .{
                .max_version = .v1_2,
                .server_name = "naruh.dev",
                .insecure_skip_verify = false,
            });
            defer client.deinit(allocator);
            defer client.close() catch {};

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            _ = try client.conn.write("GET / HTTP/1.1\r\nHost: naruh.dev\r\n\r\n");

            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), client.conn.version);
            std.log.debug("response:\n{s}", .{buffer[0..n]});
            try testing.expect(mem.startsWith(u8, buffer[0..n], "HTTP/1.1 200 OK\r\n"));
        }

        fn runTest() !void {
            const allocator = testing.allocator;
            const addr = try std.net.Address.parseIp("160.16.94.194", 443);
            try testClient(addr, allocator);
        }
    }.runTest();
}
