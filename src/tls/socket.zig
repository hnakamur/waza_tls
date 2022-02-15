const std = @import("std");
const mem = std.mem;
const net = std.net;
const Conn = @import("conn.zig").Conn;

const Server = struct {
    server: net.StreamServer,
    connections: std.ArrayListUnmanaged(ServerConn),
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
            .connections = try std.ArrayListUnmanaged(ServerConn).initCapacity(allocator, 1),
            .allocator = allocator,
            .conn_config = conn_config,
        };
    }

    pub fn deinit(self: *Server) void {
        self.connections.deinit(self.allocator);
    }

    pub fn accept(self: *Server) !ServerConn {
        var conn = try self.server.accept();
        var sc = ServerConn{
            .address = conn.address,
            .conn = Conn.init(
                self.allocator,
                .server,
                conn.stream,
                .{},
                .{},
                self.conn_config,
            ),
        };
        try self.connections.append(self.allocator, sc);
        return sc;
    }
};

const ServerConn = struct {
    address: net.Address,
    conn: Conn,

    pub fn deinit(self: *ServerConn, allocator: mem.Allocator) void {
        self.conn.deinit(allocator);
    }

    pub fn close(self: *ServerConn) !void {
        try self.conn.close();
    }
};

const Client = struct {
    conn: Conn,

    pub fn init(allocator: mem.Allocator, addr: net.Address, conn_config: Conn.Config) !Client {
        var stream = try net.tcpConnectToAddress(addr);
        return Client{
            .conn = Conn.init(allocator, .client, stream, .{}, .{}, conn_config),
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

test "socket ClientServer" {
    testing.log_level = .debug;
    try struct {
        fn testServer(server: *Server) !void {
            var client = try server.accept();
            var writer = client.conn.stream.writer();
            try writer.print("hello from server\n", .{});
            client.conn.stream.close();
        }

        fn testClient(allocator: mem.Allocator, addr: net.Address) !void {
            var client = try Client.init(allocator, addr, .{ .max_version = .v1_2 });
            defer client.close() catch {};

            var buf: [100]u8 = undefined;
            const len = try client.conn.raw_input.read(&buf);
            const msg = buf[0..len];
            try testing.expect(mem.eql(u8, msg, "hello from server\n"));
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var server = try Server.init(
                allocator,
                listen_addr,
                .{},
                .{ .max_version = .v1_2 },
            );
            defer server.deinit();

            const t = try std.Thread.spawn(
                .{},
                testClient,
                .{ allocator, server.server.listen_address },
            );
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "Conn ClientServer" {
    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
    const CertificateChain = @import("certificate_chain.zig").CertificateChain;
    const x509KeyPair = @import("certificate_chain.zig").x509KeyPair;

    testing.log_level = .info;

    try struct {
        fn testServer(server: *Server) !void {
            var client = try server.accept();
            const allocator = server.allocator;
            defer client.deinit(allocator);
            defer client.close() catch {};
            std.log.debug(
                "testServer &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), client.conn.version);
            try testing.expectEqualStrings("hello", buffer[0..n]);

            _ = try client.conn.write("How do you do?");
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

            // const cert_pem = @embedFile("../../tests/rsa2048.crt.pem");
            // const key_pem = @embedFile("../../tests/rsa2048.key.pem");
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

// test "Conn ClientServer pickTlsVersion error" {
//     try struct {
//         fn testServer(server: *Server) !void {
//             var client = try server.accept();
//             const allocator = server.allocator;
//             defer client.deinit(allocator);
//             defer client.close() catch {};
//             var buffer = [_]u8{0} ** 1024;
//             try testing.expectError(error.ProtocolVersionMismatch, client.conn.read(&buffer));
//         }

//         fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
//             var client = try Client.init(allocator, addr, .{ .max_version = .v1_2 });
//             defer client.deinit(allocator);
//             defer client.close() catch {};

//             try testing.expectError(error.Eof, client.conn.write("hello"));
//         }

//         fn runTest() !void {
//             const allocator = testing.allocator;

//             const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
//             var server = try Server.init(
//                 allocator,
//                 listen_addr,
//                 .{},
//                 .{ .min_version = .v1_3 },
//             );
//             defer server.deinit();

//             const t = try std.Thread.spawn(
//                 .{},
//                 testClient,
//                 .{ server.server.listen_address, allocator },
//             );
//             defer t.join();

//             try testServer(&server);
//         }
//     }.runTest();
// }

test "Connect to localhost" {
    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;

    testing.log_level = .debug;

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
            std.log.info("response:\n{s}", .{buffer[0..n]});
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
    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;

    testing.log_level = .debug;

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
            std.log.info("response:\n{s}", .{buffer[0..n]});
            try testing.expect(mem.startsWith(u8, buffer[0..n], "HTTP/1.1 200 OK\r\n"));
        }

        fn runTest() !void {
            const allocator = testing.allocator;
            const addr = try std.net.Address.parseIp("160.16.94.194", 443);
            try testClient(addr, allocator);
        }
    }.runTest();
}
