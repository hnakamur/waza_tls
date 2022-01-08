const std = @import("std");
const mem = std.mem;
const net = std.net;
const Conn = @import("conn.zig").Conn;

const Server = struct {
    server: net.StreamServer,
    connections: std.ArrayListUnmanaged(ServerConn),
    allocator: mem.Allocator,

    pub fn init(
        allocator: mem.Allocator,
        address: net.Address,
        options: net.StreamServer.Options,
    ) !Server {
        var server = net.StreamServer.init(options);
        try server.listen(address);
        return Server{
            .server = server,
            .connections = try std.ArrayListUnmanaged(ServerConn).initCapacity(allocator, 1),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Server) void {
        self.connections.deinit(self.allocator);
    }

    pub fn accept(self: *Server) !ServerConn {
        var conn = try self.server.accept();
        var sc = ServerConn{
            .address = conn.address,
            .conn = Conn.init(conn.stream, .{}, .{}, .{}),
        };
        try self.connections.append(self.allocator, sc);
        return sc;
    }
};

const ServerConn = struct {
    address: net.Address,
    conn: Conn,
};

const Client = struct {
    conn: Conn,

    pub fn init(addr: net.Address) !Client {
        var stream = try net.tcpConnectToAddress(addr);
        return Client{ .conn = Conn.init(stream, .{}, .{}, .{}) };
    }

    pub fn close(self: *Client) void {
        self.conn.stream.close();
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

        fn testClient(addr: net.Address) !void {
            var client = try Client.init(addr);
            defer client.close();

            var buf: [100]u8 = undefined;
            const len = try client.conn.raw_input.read(&buf);
            const msg = buf[0..len];
            try testing.expect(mem.eql(u8, msg, "hello from server\n"));
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var server = try Server.init(allocator, listen_addr, .{});
            defer server.deinit();

            const t = try std.Thread.spawn(.{}, testClient, .{server.server.listen_address});
            defer t.join();

            try testServer(&server);
        }
    }.runTest();
}

test "Conn ClientServer" {
    const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
    const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
    const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
    const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;

    testing.log_level = .debug;
    try struct {
        fn testServer(server: *Server) !void {
            var client = try server.accept();
            const allocator = server.allocator;
            defer client.conn.deinit(allocator);
            var msg = try client.conn.readClientHello(allocator);
            defer msg.deinit(allocator);

            std.log.debug("testServer msg={}", .{msg});
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), client.conn.version);
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(addr);
            defer client.close();

            var client_hello = blk: {
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
                    .vers = .v1_2,
                    .random = &[_]u8{0} ** 32,
                    .session_id = &[_]u8{0} ** 32,
                    .cipher_suites = cipher_suites,
                    .compression_methods = compression_methods,
                };
            };
            defer client_hello.deinit(allocator);

            const client_hello_bytes = try client_hello.marshal(allocator);
            try client.conn.writeRecord(allocator, .handshake, client_hello_bytes);
        }

        fn runTest() !void {
            const allocator = testing.allocator;

            const listen_addr = try net.Address.parseIp("127.0.0.1", 0);
            var server = try Server.init(allocator, listen_addr, .{});
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
