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
            .conn = Conn.init(
                self.allocator,
                .server,
                conn.stream,
                .{},
                .{},
                .{ .max_version = .v1_2 },
            ),
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

    pub fn init(allocator: mem.Allocator, addr: net.Address) !Client {
        var stream = try net.tcpConnectToAddress(addr);
        return Client{
            .conn = Conn.init(allocator, .client, stream, .{}, .{}, .{ .max_version = .v1_2 }),
        };
    }

    pub fn deinit(self: *Client, allocator: mem.Allocator) void {
        self.conn.deinit(allocator);
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

        fn testClient(allocator: mem.Allocator, addr: net.Address) !void {
            var client = try Client.init(allocator, addr);
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

    testing.log_level = .debug;
    try struct {
        fn testServer(server: *Server) !void {
            var client = try server.accept();
            const allocator = server.allocator;
            defer client.conn.deinit(allocator);
            std.log.debug(
                "testServer &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            // try client.conn.handshake(allocator);
            var buffer = [_]u8{0} ** 1024;
            const n = try client.conn.read(&buffer);
            try testing.expectEqual(@as(?ProtocolVersion, .v1_2), client.conn.version);
            try testing.expectEqualStrings("hello", buffer[0..n]);
        }

        fn testClient(addr: net.Address, allocator: mem.Allocator) !void {
            var client = try Client.init(allocator, addr);
            defer client.deinit(allocator);
            defer client.close();

            std.log.debug(
                "testClient &client.conn=0x{x} &client.conn.in=0x{x}, &client.conn.out=0x{x}",
                .{ @ptrToInt(&client.conn), @ptrToInt(&client.conn.in), @ptrToInt(&client.conn.out) },
            );
            // try client.conn.handshake(allocator);
            _ = try client.conn.write("hello");
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
