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
            .conn = .{ .stream = conn.stream, .in = .{}, .out = .{}, },
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
        return Client{ .conn = .{ .stream = stream, .in = .{}, .out = .{} } };
    }

    pub fn close(self: *Client) void {
        self.conn.stream.close();
    }
};


const testing = std.testing;

test "ClientServer" {
    try struct {
        fn testServer(server: *Server) !void {
            var client = try server.accept();
            var writer = client.conn.stream.writer();
            try writer.print("hello from server\n", .{});
        }

        fn testClient(addr: net.Address) !void {
            var client = try Client.init(addr);
            defer client.close();

            var buf: [100]u8 = undefined;
            const len = try client.conn.stream.read(&buf);
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
