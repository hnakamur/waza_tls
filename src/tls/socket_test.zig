const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const net = std.net;

const testing = std.testing;

// Run this test with the following command:
// zig build test -Dtest-filter="listen on a port, send bytes, receive bytes"
// or
// zig test --test-evented-io src/tls/socket_test.zig

test "listen on a port, send bytes, receive bytes" {
    if (!std.io.is_async) return error.SkipZigTest;

    if (builtin.os.tag != .linux and !builtin.os.tag.isDarwin()) {
        // TODO build abstractions for other operating systems
        return error.SkipZigTest;
    }

    // TODO doing this at comptime crashed the compiler
    const localhost = try net.Address.parseIp("127.0.0.1", 0);

    var server = net.StreamServer.init(net.StreamServer.Options{});
    defer server.deinit();
    try server.listen(localhost);

    var server_frame = async testServer(&server);
    var client_frame = async testClient(server.listen_address);

    try await server_frame;
    try await client_frame;
}

fn testClient(addr: net.Address) anyerror!void {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const socket_file = try net.tcpConnectToAddress(addr);
    defer socket_file.close();

    var buf: [100]u8 = undefined;
    const len = try socket_file.read(&buf);
    const msg = buf[0..len];
    try testing.expect(mem.eql(u8, msg, "hello from server\n"));
}

fn testServer(server: *net.StreamServer) anyerror!void {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    var client = try server.accept();

    const stream = client.stream.writer();
    try stream.print("hello from server\n", .{});
}
