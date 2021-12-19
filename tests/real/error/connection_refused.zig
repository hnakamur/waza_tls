const std = @import("std");

const http = @import("http");
const IO = @import("tigerbeetle-io").IO;

const testing = std.testing;

test "real / error / connection refused" {
    // testing.log_level = .debug;

    try struct {
        const Context = @This();
        const Client = http.Client(Context);
        const Server = http.Server(Context, Handler);

        const Handler = struct {
            conn: *Server.Conn = undefined,

            pub fn start(_: *Handler) void {}
        };

        fn connectCallback(
            self: *Context,
            result: IO.ConnectError!void,
        ) void {
            self.connect_result = result;
            self.client.done = true;
        }

        client: Client = undefined,
        server: Server = undefined,
        connect_result: IO.ConnectError!void = undefined,

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const allocator = testing.allocator;

            // Use a random port
            const address = try std.net.Address.parseIp4("127.0.0.1", 0);

            var self: Context = .{};

            self.server = try Server.init(allocator, &io, &self, address, .{});
            const bound_address = self.server.bound_address;
            self.server.deinit();

            self.client = try Client.init(allocator, &io, &self, &.{});
            defer self.client.deinit();

            try self.client.connect(bound_address, connectCallback);

            while (!self.client.done) {
                try io.tick();
            }

            try testing.expectError(error.ConnectionRefused, self.connect_result);
        }
    }.runTest();
}
