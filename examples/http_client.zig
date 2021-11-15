const std = @import("std");
const mem = std.mem;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const http = @import("http");

const Client = struct {
    pub const Config = struct {
        recv_buf_ini_len: usize = 1024,
        recv_buf_max_len: usize = 8192,
        send_buf_len: usize = 4096,
    };

    io: *IO,
    allocator: *mem.Allocator,
    config: *const Config,
    linked_completion: IO.LinkedCompletion = undefined,
    socket: os.socket_t = undefined,
    send_buf: []u8,
    recv_buf: []u8,
    connect_timeout: u63 = 500 * time.ns_per_ms,
    send_timeout: u63 = 500 * time.ns_per_ms,
    recv_timeout: u63 = 500 * time.ns_per_ms,
    done: bool = false,
    state: enum {
        Initial,
        Sending1,
        Sending2,
        Receiving,
    } = .Initial,

    const Self = @This();

    pub fn init(
        allocator: *mem.Allocator,
        io: *IO,
        config: *const Config,
    ) !Self {
        const recv_buf = try allocator.alloc(u8, config.recv_buf_ini_len);
        const send_buf = try allocator.alloc(u8, config.send_buf_len);
        return Self{
            .allocator = allocator,
            .io = io,
            .config = config,
            .recv_buf = recv_buf,
            .send_buf = send_buf,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.send_buf);
        self.allocator.free(self.recv_buf);
    }

    fn connect(self: *Self, addr: std.net.Address) !void {
        self.socket = try os.socket(addr.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);

        self.io.connectWithTimeout(
            *Self,
            self,
            connectCallback,
            &self.linked_completion,
            self.socket,
            addr,
            self.connect_timeout,
        );
    }
    fn connectCallback(
        self: *Self,
        comp: *IO.LinkedCompletion,
        result: IO.ConnectError!void,
    ) void {
        if (result) |_| {
            self.state = .Sending1;
            var fbs = std.io.fixedBufferStream(self.send_buf);
            var w = fbs.writer();
            std.fmt.format(w, "{s} {s} {s}\r\n", .{
                (http.Method{ .get = undefined }).toText(),
                "/",
                // "/" ++ "a" ** 8192,
                http.Version.http1_1.toText(),
            }) catch unreachable;
            std.fmt.format(w, "Host: example.com\r\n", .{}) catch unreachable;

            std.fmt.format(w, "X-Foo: ", .{}) catch unreachable;
            var pos = fbs.getPos() catch unreachable;
            std.debug.print("pos={}, self.send_buf.len={}\n", .{ pos, self.send_buf.len });
            while (pos < self.send_buf.len) : (pos += 1) {
                self.send_buf[pos] = 'f';
            }
            std.debug.print("self.send_buf={s}\n", .{self.send_buf});
            self.io.sendWithTimeout(
                *Self,
                self,
                sendCallback,
                &self.linked_completion,
                self.socket,
                self.send_buf,
                0,
                self.send_timeout,
            );
        } else |err| {
            std.debug.print("MyContext.connectCallback, err={s}\n", .{@errorName(err)});
            self.close();
        }
    }
    fn sendCallback(
        self: *Self,
        comp: *IO.LinkedCompletion,
        result: IO.SendError!usize,
    ) void {
        if (result) |_| {
            switch (self.state) {
                .Sending1 => {
                    self.state = .Sending2;
                    self.io.sendWithTimeout(
                        *Self,
                        self,
                        sendCallback,
                        &self.linked_completion,
                        self.socket,
                        "\r\n\r\n",
                        0,
                        self.send_timeout,
                    );
                },
                .Sending2 => {
                    self.state = .Receiving;
                    self.io.recvWithTimeout(
                        *Self,
                        self,
                        recvCallback,
                        &self.linked_completion,
                        self.socket,
                        self.recv_buf,
                        0,
                        self.recv_timeout,
                    );
                },
                else => @panic("unexpected state sendCallback"),
            }
        } else |err| {
            std.debug.print("MyContext.sendCallback, err={s}\n", .{@errorName(err)});
            self.close();
        }
    }
    fn recvCallback(
        self: *Self,
        comp: *IO.LinkedCompletion,
        result: IO.RecvError!usize,
    ) void {
        if (result) |received| {
            std.debug.print("response={s}", .{self.recv_buf[0..received]});
        } else |err| {
            std.debug.print("MyContext.recvCallback, err={s}\n", .{@errorName(err)});
        }
        self.close();
    }

    fn close(self: *Self) void {
        os.closeSocket(self.socket);
        self.done = true;
    }
};

const port_max = 65535;

pub fn main() anyerror!void {
    var port: u16 = 3131;
    if (os.getenv("PORT")) |port_str| {
        if (std.fmt.parseInt(u16, port_str, 10)) |v| {
            if (v <= port_max) port = v;
        } else |err| {
            std.debug.print("bad port value={s}, err={s}\n", .{ port_str, @errorName(err) });
        }
    }
    std.debug.print("port={d}\n", .{port});
    const address = try std.net.Address.parseIp4("127.0.0.1", port);

    var io = try IO.init(32, 0);
    defer io.deinit();

    const allocator = std.heap.page_allocator;
    const config = Client.Config{};
    var client = try Client.init(allocator, &io, &config);
    defer client.deinit();

    try client.connect(address);
    while (!client.done) {
        try io.run_for_ns(100 * time.ns_per_ms);
    }
}
