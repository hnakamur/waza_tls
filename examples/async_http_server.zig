const std = @import("std");
const mem = std.mem;
const net = std.net;
const os = std.os;
const IO = @import("tigerbeetle-io").IO;
const http = @import("http");
const datetime = @import("datetime");

const ClientHandler = struct {
    io: *IO,
    sock: os.socket_t,
    recv_buf: []u8,
    send_buf: []u8,
    allocator: mem.Allocator,
    completion: IO.Completion = undefined,
    frame: anyframe = undefined,
    send_result: IO.SendError!usize = undefined,
    recv_result: IO.RecvError!usize = undefined,
    close_result: IO.CloseError!void = undefined,
    timeout_result: IO.TimeoutError!void = undefined,
    request_scanner: *http.RecvRequestScanner,
    request: ?*http.RecvRequest = null,

    fn init(allocator: mem.Allocator, io: *IO, sock: os.socket_t) !*ClientHandler {
        const req_scanner = try allocator.create(http.RecvRequestScanner);
        req_scanner.* = http.RecvRequestScanner{};
        const recv_buf = try allocator.alloc(u8, 8192);
        const send_buf = try allocator.alloc(u8, 8192);
        var self = try allocator.create(ClientHandler);
        self.* = ClientHandler{
            .io = io,
            .sock = sock,
            .request_scanner = req_scanner,
            .recv_buf = recv_buf,
            .send_buf = send_buf,
            .allocator = allocator,
        };
        return self;
    }

    fn deinit(self: *ClientHandler) !void {
        self.allocator.destroy(self.request_scanner);
        self.allocator.free(self.send_buf);
        self.allocator.free(self.recv_buf);
        self.allocator.destroy(self);
    }

    fn start(self: *ClientHandler) !void {
        defer self.deinit() catch unreachable; // TODO: log error
        defer self.close(self.sock) catch unreachable; // TODO: log error

        while (true) {
            const old = self.request_scanner.totalBytesRead();
            const received = try self.recv(self.sock, self.recv_buf[old..]);
            if (received == 0) {
                return;
            }

            if (self.request_scanner.scan(self.recv_buf[old .. old + received])) |done| {
                if (done) {
                    _ = try self.timeout(std.time.ns_per_s);

                    const num_read = self.request_scanner.totalBytesRead();
                    self.request = try self.allocator.create(http.RecvRequest);
                    self.request.?.* = try http.RecvRequest.init(self.recv_buf[0..num_read], self.request_scanner);
                    // TODO read request body chunk from self.recv_buf[num_read..]

                    var fbs = std.io.fixedBufferStream(self.send_buf);
                    var w = fbs.writer();
                    try std.fmt.format(w, "{s} {d} {s}\r\n", .{
                        http.Version.http1_1.toBytes(),
                        http.StatusCode.ok.code(),
                        http.StatusCode.ok.toText(),
                    });
                    try http.writeDatetimeHeader(w, "Date", datetime.datetime.Datetime.now());
                    const body = "Hello http server\n";
                    try std.fmt.format(w, "Content-Length: {d}\r\n", .{body.len});
                    try std.fmt.format(w, "\r\n", .{});
                    if (body.len > 0) {
                        try std.fmt.format(w, "{s}", .{body});
                    }
                    _ = try self.send(self.sock, fbs.getWritten());
                    self.request_scanner.* = http.RecvRequestScanner{};
                } else {
                    // TODO: implement
                    unreachable;
                }
            } else |err| {
                // TODO: implement
                unreachable;
            }
        }
    }

    fn send(self: *ClientHandler, sock: os.socket_t, buffer: []const u8) IO.SendError!usize {
        self.io.send(
            *ClientHandler,
            self,
            send_callback,
            &self.completion,
            self.sock,
            buffer,
            if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
        );
        suspend {
            self.frame = @frame();
        }
        return self.send_result;
    }
    fn send_callback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.SendError!usize,
    ) void {
        self.send_result = result;
        resume self.frame;
    }

    fn recv(self: *ClientHandler, sock: os.socket_t, buffer: []u8) IO.RecvError!usize {
        self.io.recv(
            *ClientHandler,
            self,
            recv_callback,
            &self.completion,
            self.sock,
            buffer,
            if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
        );
        suspend {
            self.frame = @frame();
        }
        return self.recv_result;
    }
    fn recv_callback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.RecvError!usize,
    ) void {
        self.recv_result = result;
        resume self.frame;
    }

    fn close(self: *ClientHandler, sock: os.socket_t) IO.CloseError!void {
        self.io.close(
            *ClientHandler,
            self,
            close_callback,
            &self.completion,
            self.sock,
        );
        suspend {
            self.frame = @frame();
        }
        return self.close_result;
    }
    fn close_callback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.CloseError!void,
    ) void {
        self.close_result = result;
        resume self.frame;
    }

    fn timeout(self: *ClientHandler, nanoseconds: u63) IO.TimeoutError!void {
        self.io.timeout(
            *ClientHandler,
            self,
            timeout_callback,
            &self.completion,
            nanoseconds,
        );
        suspend {
            self.frame = @frame();
        }
        return self.timeout_result;
    }
    fn timeout_callback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        self.timeout_result = result;
        resume self.frame;
    }
};

const Server = struct {
    io: IO,
    server: os.socket_t,
    allocator: mem.Allocator,
    completion: IO.Completion = undefined,
    frame: anyframe = undefined,
    accept_result: IO.AcceptError!os.socket_t = undefined,

    fn init(allocator: mem.Allocator, address: std.net.Address) !Server {
        const kernel_backlog = 513;
        const server = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);

        try os.setsockopt(
            server,
            os.SOL_SOCKET,
            os.SO_REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );
        try os.bind(server, &address.any, address.getOsSockLen());
        try os.listen(server, kernel_backlog);

        var self: Server = .{
            .io = try IO.init(256, 0),
            .server = server,
            .allocator = allocator,
        };

        return self;
    }

    pub fn deinit(self: *Server) void {
        os.close(self.server);
        self.io.deinit();
    }

    pub fn start(self: *Server) !void {
        while (true) {
            const ClientHandler_sock = try self.accept(self.server, 0);
            var handler = try ClientHandler.init(self.allocator, &self.io, ClientHandler_sock);
            try handler.start();
        }
    }

    pub fn run(self: *Server) !void {
        while (true) try self.io.tick();
    }

    fn accept(self: *Server, server_sock: os.socket_t, flags: u32) IO.AcceptError!os.socket_t {
        self.io.accept(*Server, self, accept_callback, &self.completion, server_sock, flags);
        suspend {
            self.frame = @frame();
        }
        return self.accept_result;
    }
    fn accept_callback(
        self: *Server,
        completion: *IO.Completion,
        result: IO.AcceptError!os.socket_t,
    ) void {
        self.accept_result = result;
        resume self.frame;
    }
};

pub fn main() anyerror!void {
    const allocator = std.heap.page_allocator;
    const address = try std.net.Address.parseIp4("127.0.0.1", 3131);
    var server = try Server.init(allocator, address);
    defer server.deinit();

    _ = async server.start();
    try server.run();
}
