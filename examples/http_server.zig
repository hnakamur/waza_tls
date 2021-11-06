const std = @import("std");
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const http = @import("http");
const datetime = @import("datetime");

const Server = struct {
    io: IO,
    server: os.socket_t,
    allocator: *mem.Allocator,
    client_handlers: std.ArrayList(?*ClientHandler),
    shutdown_requested: bool = false,
    done: bool = false,

    fn init(allocator: *mem.Allocator, address: std.net.Address) !Server {
        const kernel_backlog = 513;
        const server = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);

        try os.setsockopt(
            server,
            os.SOL_SOCKET,
            os.SO_REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );
        try os.bind(server, &address.any, address.getOsSockLen());
        if (address.getPort() == 0) {
            var bound_addr: std.net.Address = address;
            var bound_socklen: os.socklen_t = address.getOsSockLen();
            try os.getsockname(server, &bound_addr.any, &bound_socklen);
            std.debug.print("bound port={d}\n", .{bound_addr.getPort()});
        }

        try os.listen(server, kernel_backlog);

        var self: Server = .{
            .io = try IO.init(256, 0),
            .server = server,
            .allocator = allocator,
            .client_handlers = std.ArrayList(?*ClientHandler).init(allocator),
        };
        return self;
    }

    pub fn deinit(self: *Server) void {
        os.close(self.server);
        self.client_handlers.deinit();
        self.io.deinit();
    }

    pub fn run(self: *Server) !void {
        var server_completion: IO.Completion = undefined;
        self.io.accept(*Server, self, acceptCallback, &server_completion, self.server, 0);
        while (!self.done) {
            try self.io.run_for_ns(time.ns_per_ms);
        }
    }

    fn acceptCallback(
        self: *Server,
        completion: *IO.Completion,
        result: IO.AcceptError!os.socket_t,
    ) void {
        std.debug.print("acceptCallback\n", .{});
        const accepted_sock = result catch @panic("accept error");
        var handler = self.createClientHandler(accepted_sock) catch @panic("handler create error");
        handler.start() catch @panic("handler");
        self.io.accept(*Server, self, acceptCallback, completion, self.server, 0);
    }

    fn createClientHandler(self: *Server, accepted_sock: os.socket_t) !*ClientHandler {
        const handler_id = if (self.findEmptyClientHandlerId()) |id| id else self.client_handlers.items.len;
        std.debug.print("client_handler_id={d}\n", .{handler_id});
        const handler = try ClientHandler.init(self, handler_id, self.allocator, &self.io, accepted_sock);
        if (handler_id < self.client_handlers.items.len) {
            self.client_handlers.items[handler_id] = handler;
        } else {
            try self.client_handlers.append(handler);
        }
        return handler;
    }

    fn findEmptyClientHandlerId(self: *Server) ?usize {
        for (self.client_handlers.items) |h, i| {
            std.debug.print("findEmptyClientHandlerId, i={d}\n", .{i});
            if (h) |_| {
                std.debug.print("handler is running, i={d}\n", .{i});
            } else {
                return i;
            }
        }
        return null;
    }

    fn removeClientHandlerId(self: *Server, handler_id: usize) void {
        self.client_handlers.items[handler_id] = null;
        if (self.shutdown_requested) {
            self.setDoneIfNoClient();
        }
    }

    pub fn requestShutdown(self: *Server) void {
        self.shutdown_requested = true;
        std.debug.print("set Server.shutdown_requested to true\n", .{});
        for (self.client_handlers.items) |handler, i| {
            if (handler) |h| {
                if (!h.processing) {
                    h.close();
                    std.debug.print("closed client_handler id={d}\n", .{i});
                }
            }
        }
        self.setDoneIfNoClient();
    }

    fn setDoneIfNoClient(self: *Server) void {
        var running = false;
        for (self.client_handlers.items) |h, i| {
            if (h) |_| {
                running = true;
                break;
            }
        }

        if (!running) {
            self.done = true;
        }
    }
};

const ClientHandler = struct {
    server: *Server,
    handler_id: usize,
    io: *IO,
    sock: os.socket_t,
    received: usize = undefined,
    recv_buf: []u8,
    send_buf: []u8,
    allocator: *mem.Allocator,
    completions: [2]IO.Completion = undefined,
    recv_timeout_ns: u63 = 5 * time.ns_per_s,
    send_timeout_ns: u63 = 5 * time.ns_per_s,
    request_scanner: *http.RecvRequestScanner,
    request: ?*http.RecvRequest = null,
    processing: bool = false,

    fn init(server: *Server, handler_id: usize, allocator: *mem.Allocator, io: *IO, sock: os.socket_t) !*ClientHandler {
        const req_scanner = try allocator.create(http.RecvRequestScanner);
        req_scanner.* = http.RecvRequestScanner{};
        const recv_buf = try allocator.alloc(u8, 8192);
        const send_buf = try allocator.alloc(u8, 8192);
        var self = try allocator.create(ClientHandler);
        self.* = ClientHandler{
            .server = server,
            .handler_id = handler_id,
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
        self.server.removeClientHandlerId(self.handler_id);
        self.allocator.destroy(self.request_scanner);
        self.allocator.free(self.send_buf);
        self.allocator.free(self.recv_buf);
        self.allocator.destroy(self);
    }

    fn close(self: *ClientHandler) void {
        os.close(self.sock);
        if (self.deinit()) |_| {} else |err| {
            std.debug.print("ClientHandler deinit err={s}\n", .{@errorName(err)});
        }
        std.debug.print("close and exit\n", .{});
    }

    fn start(self: *ClientHandler) !void {
        self.recvWithTimeout();
    }

    fn recvWithTimeout(self: *ClientHandler) void {
        std.debug.print("recvWithTimeout handler_id={d}\n", .{self.handler_id});
        self.io.recv(
            *ClientHandler,
            self,
            recvCallback,
            &self.completions[0],
            self.sock,
            self.recv_buf,
            if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
        );
        self.io.timeout(
            *ClientHandler,
            self,
            recvTimeoutCallback,
            &self.completions[1],
            self.recv_timeout_ns,
        );
    }
    fn recvCallback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.RecvError!usize,
    ) void {
        if (result) |received| {
            self.received = received;
            std.debug.print("received={d}\n", .{received});
            self.io.cancelTimeout(
                *ClientHandler,
                self,
                recvTimeoutCancelCallback,
                &self.completions[0],
                &self.completions[1],
            );
        } else |err| {
            std.debug.print("recv error: {s}\n", .{@errorName(err)});
        }
    }
    fn recvTimeoutCallback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("recvTimeoutCallback ok\n", .{});
            completion.io.cancel(
                *ClientHandler,
                self,
                recvCancelCallback,
                &self.completions[1],
                &self.completions[0],
            );
        } else |err| {
            std.debug.print("recvTimeoutCallback err={s}\n", .{@errorName(err)});
        }
    }
    fn recvCancelCallback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.CancelError!void,
    ) void {
        if (result) |_| {
            std.debug.print("recvCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("recvCancelCallback err={s}\n", .{@errorName(err)});
        }
    }
    fn recvTimeoutCancelCallback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.CancelTimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("recvTimeoutCancelCallback ok\n", .{});

            if (self.received == 0) {
                self.close();
                return;
            }

            self.handleStreamingRequest(self.received);
        } else |err| {
            std.debug.print("recvTimeoutCancelCallback error: {s}\n", .{@errorName(err)});
        }
    }

    fn handleStreamingRequest(self: *ClientHandler, received: usize) void {
        self.processing = true;
        const old = self.request_scanner.total_bytes_read();
        if (self.request_scanner.scan(self.recv_buf[old .. old + received])) |done| {
            if (done) {
                self.sendResponseWithTimeout();
            } else {
                // TODO: implement
                unreachable;
            }
        } else |err| {
            // TODO: implement
            unreachable;
        }
    }

    fn sendResponseWithTimeout(self: *ClientHandler) void {
        const num_read = self.request_scanner.total_bytes_read();
        self.request = self.allocator.create(http.RecvRequest) catch unreachable;
        self.request.?.* = http.RecvRequest.init(self.allocator, self.recv_buf[0..num_read], self.request_scanner) catch unreachable;
        // TODO read request body chunk from self.recv_buf[num_read..]

        var fbs = std.io.fixedBufferStream(self.send_buf);
        var w = fbs.writer();
        std.fmt.format(w, "{s} {d} {s}\r\n", .{
            http.Version.http1_1.toText(),
            http.StatusCode.ok.code(),
            http.StatusCode.ok.toText(),
        }) catch unreachable;
        var now = datetime.datetime.Datetime.now();
        std.fmt.format(w, "Date: {s}, {d} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} {s}\r\n", .{
            now.date.weekdayName()[0..3],
            now.date.day,
            now.date.monthName()[0..3],
            now.date.year,
            now.time.hour,
            now.time.minute,
            now.time.second,
            now.zone.name,
        }) catch unreachable;
        // std.fmt.format(w, "Connection: {s}\r\n", .{"close"}) catch unreachable;
        const body = "Hello http server\n";
        std.fmt.format(w, "Content-Length: {d}\r\n", .{body.len}) catch unreachable;
        std.fmt.format(w, "\r\n", .{}) catch unreachable;
        if (body.len > 0) {
            std.fmt.format(w, "{s}", .{body}) catch unreachable;
        }
        self.io.send(
            *ClientHandler,
            self,
            sendCallback,
            &self.completions[0],
            self.sock,
            fbs.getWritten(),
            if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
        );
        self.io.timeout(
            *ClientHandler,
            self,
            sendTimeoutCallback,
            &self.completions[1],
            self.send_timeout_ns,
        );
    }
    fn sendCallback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.SendError!usize,
    ) void {
        if (result) |sent| {
            std.debug.print("sent request bytes={d}\n", .{sent});
            self.io.cancelTimeout(
                *ClientHandler,
                self,
                sendTimeoutCancelCallback,
                &self.completions[0],
                &self.completions[1],
            );
        } else |err| {
            std.debug.print("send error: {s}\n", .{@errorName(err)});
        }
    }
    fn sendTimeoutCallback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.TimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("sendTimeoutCallback ok\n", .{});
            completion.io.cancel(
                *ClientHandler,
                self,
                sendCancelCallback,
                &self.completions[1],
                &self.completions[0],
            );
        } else |err| {
            if (err != error.Canceled) {
                std.debug.print("sendTimeoutCallback err={s}\n", .{@errorName(err)});
            }
        }
    }
    fn sendCancelCallback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.CancelError!void,
    ) void {
        if (result) |_| {
            std.debug.print("sendCancelCallback ok\n", .{});
        } else |err| {
            std.debug.print("sendCancelCallback err={s}\n", .{@errorName(err)});
        }
    }
    fn sendTimeoutCancelCallback(
        self: *ClientHandler,
        completion: *IO.Completion,
        result: IO.CancelTimeoutError!void,
    ) void {
        if (result) |_| {
            std.debug.print("sendTimeoutCancelCallback ok\n", .{});

            // self.close();

            if (self.server.shutdown_requested) {
                self.close();
            } else {
                self.processing = false;
                self.recvWithTimeout();
            }
        } else |err| {
            std.debug.print("sendTimeoutCancelCallback err={s}\n", .{@errorName(err)});
        }
    }
};

fn getEnvUint(comptime T: type, name: []const u8, default: T, max: T) T {
    if (os.getenv(name)) |s| {
        if (std.fmt.parseInt(T, s, 10)) |v| {
            if (v <= max) return v;
        } else |err| {
            std.debug.print("bad environment variable \"{s}\" value={s}, err={s}\n", .{ name, s, @errorName(err) });
        }
    }
    return default;
}

var global_server: Server = undefined;

fn sigchld(signo: i32) callconv(.C) void {
    std.debug.print("got signal, signo={d}\n", .{signo});
    global_server.requestShutdown();
}

pub fn main() anyerror!void {
    const allocator = std.heap.page_allocator;

    const port_max = 65535;
    const port_default = 3131;
    const port = getEnvUint(u16, "PORT", port_default, port_max);
    const address = try std.net.Address.parseIp4("127.0.0.1", port);
    global_server = try Server.init(allocator, address);
    os.sigaction(os.SIGINT, &.{
        .handler = .{ .handler = sigchld },
        .mask = os.system.empty_sigset,
        .flags = os.system.SA_NOCLDSTOP,
    }, null);
    defer global_server.deinit();
    try global_server.run();
}
