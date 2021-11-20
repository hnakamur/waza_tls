const std = @import("std");
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const datetime = @import("datetime");
const RecvRequest = @import("recv_request.zig").RecvRequest;
const RecvRequestScanner = @import("recv_request.zig").RecvRequestScanner;
const Method = @import("method.zig").Method;
const StatusCode = @import("status_code.zig").StatusCode;
const Version = @import("version.zig").Version;
const config = @import("config.zig");

pub fn Server(
    comptime Handler: type,
) type {
    return struct {
        const Self = @This();

        io: IO,
        server: os.socket_t,
        allocator: *mem.Allocator,
        connections: std.ArrayList(?*Conn),
        shutdown_requested: bool = false,
        done: bool = false,

        fn init(allocator: *mem.Allocator, address: std.net.Address) !Self {
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

            var self: Self = .{
                .io = try IO.init(256, 0),
                .server = server,
                .allocator = allocator,
                .connections = std.ArrayList(?*Conn).init(allocator),
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            os.close(self.server);
            self.connections.deinit();
            self.io.deinit();
        }

        pub fn run(self: *Self) !void {
            var server_completion: IO.Completion = undefined;
            self.io.accept(*Self, self, acceptCallback, &server_completion, self.server, 0);
            while (!self.done) {
                try self.io.run_for_ns(time.ns_per_s);
            }
        }

        fn acceptCallback(
            self: *Self,
            completion: *IO.Completion,
            result: IO.AcceptError!os.socket_t,
        ) void {
            std.debug.print("acceptCallback\n", .{});
            const accepted_sock = result catch @panic("accept error");
            var conn = self.createConn(accepted_sock) catch @panic("conn create error");
            conn.start() catch @panic("conn");
            self.io.accept(*Self, self, acceptCallback, completion, self.server, 0);
        }

        fn createConn(self: *Self, accepted_sock: os.socket_t) !*Conn {
            const conn_id = if (self.findEmptyConnId()) |id| id else self.connections.items.len;
            std.debug.print("client_handler_id={d}\n", .{conn_id});
            const conn = try Conn.init(self, conn_id, self.allocator, &self.io, accepted_sock);
            std.debug.print("conn=0x{x}\n", .{@ptrToInt(conn)});
            if (conn_id < self.connections.items.len) {
                self.connections.items[conn_id] = conn;
            } else {
                try self.connections.append(conn);
            }
            return conn;
        }

        fn findEmptyConnId(self: *Self) ?usize {
            for (self.connections.items) |h, i| {
                std.debug.print("findEmptyConnId, i={d}\n", .{i});
                if (h) |_| {
                    std.debug.print("handler is running, i={d}\n", .{i});
                } else {
                    return i;
                }
            }
            return null;
        }

        fn removeConnId(self: *Self, conn_id: usize) void {
            self.connections.items[conn_id] = null;
            if (self.shutdown_requested) {
                self.setDoneIfNoClient();
            }
        }

        pub fn requestShutdown(self: *Self) void {
            self.shutdown_requested = true;
            std.debug.print("set Self.shutdown_requested to true\n", .{});
            for (self.connections.items) |conn, i| {
                if (conn) |c| {
                    if (!c.processing) {
                        c.close();
                        std.debug.print("closed client_handler id={d}\n", .{i});
                    }
                }
            }
            self.setDoneIfNoClient();
        }

        fn setDoneIfNoClient(self: *Self) void {
            for (self.connections.items) |h| {
                if (h) |_| {
                    return;
                }
            }

            self.done = true;
        }

        const Conn = struct {
            handler: Handler = undefined,
            server: *Self,
            conn_id: usize,
            io: *IO,
            linked_completion: IO.LinkedCompletion = undefined,
            sock: os.socket_t,
            recv_buf: []u8,
            send_buf: []u8,
            allocator: *mem.Allocator,
            recv_timeout_ns: u63 = 5 * time.ns_per_s,
            send_timeout_ns: u63 = 5 * time.ns_per_s,
            request_scanner: *RecvRequestScanner,
            request_version: Version = undefined,
            keep_alive: bool = true,
            req_content_length: ?u64 = null,
            content_length_read_so_far: u64 = 0,
            processing: bool = false,
            resp_headers_len: u64 = 0,
            content_length: u64 = 0,
            content_len_sent_so_far: u64 = 0,
            sent_bytes_so_far: u64 = 0,
            send_buf_data_len: u64 = 0,
            send_buf_sent_len: u64 = 0,
            state: enum {
                ReceivingHeaders,
                ReceivingContent,
                SendingHeaders,
                SendingContent,
            } = .ReceivingHeaders,

            fn init(server: *Self, conn_id: usize, allocator: *mem.Allocator, io: *IO, sock: os.socket_t) !*Conn {
                const req_scanner = try allocator.create(RecvRequestScanner);
                req_scanner.* = RecvRequestScanner{};
                const recv_buf = try allocator.alloc(u8, config.recv_buf_ini_len);
                const send_buf = try allocator.alloc(u8, 1024);
                var self = try allocator.create(Conn);
                const handler = Handler{};
                self.* = Conn{
                    .handler = handler,
                    .server = server,
                    .conn_id = conn_id,
                    .io = io,
                    .sock = sock,
                    .request_scanner = req_scanner,
                    .recv_buf = recv_buf,
                    .send_buf = send_buf,
                    .allocator = allocator,
                };
                return self;
            }

            fn deinit(self: *Conn) !void {
                self.server.removeConnId(self.conn_id);
                self.allocator.destroy(self.request_scanner);
                self.allocator.free(self.send_buf);
                self.allocator.free(self.recv_buf);
                self.allocator.destroy(self);
            }

            fn close(self: *Conn) void {
                os.closeSocket(self.sock);
                if (self.deinit()) |_| {} else |err| {
                    std.debug.print("Conn deinit err={s}\n", .{@errorName(err)});
                }
                std.debug.print("close and exit\n", .{});
            }

            fn start(self: *Conn) !void {
                self.handler.hook(self);
                self.recvWithTimeout(self.recv_buf);
            }

            fn recvWithTimeout(
                self: *Conn,
                buf: []u8,
            ) void {
                std.debug.print("recvWithTimeout conn_id={d}\n", .{self.conn_id});
                self.io.recvWithTimeout(
                    *Conn,
                    self,
                    recvCallback,
                    &self.linked_completion,
                    self.sock,
                    buf,
                    0,
                    self.recv_timeout_ns,
                );
            }
            fn recvCallback(
                self: *Conn,
                completion: *IO.LinkedCompletion,
                result: IO.RecvError!usize,
            ) void {
                if (result) |received| {
                    std.debug.print("received={d}\n", .{received});

                    if (received == 0) {
                        if (self.request_scanner.totalBytesRead() > 0) {
                            std.debug.print("closed from client during request, close connection.\n", .{});
                        }
                        self.close();
                        return;
                    }

                    self.handleStreamingRequest(received);
                } else |err| {
                    std.debug.print("recv error: {s}\n", .{@errorName(err)});
                }
            }

            fn handleStreamingRequest(self: *Conn, received: usize) void {
                switch (self.state) {
                    .ReceivingHeaders => {
                        self.processing = true;
                        const old = self.request_scanner.totalBytesRead();
                        std.debug.print("handleStreamingRequest old={}, received={}\n", .{ old, received });
                        std.debug.print("handleStreamingRequest scan data={s}\n", .{self.recv_buf[old .. old + received]});
                        if (self.request_scanner.scan(self.recv_buf[old .. old + received])) |done| {
                            if (done) {
                                self.state = .ReceivingContent;
                                const total = self.request_scanner.totalBytesRead();
                                if (RecvRequest.init(self.recv_buf[0..total], self.request_scanner)) |req| {
                                    std.debug.print("request method={s}, version={s}, url={s}, headers=\n{s}\n", .{
                                        req.method.toText(),
                                        req.version.toText(),
                                        req.uri,
                                        req.headers.fields,
                                    });
                                    if (req.isKeepAlive()) |keep_alive| {
                                        self.keep_alive = keep_alive;
                                    } else |err| {
                                        self.sendError(.http_version_not_supported);
                                        return;
                                    }
                                    self.request_version = req.version;
                                    self.req_content_length = if (req.headers.getContentLength()) |len| len else |err| {
                                        std.debug.print("bad request, invalid content-length, err={s}\n", .{@errorName(err)});
                                        self.sendError(.bad_request);
                                        return;
                                    };
                                    if (self.req_content_length) |len| {
                                        std.debug.print("content_length={}\n", .{len});
                                        const actual_content_chunk_len = old + received - total;
                                        self.content_length_read_so_far += actual_content_chunk_len;
                                        std.debug.print("first content chunk length={},\ncontent=\n{s}", .{
                                            actual_content_chunk_len,
                                            self.recv_buf[total .. old + received],
                                        });
                                        if (actual_content_chunk_len < len) {
                                            self.io.recvWithTimeout(
                                                *Conn,
                                                self,
                                                recvCallback,
                                                &self.linked_completion,
                                                self.sock,
                                                self.recv_buf,
                                                0,
                                                self.recv_timeout_ns,
                                            );
                                            return;
                                        }
                                    }
                                } else |err| {
                                    self.sendError(.bad_request);
                                    return;
                                }
                                self.sendResponseWithTimeout();
                            } else {
                                std.debug.print("handleStreamingRequest not done\n", .{});
                                if (old + received == self.recv_buf.len) {
                                    const new_len = self.recv_buf.len + config.recv_buf_ini_len;
                                    if (config.recv_buf_max_len < new_len) {
                                        std.debug.print("request header fields too long.\n", .{});
                                        self.sendError(.bad_request);
                                        return;
                                    }
                                    self.recv_buf = self.allocator.realloc(self.recv_buf, new_len) catch unreachable;
                                }
                                self.io.recvWithTimeout(
                                    *Conn,
                                    self,
                                    recvCallback,
                                    &self.linked_completion,
                                    self.sock,
                                    self.recv_buf[old + received ..],
                                    0,
                                    self.recv_timeout_ns,
                                );
                            }
                        } else |err| {
                            std.debug.print("handleStreamingRequest scan failed with {s}\n", .{@errorName(err)});
                            self.sendError(switch (err) {
                                error.UriTooLong => .uri_too_long,
                                error.VersionNotSupported => .http_version_not_supported,
                                else => .bad_request,
                            });
                        }
                    },
                    .ReceivingContent => {
                        std.debug.print("{s}", .{self.recv_buf[0..received]});
                        self.content_length_read_so_far += received;
                        if (self.content_length_read_so_far < self.req_content_length.?) {
                            self.io.recvWithTimeout(
                                *Conn,
                                self,
                                recvCallback,
                                &self.linked_completion,
                                self.sock,
                                self.recv_buf,
                                0,
                                self.recv_timeout_ns,
                            );
                            return;
                        }
                        self.sendResponseWithTimeout();
                    },
                    else => @panic("unexpected state in recvCallback"),
                }
            }

            fn sendError(self: *Conn, status_code: StatusCode) void {
                var fbs = std.io.fixedBufferStream(self.send_buf);
                var w = fbs.writer();
                std.fmt.format(w, "{s} {d} {s}\r\n", .{
                    Version.http1_1.toText(),
                    status_code.code(),
                    status_code.toText(),
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

                self.keep_alive = false;
                std.fmt.format(w, "Connection: {s}\r\n", .{"close"}) catch unreachable;
                std.fmt.format(w, "Content-Length: 0\r\n", .{}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
                self.io.sendWithTimeout(
                    *Conn,
                    self,
                    sendCallback,
                    &self.linked_completion,
                    self.sock,
                    fbs.getWritten(),
                    0,
                    self.send_timeout_ns,
                );
            }

            fn sendResponseWithTimeout(self: *Conn) void {
                var fbs = std.io.fixedBufferStream(self.send_buf);
                var w = fbs.writer();
                std.fmt.format(w, "{s} {d} {s}\r\n", .{
                    Version.http1_1.toText(),
                    StatusCode.ok.code(),
                    StatusCode.ok.toText(),
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

                switch (self.request_version) {
                    .http1_1 => if (!self.keep_alive) {
                        std.fmt.format(w, "Connection: {s}\r\n", .{"close"}) catch unreachable;
                        std.debug.print("wrote connection: close for HTTP/1.1\n", .{});
                    },
                    .http1_0 => if (self.keep_alive) {
                        std.debug.print("wrote connection: keep-alive for HTTP/1.0\n", .{});
                        std.fmt.format(w, "Connection: {s}\r\n", .{"keep-alive"}) catch unreachable;
                    },
                    else => {},
                }
                self.content_length = 2048;
                std.fmt.format(w, "Content-Length: {d}\r\n", .{self.content_length}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
                var pos = fbs.getPos() catch unreachable;
                self.resp_headers_len = pos;
                while (pos < self.send_buf.len) : (pos += 1) {
                    self.send_buf[pos] = 'e';
                }
                self.send_buf_data_len = self.send_buf.len;
                self.send_buf_sent_len = 0;
                self.state = .SendingHeaders;
                self.io.sendWithTimeout(
                    *Conn,
                    self,
                    sendCallback,
                    &self.linked_completion,
                    self.sock,
                    self.send_buf[0..self.send_buf_data_len],
                    0,
                    self.send_timeout_ns,
                );
            }
            fn sendCallback(
                self: *Conn,
                completion: *IO.LinkedCompletion,
                result: IO.SendError!usize,
            ) void {
                if (result) |sent| {
                    std.debug.print("sent response bytes={d}\n", .{sent});
                    self.send_buf_sent_len += sent;
                    self.sent_bytes_so_far += sent;
                    if (self.send_buf_sent_len < self.send_buf_data_len) {
                        self.io.sendWithTimeout(
                            *Conn,
                            self,
                            sendCallback,
                            &self.linked_completion,
                            self.sock,
                            self.send_buf[self.send_buf_sent_len..self.send_buf_data_len],
                            0,
                            self.send_timeout_ns,
                        );
                        return;
                    }

                    switch (self.state) {
                        .SendingHeaders => {
                            self.state = .SendingContent;
                            self.send_buf_data_len = std.math.min(
                                self.content_length - (self.sent_bytes_so_far - self.resp_headers_len),
                                self.send_buf.len,
                            );
                            self.send_buf_sent_len = 0;
                            var pos: usize = 0;
                            while (pos < self.send_buf_data_len) : (pos += 1) {
                                self.send_buf[pos] = 'f';
                            }
                            self.io.sendWithTimeout(
                                *Conn,
                                self,
                                sendCallback,
                                &self.linked_completion,
                                self.sock,
                                self.send_buf[0..self.send_buf_data_len],
                                0,
                                self.send_timeout_ns,
                            );
                            return;
                        },
                        .SendingContent => {
                            self.send_buf_data_len = std.math.min(
                                self.content_length - (self.sent_bytes_so_far - self.resp_headers_len),
                                self.send_buf.len,
                            );
                            if (self.send_buf_data_len > 0) {
                                self.send_buf_sent_len = 0;
                                var pos: usize = 0;
                                while (pos < self.send_buf_data_len) : (pos += 1) {
                                    self.send_buf[pos] = 'g';
                                }
                                self.io.sendWithTimeout(
                                    *Conn,
                                    self,
                                    sendCallback,
                                    &self.linked_completion,
                                    self.sock,
                                    self.send_buf[0..self.send_buf_data_len],
                                    0,
                                    self.send_timeout_ns,
                                );
                                return;
                            }
                        },
                        else => @panic("unexpected state in sendCallback"),
                    }

                    if (!self.keep_alive or self.server.shutdown_requested) {
                        self.close();
                        return;
                    }

                    self.processing = false;
                    self.request_scanner.* = RecvRequestScanner{};
                    self.recvWithTimeout(self.recv_buf);
                } else |err| {
                    std.debug.print("send error: {s}\n", .{@errorName(err)});
                    self.close();
                }
            }
        };
    };
}

const testing = std.testing;

test "Server" {
    const Handler = struct {
        const Self = @This();
        pub const MyServer = Server(Self);

        some_data: usize = undefined,

        fn hook(self: *Self, conn: *MyServer.Conn) void {
            std.debug.print("hook called, self=0x{x}, conn=0x{x}, conn_id={}\n", .{ @ptrToInt(self), @ptrToInt(conn), conn.conn_id });
        }
    };

    try struct {
        fn runTest() !void {
            var allocator = testing.allocator;
            const address = try std.net.Address.parseIp4("127.0.0.1", 3131);

            var svr = try Handler.MyServer.init(allocator, address);
            defer svr.deinit();

            try svr.run();
        }
    }.runTest();
}
