const std = @import("std");
const assert = std.debug.assert;
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

pub fn Server(comptime Handler: type) type {
    return struct {
        const Self = @This();
        const Config = struct {
            client_header_buffer_size: usize = 1024,
            large_client_header_buffer_size: usize = 8192,
            large_client_header_buffer_max_count: usize = 4,
            client_body_buffer_size: usize = 16384,

            fn validate(self: Config) !void {
                assert(self.client_header_buffer_size > 0);
                assert(self.large_client_header_buffer_size > self.client_header_buffer_size);
                assert(self.large_client_header_buffer_max_count > 0);
                assert(self.client_body_buffer_size > 0);
            }
        };

        io: *IO,
        socket: os.socket_t,
        allocator: *mem.Allocator,
        config: Config,
        connections: std.ArrayList(?*Conn),
        shutdown_requested: bool = false,
        done: bool = false,

        fn init(allocator: *mem.Allocator, io: *IO, address: std.net.Address, config: Config) !Self {
            try config.validate();
            const kernel_backlog = 513;
            const socket = try os.socket(address.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);

            try os.setsockopt(
                socket,
                os.SOL_SOCKET,
                os.SO_REUSEADDR,
                &std.mem.toBytes(@as(c_int, 1)),
            );
            try os.bind(socket, &address.any, address.getOsSockLen());
            if (address.getPort() == 0) {
                var bound_addr: std.net.Address = address;
                var bound_socklen: os.socklen_t = address.getOsSockLen();
                try os.getsockname(socket, &bound_addr.any, &bound_socklen);
                std.debug.print("bound port={d}\n", .{bound_addr.getPort()});
            }

            try os.listen(socket, kernel_backlog);

            var self: Self = .{
                .io = io,
                .socket = socket,
                .allocator = allocator,
                .config = config,
                .connections = std.ArrayList(?*Conn).init(allocator),
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            os.close(self.socket);
            self.connections.deinit();
        }

        pub fn run(self: *Self) !void {
            var server_completion: IO.Completion = undefined;
            self.io.accept(*Self, self, acceptCallback, &server_completion, self.socket, 0);
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
            self.io.accept(*Self, self, acceptCallback, completion, self.socket, 0);
        }

        fn createConn(self: *Self, accepted_sock: os.socket_t) !*Conn {
            const conn_id = if (self.findEmptyConnId()) |id| id else self.connections.items.len;
            std.debug.print("client_handler_id={d}\n", .{conn_id});
            const conn = try Conn.init(self, conn_id, accepted_sock);
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
            socket: os.socket_t,
            conn_id: usize,
            linked_completion: IO.LinkedCompletion = undefined,
            client_header_buf: []u8,
            client_body_buf: ?[]u8 = null,
            send_buf: []u8,
            recv_timeout_ns: u63 = 5 * time.ns_per_s,
            send_timeout_ns: u63 = 5 * time.ns_per_s,
            request_scanner: *RecvRequestScanner,
            request: RecvRequest = undefined,
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

            fn init(server: *Self, conn_id: usize, socket: os.socket_t) !*Conn {
                const req_scanner = try server.allocator.create(RecvRequestScanner);
                req_scanner.* = RecvRequestScanner{};
                const client_header_buf = try server.allocator.alloc(u8, server.config.client_header_buffer_size);
                const send_buf = try server.allocator.alloc(u8, 1024);
                var self = try server.allocator.create(Conn);
                const handler = Handler{
                    .conn = self,
                };
                self.* = Conn{
                    .handler = handler,
                    .server = server,
                    .conn_id = conn_id,
                    .socket = socket,
                    .request_scanner = req_scanner,
                    .client_header_buf = client_header_buf,
                    .send_buf = send_buf,
                };
                return self;
            }

            fn deinit(self: *Conn) !void {
                self.server.removeConnId(self.conn_id);
                self.server.allocator.destroy(self.request_scanner);
                self.server.allocator.free(self.send_buf);
                if (self.client_body_buf) |buf| {
                    self.server.allocator.free(buf);
                }
                self.server.allocator.free(self.client_header_buf);
                self.server.allocator.destroy(self);
            }

            fn close(self: *Conn) void {
                os.closeSocket(self.socket);
                if (self.deinit()) |_| {} else |err| {
                    std.debug.print("Conn deinit err={s}\n", .{@errorName(err)});
                }
                std.debug.print("close and exit\n", .{});
            }

            fn start(self: *Conn) !void {
                self.recvWithTimeout(self.client_header_buf);
            }

            fn recvWithTimeout(
                self: *Conn,
                buf: []u8,
            ) void {
                std.debug.print("recvWithTimeout conn_id={d}\n", .{self.conn_id});
                self.server.io.recvWithTimeout(
                    *Conn,
                    self,
                    recvCallback,
                    &self.linked_completion,
                    self.socket,
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

                    self.handleReceivedData(received);
                } else |err| {
                    std.debug.print("recv error: {s}\n", .{@errorName(err)});
                }
            }

            fn handleReceivedData(self: *Conn, received: usize) void {
                switch (self.state) {
                    .ReceivingHeaders => {
                        self.processing = true;
                        const old = self.request_scanner.totalBytesRead();
                        std.debug.print("handleReceivedData old={}, received={}\n", .{ old, received });
                        std.debug.print("handleReceivedData scan data={s}\n", .{self.client_header_buf[old .. old + received]});
                        if (self.request_scanner.scan(self.client_header_buf[old .. old + received])) |done| {
                            if (done) {
                                const total = self.request_scanner.totalBytesRead();
                                if (RecvRequest.init(self.client_header_buf[0..total], self.request_scanner)) |req| {
                                    if (req.isKeepAlive()) |keep_alive| {
                                        self.keep_alive = keep_alive;
                                    } else |err| {
                                        self.sendError(.http_version_not_supported);
                                        return;
                                    }
                                    self.request = req;
                                    self.req_content_length = if (req.headers.getContentLength()) |len| len else |err| {
                                        std.debug.print("bad request, invalid content-length, err={s}\n", .{@errorName(err)});
                                        self.sendError(.bad_request);
                                        return;
                                    };
                                    if (self.handler.handleRequestHeaders(&self.request)) |_| {} else |err| {
                                        self.sendError(.internal_server_error);
                                        return;
                                    }

                                    if (self.req_content_length) |len| {
                                        std.debug.print("content_length={}\n", .{len});
                                        const actual_content_chunk_len = old + received - total;
                                        self.content_length_read_so_far += actual_content_chunk_len;
                                        const is_last_fragment = len <= actual_content_chunk_len;
                                        if (self.handler.handleRequestBodyFragment(
                                            self.client_header_buf[total .. old + received],
                                            is_last_fragment,
                                        )) |_| {} else |err| {
                                            self.sendError(.internal_server_error);
                                            return;
                                        }
                                        if (!is_last_fragment) {
                                            self.state = .ReceivingContent;
                                            self.client_body_buf = self.server.allocator.alloc(u8, self.server.config.client_body_buffer_size) catch {
                                                self.sendError(.internal_server_error);
                                                return;
                                            };
                                            self.server.io.recvWithTimeout(
                                                *Conn,
                                                self,
                                                recvCallback,
                                                &self.linked_completion,
                                                self.socket,
                                                self.client_body_buf.?,
                                                0,
                                                self.recv_timeout_ns,
                                            );
                                            return;
                                        }
                                    } else {
                                        if (self.handler.handleRequestBodyFragment(
                                            self.client_header_buf[total .. old + received],
                                            true,
                                        )) |_| {} else |err| {
                                            self.sendError(.internal_server_error);
                                            return;
                                        }
                                    }
                                } else |err| {
                                    self.sendError(.bad_request);
                                    return;
                                }
                                self.sendResponseWithTimeout();
                            } else {
                                std.debug.print("handleReceivedData not done\n", .{});
                                if (old + received == self.client_header_buf.len) {
                                    const config = self.server.config;
                                    const new_len = if (self.client_header_buf.len == config.client_header_buffer_size) blk1: {
                                        break :blk1 config.large_client_header_buffer_size;
                                    } else blk2: {
                                        break :blk2 self.client_header_buf.len + config.large_client_header_buffer_size;
                                    };
                                    const max_len = config.large_client_header_buffer_size * config.large_client_header_buffer_max_count;
                                    if (max_len < new_len) {
                                        std.debug.print("request header fields too long.\n", .{});
                                        self.sendError(.bad_request);
                                        return;
                                    }
                                    self.client_header_buf = self.server.allocator.realloc(self.client_header_buf, new_len) catch {
                                        self.sendError(.internal_server_error);
                                        return;
                                    };
                                }
                                self.server.io.recvWithTimeout(
                                    *Conn,
                                    self,
                                    recvCallback,
                                    &self.linked_completion,
                                    self.socket,
                                    self.client_header_buf[old + received ..],
                                    0,
                                    self.recv_timeout_ns,
                                );
                            }
                        } else |err| {
                            std.debug.print("handleReceivedData scan failed with {s}\n", .{@errorName(err)});
                            self.sendError(switch (err) {
                                error.UriTooLong => .uri_too_long,
                                error.VersionNotSupported => .http_version_not_supported,
                                else => .bad_request,
                            });
                        }
                    },
                    .ReceivingContent => {
                        self.content_length_read_so_far += received;
                        const is_last_fragment = self.req_content_length.? <= self.content_length_read_so_far;
                        if (self.handler.handleRequestBodyFragment(
                            self.client_body_buf.?[0..received],
                            is_last_fragment,
                        )) |_| {} else |err| {
                            self.sendError(.internal_server_error);
                            return;
                        }
                        if (is_last_fragment) {
                            self.server.allocator.free(self.client_body_buf.?);
                            self.client_body_buf = null;
                        } else {
                            self.server.io.recvWithTimeout(
                                *Conn,
                                self,
                                recvCallback,
                                &self.linked_completion,
                                self.socket,
                                self.client_body_buf.?,
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
                var now = datetime.datetime.Datetime.now().shiftTimezone(&datetime.timezones.GMT);
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
                self.server.io.sendWithTimeout(
                    *Conn,
                    self,
                    sendCallback,
                    &self.linked_completion,
                    self.socket,
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

                switch (self.request.version) {
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
                self.content_length = 12;
                // self.content_length = 2048;
                std.fmt.format(w, "Content-Length: {d}\r\n", .{self.content_length}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
                var pos = fbs.getPos() catch unreachable;
                self.resp_headers_len = pos;
                self.send_buf_data_len = std.math.min(
                    pos + self.content_length,
                    self.send_buf.len,
                );
                while (pos < self.send_buf_data_len) : (pos += 1) {
                    self.send_buf[pos] = 'e';
                }
                self.send_buf_sent_len = 0;
                // self.state = .SendingHeaders;
                self.state = .SendingContent;
                self.server.io.sendWithTimeout(
                    *Conn,
                    self,
                    sendCallback,
                    &self.linked_completion,
                    self.socket,
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
                        self.server.io.sendWithTimeout(
                            *Conn,
                            self,
                            sendCallback,
                            &self.linked_completion,
                            self.socket,
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
                            self.server.io.sendWithTimeout(
                                *Conn,
                                self,
                                sendCallback,
                                &self.linked_completion,
                                self.socket,
                                self.send_buf[0..self.send_buf_data_len],
                                0,
                                self.send_timeout_ns,
                            );
                            return;
                        },
                        .SendingContent => {
                            std.debug.print("self.content_length={}, self.sent_bytes_so_far={}, self.resp_headers_len={}\n", .{ self.content_length, self.sent_bytes_so_far, self.resp_headers_len });
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
                                self.server.io.sendWithTimeout(
                                    *Conn,
                                    self,
                                    sendCallback,
                                    &self.linked_completion,
                                    self.socket,
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
                    self.recvWithTimeout(self.client_header_buf);
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
        pub const Svr = Server(Self);

        conn: *Svr.Conn = undefined,

        fn handleRequestHeaders(self: *Self, req: *RecvRequest) !void {
            std.debug.print("handleRequestHeaders: request method={s}, version={s}, url={s}, headers=\n{s}", .{
                req.method.toText(),
                req.version.toText(),
                req.uri,
                req.headers.fields,
            });
        }

        fn handleRequestBodyFragment(self: *Self, body_fragment: []const u8, is_last_fragment: bool) !void {
            std.debug.print("handleRequestBodyFragment: body_fragment={s}, is_last_fragment={}\n", .{ body_fragment, is_last_fragment });
        }
    };

    try struct {
        fn runTest() !void {
            var allocator = testing.allocator;
            const address = try std.net.Address.parseIp4("127.0.0.1", 3131);

            var io = try IO.init(256, 0);
            defer io.deinit();

            var svr = try Handler.Svr.init(allocator, &io, address, .{});
            defer svr.deinit();

            try svr.run();
        }
    }.runTest();
}
