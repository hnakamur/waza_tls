const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const datetime = @import("datetime");
const Fields = @import("fields.zig").Fields;
const RecvRequest = @import("recv_request.zig").RecvRequest;
const RecvRequestScanner = @import("recv_request.zig").RecvRequestScanner;
const Method = @import("method.zig").Method;
const StatusCode = @import("status_code.zig").StatusCode;
const Version = @import("version.zig").Version;
const writeDatetimeHeader = @import("datetime.zig").writeDatetimeHeader;

const http_log = std.log.scoped(.http);

const recv_flags = if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0;
const send_flags = if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0;

pub fn Server(comptime Handler: type) type {
    return struct {
        const Self = @This();
        const Config = struct {
            recv_timeout_ns: u63 = 5 * time.ns_per_s,
            send_timeout_ns: u63 = 5 * time.ns_per_s,
            request_header_buf_len: usize = 1024,
            large_request_header_buf_len: usize = 8192,
            large_request_header_buf_max_count: usize = 4,
            request_content_fragment_buf_len: usize = 16384,
            response_buf_len: usize = 1024,

            fn validate(self: Config) !void {
                assert(self.recv_timeout_ns > 0);
                assert(self.send_timeout_ns > 0);
                assert(self.request_header_buf_len > 0);
                assert(self.large_request_header_buf_len > self.request_header_buf_len);
                assert(self.large_request_header_buf_max_count > 0);
                assert(self.request_content_fragment_buf_len > 0);
                // should be large enough to build error responses.
                assert(self.response_buf_len >= 1024);
            }
        };

        io: *IO,
        socket: os.socket_t,
        allocator: *mem.Allocator,
        config: Config,
        bound_address: std.net.Address = undefined,
        connections: std.ArrayList(?*Conn),
        completion: IO.Completion = undefined,
        shutdown_requested: bool = false,
        done: bool = false,

        pub fn init(allocator: *mem.Allocator, io: *IO, address: std.net.Address, config: Config) !Self {
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
            var bound_address: std.net.Address = undefined;
            if (address.getPort() == 0) {
                bound_address = address;
                var bound_socklen: os.socklen_t = bound_address.getOsSockLen();
                try os.getsockname(socket, &bound_address.any, &bound_socklen);
            }

            try os.listen(socket, kernel_backlog);

            var self: Self = .{
                .io = io,
                .socket = socket,
                .allocator = allocator,
                .config = config,
                .bound_address = bound_address,
                .connections = std.ArrayList(?*Conn).init(allocator),
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            os.close(self.socket);
            self.connections.deinit();
        }

        pub fn start(self: *Self) !void {
            self.io.accept(*Self, self, acceptCallback, &self.completion, self.socket, 0);
        }
        fn acceptCallback(
            self: *Self,
            completion: *IO.Completion,
            result: IO.AcceptError!os.socket_t,
        ) void {
            const accepted_sock = result catch @panic("accept error");
            var conn = self.createConn(accepted_sock) catch @panic("conn create error");
            conn.start();
            self.io.accept(*Self, self, acceptCallback, completion, self.socket, 0);
        }

        fn createConn(self: *Self, accepted_sock: os.socket_t) !*Conn {
            const conn_id = if (self.findEmptyConnId()) |id| id else self.connections.items.len;
            const conn = try Conn.init(self, conn_id, accepted_sock);
            if (conn_id < self.connections.items.len) {
                self.connections.items[conn_id] = conn;
            } else {
                try self.connections.append(conn);
            }
            return conn;
        }

        fn findEmptyConnId(self: *Self) ?usize {
            for (self.connections.items) |h, i| {
                if (h) |_| {} else {
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
            for (self.connections.items) |conn, i| {
                if (conn) |c| {
                    if (!c.processing) {
                        c.close();
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

        pub const Completion = struct {
            linked_completion: IO.LinkedCompletion = undefined,
            buffer: []const u8 = undefined,
            processed_len: usize = undefined,
            callback: fn (ctx: ?*c_void, result: *const c_void) void = undefined,
        };

        pub const RecvRequestHeaderError = error{
            UnexpectedEof,
            HeaderTooLong,
            HttpVersionNotSupported,
            OutOfMemory,
        } || IO.RecvError || RecvRequestScanner.Error || RecvRequest.Error || Fields.ContentLengthError;

        pub const RecvRequestContentFragmentError = error{
            UnexpectedEof,
            OutOfMemory,
        } || IO.RecvError;

        pub const Conn = struct {
            handler: Handler = undefined,
            server: *Self,
            socket: os.socket_t,
            conn_id: usize,
            completion: Completion = undefined,
            request_header_buf: []u8,
            request_content_fragment_buf: ?[]u8 = null,
            send_buf: []u8,
            request_scanner: RecvRequestScanner = undefined,
            request: RecvRequest = undefined,
            request_version: Version = undefined,
            keep_alive: bool = true,
            request_content_length: ?u64 = null,
            content_len_read_so_far: u64 = 0,
            processing: bool = false,
            is_send_finished: bool = true,

            fn init(server: *Self, conn_id: usize, socket: os.socket_t) !*Conn {
                const request_header_buf = try server.allocator.alloc(u8, server.config.request_header_buf_len);
                const send_buf = try server.allocator.alloc(u8, server.config.response_buf_len);
                var self = try server.allocator.create(Conn);
                self.* = Conn{
                    .handler = Handler{ .conn = self },
                    .server = server,
                    .conn_id = conn_id,
                    .socket = socket,
                    .request_header_buf = request_header_buf,
                    .send_buf = send_buf,
                };
                http_log.debug("Conn main_completion=0x{x}, linked_completion=0x{x}", .{
                    @ptrToInt(&self.completion.linked_completion.main_completion),
                    @ptrToInt(&self.completion.linked_completion.linked_completion),
                });
                return self;
            }

            fn deinit(self: *Conn) !void {
                self.server.removeConnId(self.conn_id);
                http_log.debug("Conn.deinit after removeConnId server.done={}", .{self.server.done});
                self.server.allocator.free(self.send_buf);
                if (self.request_content_fragment_buf) |buf| {
                    self.server.allocator.free(buf);
                }
                self.server.allocator.free(self.request_header_buf);
                self.server.allocator.destroy(self);
            }

            fn close(self: *Conn) void {
                os.closeSocket(self.socket);
                // http_log.debug("Conn.Close not calling deinit", .{});
                http_log.debug("Conn.Close before calling deinit", .{});
                if (self.deinit()) |_| {} else |err| {
                    http_log.debug("Conn deinit err={s}", .{@errorName(err)});
                }
                http_log.debug("Conn.Close after calling deinit", .{});
            }

            fn start(self: *Conn) void {
                self.handler.start();
            }

            pub fn recvRequestHeader(
                self: *Conn,
                comptime callback: fn (
                    context: *Handler,
                    result: RecvRequestHeaderError!usize,
                ) void,
            ) void {
                self.completion = .{
                    .callback = struct {
                        fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                            callback(
                                @intToPtr(*Handler, @ptrToInt(ctx)),
                                @intToPtr(*const RecvRequestHeaderError!usize, @ptrToInt(res)).*,
                            );
                        }
                    }.wrapper,
                    .processed_len = 0,
                };

                self.processing = true;
                self.request_scanner = RecvRequestScanner{};
                http_log.debug("Conn.recvRequestHeader main_completion=0x{x}", .{@ptrToInt(&self.completion.linked_completion.main_completion)});
                http_log.debug("Conn.recvRequestHeader linked_completion=0x{x}", .{@ptrToInt(&self.completion.linked_completion.linked_completion)});
                self.server.io.recvWithTimeout(
                    *Conn,
                    self,
                    recvRequestHeaderCallback,
                    &self.completion.linked_completion,
                    self.socket,
                    self.request_header_buf,
                    recv_flags,
                    self.server.config.recv_timeout_ns,
                );
            }
            fn recvRequestHeaderCallback(
                self: *Conn,
                linked_completion: *IO.LinkedCompletion,
                result: IO.RecvError!usize,
            ) void {
                http_log.debug("Conn.recvRequestHeaderCallback result={}", .{result});
                http_log.debug("Conn.recvRequestHeaderCallback main_completion=0x{x}", .{@ptrToInt(&linked_completion.main_completion)});
                http_log.debug("Conn.recvRequestHeaderCallback linked_completion=0x{x}", .{@ptrToInt(&linked_completion.linked_completion)});
                const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
                if (result) |received| {
                    if (received == 0) {
                        if (self.request_scanner.totalBytesRead() != 0) {
                            const err_result: RecvRequestHeaderError!usize = error.UnexpectedEof;
                            comp.callback(&self.handler, &err_result);
                            self.sendError(.bad_request);
                        } else {
                            self.close();
                        }
                        return;
                    }

                    const old = comp.processed_len;
                    comp.processed_len += received;
                    const buf = self.request_header_buf;
                    if (self.request_scanner.scan(buf[old..comp.processed_len])) |done| {
                        if (done) {
                            const total = self.request_scanner.totalBytesRead();
                            if (RecvRequest.init(buf[0..total], &self.request_scanner)) |req| {
                                if (req.isKeepAlive()) |keep_alive| {
                                    self.keep_alive = keep_alive;
                                } else |err| {
                                    const err_result: RecvRequestHeaderError!usize = err;
                                    comp.callback(&self.handler, &err_result);
                                    self.sendError(.http_version_not_supported);
                                    return;
                                }
                                self.request_content_length = if (req.headers.getContentLength()) |len| len else |err| {
                                    http_log.debug("bad request, invalid content-length, err={s}", .{@errorName(err)});
                                    const err_result: RecvRequestHeaderError!usize = err;
                                    comp.callback(&self.handler, &err_result);
                                    self.sendError(.bad_request);
                                    return;
                                };
                                self.request = req;
                                const content_fragment_len = comp.processed_len - total;
                                self.content_len_read_so_far = content_fragment_len;
                                const has_content = content_fragment_len > 0;
                                if (has_content) self.request_content_fragment_buf = buf[total..comp.processed_len];
                                comp.callback(&self.handler, &result);
                                if (has_content) self.request_content_fragment_buf = null;
                            } else |err| {
                                const err_result: RecvRequestHeaderError!usize = err;
                                comp.callback(&self.handler, &err_result);
                                self.sendError(.bad_request);
                                return;
                            }
                        } else {
                            if (old + received == buf.len) {
                                const new_len =
                                    if (self.request_header_buf.len == self.server.config.request_header_buf_len)
                                blk1: {
                                    break :blk1 self.server.config.large_request_header_buf_len;
                                } else blk2: {
                                    break :blk2 self.request_header_buf.len +
                                        self.server.config.large_request_header_buf_len;
                                };
                                const max_len = self.server.config.large_request_header_buf_len *
                                    self.server.config.large_request_header_buf_max_count;
                                if (max_len < new_len) {
                                    const err_result: RecvRequestHeaderError!usize = error.HeaderTooLong;
                                    comp.callback(&self.handler, &err_result);
                                    self.sendError(.request_header_fields_too_large);
                                    return;
                                }
                                self.request_header_buf = self.server.allocator.realloc(self.request_header_buf, new_len) catch |err| {
                                    const err_result: RecvRequestHeaderError!usize = err;
                                    comp.callback(&self.handler, &err_result);
                                    self.sendError(.internal_server_error);
                                    return;
                                };

                                self.server.io.recvWithTimeout(
                                    *Conn,
                                    self,
                                    recvRequestHeaderCallback,
                                    linked_completion,
                                    self.socket,
                                    self.request_header_buf[comp.processed_len..],
                                    linked_completion.main_completion.operation.recv.flags,
                                    @intCast(u63, linked_completion.linked_completion.operation.link_timeout.timespec.tv_nsec),
                                );
                            }
                        }
                    } else |err| {
                        const err_result: RecvRequestHeaderError!usize = err;
                        comp.callback(&self.handler, &err_result);
                        self.sendError(.bad_request);
                        return;
                    }
                } else |_| {
                    http_log.debug("Conn.recvRequestHeaderCallback before calling callback with result={}", .{result});
                    comp.callback(&self.handler, &result);
                    http_log.debug("Conn.recvRequestHeaderCallback after calling callback with result={}", .{result});
                    self.close();
                }
            }

            pub fn fullyReadRequestContent(self: *Conn) bool {
                return if (self.request_content_length) |len|
                    self.content_len_read_so_far >= len
                else
                    true;
            }

            pub fn recvRequestContentFragment(
                self: *Conn,
                comptime callback: fn (
                    context: *Handler,
                    result: RecvRequestContentFragmentError!usize,
                ) void,
            ) void {
                self.completion = .{
                    .callback = struct {
                        fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                            callback(
                                @intToPtr(*Handler, @ptrToInt(ctx)),
                                @intToPtr(*const RecvRequestContentFragmentError!usize, @ptrToInt(res)).*,
                            );
                        }
                    }.wrapper,
                    .processed_len = 0,
                };

                if (self.request_content_fragment_buf) |_| {} else {
                    if (self.server.allocator.alloc(u8, self.server.config.request_content_fragment_buf_len)) |buf| {
                        self.request_content_fragment_buf = buf;
                    } else |err| {
                        const err_result: RecvRequestContentFragmentError!usize = err;
                        self.completion.callback(&self.handler, &err_result);
                        self.sendError(.internal_server_error);
                        return;
                    }
                }

                self.server.io.recvWithTimeout(
                    *Conn,
                    self,
                    recvRequestContentFragmentCallback,
                    &self.completion.linked_completion,
                    self.socket,
                    self.request_content_fragment_buf.?,
                    recv_flags,
                    self.server.config.recv_timeout_ns,
                );
            }
            fn recvRequestContentFragmentCallback(
                self: *Conn,
                linked_completion: *IO.LinkedCompletion,
                result: IO.RecvError!usize,
            ) void {
                const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
                if (result) |received| {
                    if (received == 0) {
                        if (self.fullyReadRequestContent()) {
                            comp.callback(&self.handler, &result);
                        } else {
                            const err_result: RecvRequestContentFragmentError!usize = error.UnexpectedEof;
                            comp.callback(&self.handler, &err_result);
                        }
                        self.close();
                        return;
                    }

                    self.content_len_read_so_far += received;
                    comp.callback(&self.handler, &result);
                } else |_| {
                    comp.callback(&self.handler, &result);
                    self.close();
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
                writeDatetimeHeader(w, "Date", datetime.datetime.Datetime.now()) catch unreachable;

                self.keep_alive = false;
                std.fmt.format(w, "Connection: {s}\r\n", .{"close"}) catch unreachable;
                std.fmt.format(w, "Content-Length: 0\r\n", .{}) catch unreachable;
                std.fmt.format(w, "\r\n", .{}) catch unreachable;
                self.server.io.sendWithTimeout(
                    *Conn,
                    self,
                    sendErrorCallback,
                    &self.completion.linked_completion,
                    self.socket,
                    fbs.getWritten(),
                    send_flags,
                    self.server.config.send_timeout_ns,
                );
            }
            fn sendErrorCallback(
                self: *Conn,
                completion: *IO.LinkedCompletion,
                result: IO.SendError!usize,
            ) void {
                if (result) |_| {} else |err| {
                    http_log.debug("Conn.sendErrorCallback, err={s}", .{@errorName(err)});
                }
                self.close();
            }

            pub fn sendFull(
                self: *Conn,
                buffer: []const u8,
                comptime callback: fn (
                    handler: *Handler,
                    last_result: IO.SendError!usize,
                ) void,
            ) void {
                self.completion = .{
                    .callback = struct {
                        fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                            callback(
                                @intToPtr(*Handler, @ptrToInt(ctx)),
                                @intToPtr(*const IO.SendError!usize, @ptrToInt(res)).*,
                            );
                        }
                    }.wrapper,
                    .buffer = buffer,
                    .processed_len = 0,
                };
                self.server.io.sendWithTimeout(
                    *Conn,
                    self,
                    sendFullWithTimeoutCallback,
                    &self.completion.linked_completion,
                    self.socket,
                    buffer,
                    send_flags,
                    self.server.config.send_timeout_ns,
                );
            }
            fn sendFullWithTimeoutCallback(
                self: *Conn,
                linked_completion: *IO.LinkedCompletion,
                result: IO.SendError!usize,
            ) void {
                const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
                if (result) |sent| {
                    comp.processed_len += sent;
                    if (comp.processed_len < comp.buffer.len) {
                        self.server.io.sendWithTimeout(
                            *Conn,
                            self,
                            sendFullWithTimeoutCallback,
                            &self.completion.linked_completion,
                            self.socket,
                            comp.buffer[comp.processed_len..],
                            linked_completion.main_completion.operation.send.flags,
                            @intCast(u63, linked_completion.linked_completion.operation.link_timeout.timespec.tv_nsec),
                        );
                        return;
                    }

                    self.is_send_finished = false;
                    comp.callback(&self.handler, &result);
                    if (!self.is_send_finished) {
                        return;
                    }

                    if (!self.keep_alive or self.server.shutdown_requested) {
                        self.close();
                        return;
                    }

                    self.processing = false;
                    self.start();
                } else |_| {
                    comp.callback(&self.handler, &result);
                    self.close();
                }
            }

            pub fn finishSend(self: *Conn) void {
                self.is_send_finished = true;
            }
        };
    };
}
