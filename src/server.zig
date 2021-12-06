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
// const http_log = @import("nop_log.zig").scoped(.http);

const recv_flags = if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0;
const send_flags = if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0;

pub fn Server(comptime Context: type, comptime Handler: type) type {
    return struct {
        const Self = @This();
        pub const Config = struct {
            recv_timeout_ns: u63 = 5 * time.ns_per_s,
            send_timeout_ns: u63 = 5 * time.ns_per_s,
            method_max_len: usize = 32,
            uri_max_len: usize = 8192,
            request_header_buf_len: usize = 1024,
            large_request_header_buf_len: usize = 8192,
            large_request_header_buf_max_count: usize = 4,
            request_content_fragment_buf_len: usize = 16384,
            response_buf_len: usize = 1024,

            fn validate(self: Config) !void {
                assert(self.recv_timeout_ns > 0);
                assert(self.send_timeout_ns > 0);
                assert(self.method_max_len > 0);
                assert(self.uri_max_len > 0);
                assert(self.request_header_buf_len > 0);
                assert(self.large_request_header_buf_len > self.request_header_buf_len);
                assert(self.large_request_header_buf_max_count > 0);
                assert(self.request_content_fragment_buf_len > 0);
                // should be large enough to build error responses.
                assert(self.response_buf_len >= 1024);
            }
        };

        context: *Context,
        io: *IO,
        socket: os.socket_t,
        allocator: *mem.Allocator,
        config: Config,
        bound_address: std.net.Address = undefined,
        connections: std.ArrayList(?*Conn),
        completion: IO.Completion = undefined,
        shutdown_requested: bool = false,
        done: bool = false,

        pub fn init(allocator: *mem.Allocator, io: *IO, context: *Context, address: std.net.Address, config: Config) !Self {
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
                .allocator = allocator,
                .io = io,
                .context = context,
                .socket = socket,
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
            if (result) |accepted_sock| {
                if (self.done) {
                    return;
                }
                var conn = self.createConn(accepted_sock) catch @panic("conn create error");
                conn.start();
                self.io.accept(*Self, self, acceptCallback, completion, self.socket, 0);
            } else |err| {
                http_log.warn("Server.acceptCallback err={s}, server=0x{x}", .{ @errorName(err), @ptrToInt(self) });
            }
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
            http_log.debug("Server.removeConnId conn_id={}", .{conn_id});
            self.connections.items[conn_id] = null;
            if (self.shutdown_requested) {
                self.setDoneIfNoClient();
            }
        }

        pub fn requestShutdown(self: *Self) void {
            http_log.debug("Server.requestShutdown start, server=0x{x}, conn count={}", .{ @ptrToInt(self), self.connections.items.len });
            self.shutdown_requested = true;
            for (self.connections.items) |conn, i| {
                if (conn) |c| {
                    if (!c.processing) {
                        http_log.debug("Server.requestShutdown before calling close for i={}, server=0x{x}", .{ i, @ptrToInt(self) });
                        c.closeSync();
                        http_log.debug("Server.requestShutdown after calling close for i={}", .{i});
                    } else {
                        http_log.debug("Server.requestShutdown i={} processing, server=0x{x}", .{ i, @ptrToInt(self) });
                    }
                } else {
                    http_log.debug("Server.requestShutdown conn i={} null, server=0x{x}", .{ i, @ptrToInt(self) });
                }
            }
            self.setDoneIfNoClient();
        }

        fn setDoneIfNoClient(self: *Self) void {
            http_log.debug("Server.setDoneIfNoClient start, server=0x{x}, conn count={}", .{ @ptrToInt(self), self.connections.items.len });
            for (self.connections.items) |h| {
                if (h) |_| {
                    return;
                }
            }

            // http_log.debug("Server.setDoneIfNoClient calling cancelAccept, server=0x{x}", .{@ptrToInt(self)});
            // self.cancelAccept();
            http_log.debug("Server.setDoneIfNoClient calling close, server=0x{x}", .{@ptrToInt(self)});
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
            req_hdr_buf_content_fragment: ?[]u8 = null,
            request_scanner: RecvRequestScanner = undefined,
            request: RecvRequest = undefined,
            request_version: Version = undefined,
            keep_alive: bool = true,
            request_content_length: ?u64 = null,
            content_len_read_so_far: u64 = 0,
            request_content_fragment_buf: ?[]u8 = null,
            send_buf: []u8,
            is_send_finished: bool = true,
            processing: bool = false,

            fn init(server: *Self, conn_id: usize, socket: os.socket_t) !*Conn {
                const request_header_buf = try server.allocator.alloc(u8, server.config.request_header_buf_len);
                http_log.debug("Server.Conn.init, server=0x{x}, request_header_buf=0x{x}", .{ @ptrToInt(server), @ptrToInt(request_header_buf.ptr) });
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
                if (@hasDecl(Handler, "init")) {
                    try self.handler.init();
                }
                http_log.debug("Server.Conn self=0x{x}, server=0x{x}, main_completion=0x{x}, linked_completion=0x{x}", .{
                    @ptrToInt(self),
                    @ptrToInt(self.server),
                    @ptrToInt(&self.completion.linked_completion.main_completion),
                    @ptrToInt(&self.completion.linked_completion.linked_completion),
                });
                return self;
            }

            pub fn deinit(self: *Conn) !void {
                http_log.debug("Server.Conn.deinit self=0x{x}, server=0x{x}", .{ @ptrToInt(self), @ptrToInt(self.server) });
                self.server.removeConnId(self.conn_id);
                http_log.debug("Conn.deinit after removeConnId self=0x{x}, server.done={}", .{ @ptrToInt(self), self.server.done });
                if (@hasDecl(Handler, "deinit")) {
                    self.handler.deinit();
                }
                self.server.allocator.free(self.send_buf);
                if (self.request_content_fragment_buf) |buf| {
                    self.server.allocator.free(buf);
                }
                self.server.allocator.free(self.request_header_buf);
                self.server.allocator.destroy(self);
            }

            fn closeSync(self: *Conn) void {
                http_log.debug("Server.Conn.closeSync start, conn_id={}, server=0x{x}", .{ self.conn_id, @ptrToInt(self.server) });
                os.closeSocket(self.socket);
                http_log.debug("Server.Conn.closeSync before calling deinit", .{});
                if (self.deinit()) |_| {} else |err| {
                    http_log.err("Server.Conn.closeSync deinit err={s}", .{@errorName(err)});
                }
                http_log.debug("Server.Conn.closeSync after calling deinit", .{});
            }

            pub fn close(
                self: *Conn,
                comptime callback: fn (
                    context: *Handler,
                    result: IO.CloseError!void,
                ) void,
            ) void {
                http_log.debug("Server.Conn.close self=0x{x}, server=0x{x}", .{ @ptrToInt(&self), @ptrToInt(self.server) });
                self.completion = .{
                    .callback = struct {
                        fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                            callback(
                                @intToPtr(*Handler, @ptrToInt(ctx)),
                                @intToPtr(*const IO.CloseError!void, @ptrToInt(res)).*,
                            );
                        }
                    }.wrapper,
                };

                self.server.io.close(
                    *Conn,
                    self,
                    closeCallback,
                    &self.completion.linked_completion.main_completion,
                    self.socket,
                );
            }
            fn closeCallback(
                self: *Conn,
                completion: *IO.Completion,
                result: IO.CloseError!void,
            ) void {
                http_log.debug("Server.Conn.closeCallback result={}, self=0x{x}, server=0x{x}", .{ result, @ptrToInt(&self), @ptrToInt(self.server) });
                const linked_comp = @fieldParentPtr(IO.LinkedCompletion, "main_completion", completion);
                const comp = @fieldParentPtr(Completion, "linked_completion", linked_comp);
                comp.callback(&self.handler, &result);
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

                self.request_scanner = RecvRequestScanner{
                    .request_line = .{
                        .method_max_len = self.server.config.method_max_len,
                        .uri_max_len = self.server.config.uri_max_len,
                    },
                };
                http_log.debug("Conn.recvRequestHeader main_completion=0x{x}", .{@ptrToInt(&self.completion.linked_completion.main_completion)});
                http_log.debug("Conn.recvRequestHeader linked_completion=0x{x}", .{@ptrToInt(&self.completion.linked_completion.linked_completion)});
                self.processing = true;
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
                            http_log.debug("Server.Conn.recvRequestHeaderCallback calling closeSync server=0x{x}", .{@ptrToInt(self.server)});
                            self.closeSync();
                        }
                        return;
                    }

                    const old = comp.processed_len;
                    comp.processed_len += received;
                    const buf = self.request_header_buf;
                    http_log.debug("Server.Conn.recvRequestHeaderCallback self=0x{x}, buf.len={}, old={}, processed_len={}", .{ @ptrToInt(self), buf.len, old, comp.processed_len });
                    if (self.request_scanner.scan(buf[old..comp.processed_len])) |done| {
                        http_log.debug("Server.Conn.recvRequestHeaderCallback scan_done={}, processed_len={}, buf.len={}", .{
                            done,
                            comp.processed_len,
                            buf.len,
                        });
                        if (done) {
                            const total = self.request_scanner.totalBytesRead();
                            if (RecvRequest.init(buf[0..total], &self.request_scanner)) |req| {
                                http_log.debug("Server.Conn.recvRequestHeaderCallback RecvRequest.init ok", .{});
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
                                http_log.debug("Server.Conn.recvRequestHeaderCallback request_content_length={}", .{
                                    self.request_content_length,
                                });
                                self.request = req;
                                const content_fragment_len = comp.processed_len - total;
                                self.content_len_read_so_far = content_fragment_len;
                                const has_content = content_fragment_len > 0;
                                if (has_content) self.req_hdr_buf_content_fragment = buf[total..comp.processed_len];
                                if (has_content) self.request_content_fragment_buf = buf[total..comp.processed_len];
                                comp.callback(&self.handler, &result);
                                if (has_content) self.request_content_fragment_buf = null;
                            } else |err| {
                                http_log.debug("Server.Conn.recvRequestHeaderCallback RecvRequest.init err={s}", .{@errorName(err)});
                                const err_result: RecvRequestHeaderError!usize = err;
                                comp.callback(&self.handler, &err_result);
                                self.sendError(.bad_request);
                                return;
                            }
                        } else {
                            if (comp.processed_len == buf.len) {
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
                                http_log.debug("Server.Conn.recvRequestHeaderCallback new_len={}, max_len={}", .{ new_len, max_len });
                                if (max_len < new_len) {
                                    const err_result: RecvRequestHeaderError!usize = error.HeaderTooLong;
                                    comp.callback(&self.handler, &err_result);
                                    self.sendError(.request_header_fields_too_large);
                                    return;
                                }
                                self.request_header_buf = self.server.allocator.realloc(self.request_header_buf, new_len) catch |err| {
                                    http_log.warn("Server.Conn.recvRequestHeaderCallback sending internal_server_error after realloc err={s}", .{@errorName(err)});
                                    const err_result: RecvRequestHeaderError!usize = err;
                                    comp.callback(&self.handler, &err_result);
                                    // TODO: Decide what to do for the case causing error.ConnectionResetByPeer
                                    // in a client in server_alloc_fail_case1 test.
                                    self.sendError(.internal_server_error);
                                    return;
                                };
                            }

                            http_log.debug("Server.Conn.recvRequestHeaderCallback calling recvWithTimeout processed_len={}, recv_len={}", .{
                                comp.processed_len,
                                self.request_header_buf.len - comp.processed_len,
                            });
                            self.server.io.recvWithTimeout(
                                *Conn,
                                self,
                                recvRequestHeaderCallback,
                                linked_completion,
                                self.socket,
                                self.request_header_buf[comp.processed_len..],
                                recv_flags,
                                self.server.config.recv_timeout_ns,
                            );
                        }
                    } else |err| {
                        http_log.debug("Server.Conn.recvRequestHeaderCallback scan err={s}", .{@errorName(err)});
                        const err_result: RecvRequestHeaderError!usize = err;
                        comp.callback(&self.handler, &err_result);
                        const status_code: StatusCode = switch (err) {
                            error.UriTooLong => .uri_too_long,
                            error.VersionNotSupported => .http_version_not_supported,
                            else => .bad_request,
                        };
                        self.sendError(status_code);
                        return;
                    }
                } else |_| {
                    http_log.debug("Conn.recvRequestHeaderCallback before calling callback with result={}", .{result});
                    comp.callback(&self.handler, &result);
                    http_log.debug("Conn.recvRequestHeaderCallback after calling callback with result={}, server=0x{x}", .{ result, @ptrToInt(self.server) });
                    self.closeSync();
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
                        http_log.warn("Server.Conn.recvRequestContentFragment alloc request_content_fragment_buf err={s}", .{@errorName(err)});
                        const err_result: RecvRequestContentFragmentError!usize = err;
                        self.completion.callback(&self.handler, &err_result);
                        // TODO: Decide what to do for the case causing error.ConnectionResetByPeer
                        // in a client in server_alloc_fail_case2 test.
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
                http_log.debug("Server.Conn.recvRequestContentFragmentCallback result={}, content_len_read_so_far={}", .{ result, self.content_len_read_so_far });
                const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
                if (result) |received| {
                    if (received == 0) {
                        const err_result: RecvRequestContentFragmentError!usize = error.UnexpectedEof;
                        comp.callback(&self.handler, &err_result);
                        http_log.debug("Server.Conn.recvRequestContentFragmentCallback calling closeSync#1 server=0x{x}", .{@ptrToInt(self.server)});
                        self.closeSync();
                        return;
                    }

                    self.content_len_read_so_far += received;
                    comp.callback(&self.handler, &result);
                } else |_| {
                    comp.callback(&self.handler, &result);
                    http_log.debug("Server.Conn.recvRequestContentFragmentCallback calling closeSync#2 server=0x{x}", .{@ptrToInt(self.server)});
                    self.closeSync();
                }
            }

            fn sendError(self: *Conn, status_code: StatusCode) void {
                var fbs = std.io.fixedBufferStream(self.send_buf);
                var w = fbs.writer();
                std.fmt.format(w, "{s} {d} {s}\r\n", .{
                    Version.http1_1.toBytes(),
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
                http_log.debug("Conn.sendError after sendWithTimeout, conn_id={}", .{self.conn_id});
            }
            fn sendErrorCallback(
                self: *Conn,
                completion: *IO.LinkedCompletion,
                result: IO.SendError!usize,
            ) void {
                http_log.debug("Conn.sendErrorCallback, result={}, conn_id={}", .{ result, self.conn_id });
                if (result) |_| {} else |err| {
                    http_log.debug("Conn.sendErrorCallback, err={s}", .{@errorName(err)});
                }
                http_log.debug("Conn.sendErrorCallback, calling close, conn_id={}, server=0x{x}", .{ self.conn_id, @ptrToInt(self.server) });
                self.closeSync();
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
                            send_flags,
                            self.server.config.send_timeout_ns,
                        );
                        return;
                    }

                    self.is_send_finished = false;
                    comp.callback(&self.handler, &result);
                    if (!self.is_send_finished) {
                        return;
                    }

                    if (!self.keep_alive or self.server.shutdown_requested) {
                        http_log.debug("Server.Conn.sendFullWithTimeoutCallback calling closeSync#1 server=0x{x}", .{@ptrToInt(self.server)});
                        self.closeSync();
                        return;
                    }

                    self.processing = false;
                    self.start();
                } else |_| {
                    comp.callback(&self.handler, &result);
                    http_log.debug("Server.Conn.sendFullWithTimeoutCallback calling closeSync#2 server=0x{x}", .{@ptrToInt(self.server)});
                    self.closeSync();
                }
            }

            pub fn finishSend(self: *Conn) void {
                self.is_send_finished = true;
            }
        };
    };
}
