const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const Fields = @import("fields.zig").Fields;
const RecvResponseScanner = @import("recv_response.zig").RecvResponseScanner;
const RecvResponse = @import("recv_response.zig").RecvResponse;
const Method = @import("method.zig").Method;
const Version = @import("version.zig").Version;

const http_log = std.log.scoped(.http);

const recv_flags = if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0;
const send_flags = if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0;

pub fn Client(comptime Context: type) type {
    return struct {
        const Self = @This();

        pub const Config = struct {
            connect_timeout_ns: u63 = 5 * time.ns_per_s,
            send_timeout_ns: u63 = 5 * time.ns_per_s,
            recv_timeout_ns: u63 = 5 * time.ns_per_s,
            response_header_buf_ini_len: usize = 4096,
            response_header_buf_max_len: usize = 64 * 1024,
            response_content_fragment_buf_len: usize = 64 * 1024,

            fn validate(self: Config) !void {
                assert(self.connect_timeout_ns > 0);
                assert(self.send_timeout_ns > 0);
                assert(self.recv_timeout_ns > 0);
                assert(self.response_header_buf_ini_len > 0);
                assert(self.response_header_buf_max_len > self.response_header_buf_ini_len);
                assert(self.response_header_buf_max_len % self.response_header_buf_ini_len == 0);
                assert(self.response_content_fragment_buf_len > 0);
            }
        };

        const Completion = struct {
            linked_completion: IO.LinkedCompletion = undefined,
            send_buffer: []const u8 = undefined,
            processed_len: usize = undefined,
            response: RecvResponse = undefined,
            callback: fn (ctx: ?*c_void, result: *const c_void) void = undefined,
        };

        allocator: *mem.Allocator,
        io: *IO,
        context: *Context,
        socket: os.socket_t = undefined,
        completion: Completion = undefined,
        response: RecvResponse = undefined,
        resp_scanner: RecvResponseScanner = undefined,
        response_header_buf: []u8 = undefined,
        response_content_fragment_buf: ?[]u8 = null,
        response_content_length: ?u64 = null,
        content_len_read_so_far: u64 = undefined,
        config: *const Config,
        done: bool = false,

        pub fn init(allocator: *mem.Allocator, io: *IO, context: *Context, config: *const Config) !Self {
            try config.validate();

            return Self{
                .allocator = allocator,
                .io = io,
                .context = context,
                .config = config,
                .response_header_buf = try allocator.alloc(u8, config.response_header_buf_ini_len),
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.response_content_fragment_buf) |buf| {
                self.allocator.free(buf);
            }
            self.allocator.free(self.response_header_buf);
        }

        pub fn connect(
            self: *Self,
            addr: std.net.Address,
            comptime callback: fn (
                context: *Context,
                result: IO.ConnectError!void,
            ) void,
        ) !void {
            self.socket = try os.socket(addr.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);

            self.completion = .{
                .callback = struct {
                    fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            @intToPtr(*const IO.ConnectError!void, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
            };
            http_log.debug("Client.connect main_completion=0x{x}, linked_completion=0x{x}", .{
                @ptrToInt(&self.completion.linked_completion.main_completion),
                @ptrToInt(&self.completion.linked_completion.linked_completion),
            });
            self.io.connectWithTimeout(
                *Self,
                self,
                connectCallback,
                &self.completion.linked_completion,
                self.socket,
                addr,
                self.config.connect_timeout_ns,
            );
        }
        fn connectCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.ConnectError!void,
        ) void {
            http_log.debug("Client.connectCallback result={}", .{result});
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            comp.callback(self.context, &result);
            if (result) |_| {} else |err| {
                http_log.debug("Client.connectCallback before calling close, err={s}", .{@errorName(err)});
                self.close();
                http_log.debug("Client.connectCallback after calling close", .{});
            }
        }

        pub fn sendFull(
            self: *Self,
            buffer: []const u8,
            comptime callback: fn (
                context: *Context,
                last_result: IO.SendError!usize,
            ) void,
        ) void {
            self.completion = .{
                .callback = struct {
                    fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            @intToPtr(*const IO.SendError!usize, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
                .send_buffer = buffer,
                .processed_len = 0,
            };
            self.io.sendWithTimeout(
                *Self,
                self,
                sendCallback,
                &self.completion.linked_completion,
                self.socket,
                buffer,
                send_flags,
                self.config.send_timeout_ns,
            );
        }
        fn sendCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.SendError!usize,
        ) void {
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            if (result) |sent| {
                comp.processed_len += sent;
                const buf = comp.send_buffer;
                if (comp.processed_len < buf.len) {
                    http_log.info("Client.sendCallback, processed_len={} < buf.len={}, timeout_result={}", .{
                        comp.processed_len,
                        buf.len,
                        linked_completion.linked_result,
                    });
                    self.io.sendWithTimeout(
                        *Self,
                        self,
                        sendCallback,
                        linked_completion,
                        self.socket,
                        buf[comp.processed_len..],
                        linked_completion.main_completion.operation.send.flags,
                        self.config.send_timeout_ns,
                    );
                    return;
                }

                comp.callback(self.context, &result);
            } else |_| {
                comp.callback(self.context, &result);
                self.close();
            }
        }

        pub const RecvResponseHeaderError = error{
            UnexpectedEof,
            HeaderTooLong,
            BadGateway,
            OutOfMemory,
        } || IO.RecvError || Fields.ContentLengthError;

        pub fn recvResponseHeader(
            self: *Self,
            comptime callback: fn (
                context: *Context,
                result: RecvResponseHeaderError!usize,
            ) void,
        ) void {
            self.completion = .{
                .callback = struct {
                    fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            @intToPtr(*const RecvResponseHeaderError!usize, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
                .processed_len = 0,
            };

            self.resp_scanner = RecvResponseScanner{};
            self.io.recvWithTimeout(
                *Self,
                self,
                recvResponseHeaderCallback,
                &self.completion.linked_completion,
                self.socket,
                self.response_header_buf,
                recv_flags,
                self.config.recv_timeout_ns,
            );
        }
        fn recvResponseHeaderCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.RecvError!usize,
        ) void {
            http_log.debug("Client.recvResponseHeaderCallback result={}", .{result});
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            if (result) |received| {
                if (received == 0) {
                    const err_result: RecvResponseHeaderError!usize = error.UnexpectedEof;
                    comp.callback(self.context, &err_result);
                    http_log.debug("Client.recvResponseHeaderCallback before calling close#1", .{});
                    self.close();
                    return;
                }

                const old = comp.processed_len;
                comp.processed_len += received;
                const buf = self.response_header_buf;
                if (self.resp_scanner.scan(buf[old..comp.processed_len])) |done| {
                    if (done) {
                        const total = self.resp_scanner.totalBytesRead();
                        if (RecvResponse.init(buf[0..total], &self.resp_scanner)) |resp| {
                            self.response = resp;
                            self.response_content_length = if (self.response.headers.getContentLength()) |len| len else |err| {
                                http_log.debug("bad response, invalid content-length, err={s}", .{@errorName(err)});
                                const err_result: RecvResponseHeaderError!usize = err;
                                comp.callback(self.context, &err_result);
                                http_log.debug("Client.recvResponseHeaderCallback before calling close#2", .{});
                                self.close();
                                return;
                            };
                            http_log.info("Client.recvResponseHeaderCallback response_content_length={}", .{self.response_content_length});

                            const content_fragment_len = comp.processed_len - total;
                            self.content_len_read_so_far = content_fragment_len;
                            const has_content = content_fragment_len > 0;
                            if (has_content) self.response_content_fragment_buf = buf[total..comp.processed_len];
                            comp.callback(self.context, &result);
                            if (has_content) self.response_content_fragment_buf = null;
                        } else |err| {
                            const err_result: RecvResponseHeaderError!usize = err;
                            comp.callback(self.context, &err_result);
                            http_log.debug("Client.recvResponseHeaderCallback before calling close#3", .{});
                            self.close();
                            return;
                        }
                    } else {
                        if (old + received == buf.len) {
                            const new_len = buf.len + self.config.response_header_buf_ini_len;
                            if (self.config.response_header_buf_max_len < new_len) {
                                const err_result: RecvResponseHeaderError!usize = error.HeaderTooLong;
                                comp.callback(self.context, &err_result);
                                http_log.debug("Client.recvResponseHeaderCallback before calling close#4", .{});
                                self.close();
                                return;
                            }
                            self.response_header_buf = self.allocator.realloc(self.response_header_buf, new_len) catch |err| {
                                comp.callback(self.context, &result);
                                http_log.debug("Client.recvResponseHeaderCallback before calling close#5", .{});
                                self.close();
                                return;
                            };
                        }

                        self.io.recvWithTimeout(
                            *Self,
                            self,
                            recvResponseHeaderCallback,
                            linked_completion,
                            self.socket,
                            self.response_header_buf[comp.processed_len..],
                            recv_flags,
                            self.config.recv_timeout_ns,
                        );
                    }
                } else |err| {
                    const err_result: RecvResponseHeaderError!usize = err;
                    comp.callback(self.context, &err_result);
                    http_log.debug("Client.recvResponseHeaderCallback before calling close#6", .{});
                    self.close();
                    return;
                }
            } else |_| {
                comp.callback(self.context, &result);
                self.close();
            }
        }

        pub fn fullyReadResponseContent(self: *Self) bool {
            return if (self.response_content_length) |len|
                self.content_len_read_so_far >= len
            else
                true;
        }

        pub const RecvResponseContentFragmentError = error{
            UnexpectedEof,
            OutOfMemory,
        } || IO.RecvError;

        pub fn recvResponseContentFragment(
            self: *Self,
            comptime callback: fn (
                context: *Context,
                result: RecvResponseContentFragmentError!usize,
            ) void,
        ) void {
            self.completion = .{
                .callback = struct {
                    fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            @intToPtr(*const IO.RecvError!usize, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
            };

            if (self.response_content_fragment_buf) |_| {} else {
                if (self.allocator.alloc(u8, self.config.response_content_fragment_buf_len)) |buf| {
                    self.response_content_fragment_buf = buf;
                } else |err| {
                    const err_result: RecvResponseContentFragmentError!usize = err;
                    self.completion.callback(self.context, &err_result);
                    http_log.debug("Client.recvResponseContentFragment before calling close#1", .{});
                    self.close();
                }
            }

            self.io.recvWithTimeout(
                *Self,
                self,
                recvResponseContentFragmentCallback,
                &self.completion.linked_completion,
                self.socket,
                self.response_content_fragment_buf.?,
                recv_flags,
                self.config.recv_timeout_ns,
            );
        }
        fn recvResponseContentFragmentCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.RecvError!usize,
        ) void {
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            if (result) |received| {
                if (received == 0) {
                    const err_result: RecvResponseContentFragmentError!usize = error.UnexpectedEof;
                    comp.callback(self.context, &err_result);
                    http_log.debug("Client.recvResponseContentFragmentCallback before calling close#1", .{});
                    self.close();
                    return;
                }

                self.content_len_read_so_far += received;
                comp.callback(self.context, &result);
            } else |_| {
                comp.callback(self.context, &result);
                self.close();
            }
        }

        pub fn close(self: *Self) void {
            os.closeSocket(self.socket);
            self.done = true;
            http_log.debug("Client.close exit.", .{});
        }
    };
}
