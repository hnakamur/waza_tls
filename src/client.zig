const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const RecvResponseScanner = @import("recv_response.zig").RecvResponseScanner;
const RecvResponse = @import("recv_response.zig").RecvResponse;
const Method = @import("method.zig").Method;
const Version = @import("version.zig").Version;

pub const DynamicByteBuffer = std.fifo.LinearFifo(u8, .Dynamic);

pub const Client = struct {
    const Self = @This();

    pub const Completion = struct {
        linked_completion: IO.LinkedCompletion = undefined,
        context: ?*c_void = null,
        buffer: *DynamicByteBuffer = undefined,
        processed_len: usize = undefined,
        header_buf_max_len: usize = undefined,
        response: RecvResponse = undefined,
        callback: fn (ctx: ?*c_void, comp: *Completion, result: *const c_void) void = undefined,
    };

    io: *IO,
    socket: os.socket_t = undefined,
    done: bool = false,
    resp_scanner: RecvResponseScanner = undefined,

    pub fn init(io: *IO) Self {
        return Self{
            .io = io,
        };
    }

    pub fn connectWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: IO.ConnectError!void,
        ) void,
        completion: *Completion,
        addr: std.net.Address,
        connect_timeout_ns: u63,
    ) !void {
        self.socket = try os.socket(addr.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
        std.debug.print("Client.connectWithTimeout, client=0x{x}, socket={}\n", .{ @ptrToInt(self), self.socket });

        completion.* = .{
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const IO.ConnectError!void, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
        };
        self.io.connectWithTimeout(
            *Self,
            self,
            connectCallback,
            &completion.linked_completion,
            self.socket,
            addr,
            connect_timeout_ns,
        );
    }
    fn connectCallback(
        self: *Self,
        linked_completion: *IO.LinkedCompletion,
        result: IO.ConnectError!void,
    ) void {
        std.debug.print("Client.connectCallback result={}\n", .{result});
        std.debug.print("Client.connectCallback socket={}\n", .{self.socket});
        const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
        comp.callback(comp.context, comp, &result);
        if (result) |_| {} else |err| {
            self.close();
        }
    }

    pub fn sendFullWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            last_result: IO.SendError!usize,
        ) void,
        completion: *Completion,
        buffer: *DynamicByteBuffer,
        flags: u32,
        timeout_ns: u63,
    ) void {
        std.debug.print("Client.sendFullWithTimeout socket={}\n", .{self.socket});
        completion.* = .{
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const IO.SendError!usize, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .buffer = buffer,
            .processed_len = 0,
        };
        std.debug.print("Client.sendFullWithTimeout calling sendWithTimeout socket={}\n", .{self.socket});
        self.io.sendWithTimeout(
            *Self,
            self,
            sendCallback,
            &completion.linked_completion,
            self.socket,
            buffer.readableSlice(0),
            flags,
            timeout_ns,
        );
    }
    fn sendCallback(
        self: *Self,
        linked_completion: *IO.LinkedCompletion,
        result: IO.SendError!usize,
    ) void {
        std.debug.print("Client.sendCallback result={}\n", .{result});
        const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
        if (result) |sent| {
            comp.processed_len += sent;
            const buf = comp.buffer;
            if (comp.processed_len < buf.readableLength()) {
                self.io.sendWithTimeout(
                    *Self,
                    self,
                    sendCallback,
                    linked_completion,
                    self.socket,
                    buf.readableSlice(comp.processed_len),
                    linked_completion.main_completion.operation.send.flags,
                    @intCast(u63, linked_completion.linked_completion.operation.link_timeout.timespec.tv_nsec),
                );
                return;
            }

            comp.callback(comp.context, comp, &result);
        } else |err| {
            comp.callback(comp.context, comp, &result);
            self.close();
        }
    }

    pub const RecvResponseHeaderError = error{
        UnexpectedEof,
        HeaderTooLong,
        BadGateway,
    } || IO.RecvError;

    pub fn recvResponseHeader(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: RecvResponseHeaderError!usize,
        ) void,
        completion: *Completion,
        buffer: *DynamicByteBuffer,
        header_buf_max_len: usize,
        flags: u32,
        timeout_ns: u63,
    ) void {
        assert(buffer.head == 0);
        assert(buffer.count == 0);
        completion.* = .{
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const RecvResponseHeaderError!usize, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .buffer = buffer,
            .processed_len = 0,
            .header_buf_max_len = header_buf_max_len,
        };

        self.resp_scanner = RecvResponseScanner{};
        self.io.recvWithTimeout(
            *Self,
            self,
            recvResponseHeaderCallback,
            &completion.linked_completion,
            self.socket,
            buffer.buf,
            flags,
            timeout_ns,
        );
    }
    fn recvResponseHeaderCallback(
        self: *Self,
        linked_completion: *IO.LinkedCompletion,
        result: IO.RecvError!usize,
    ) void {
        std.debug.print("Client.recvCallback result={}\n", .{result});
        const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
        if (result) |received| {
            if (received == 0) {
                const err = error.UnexpectedEof;
                comp.callback(comp.context, comp, &err);
                self.close();
                return;
            }

            const old = comp.processed_len;
            comp.processed_len += received;
            const buf = comp.buffer.buf;
            if (self.resp_scanner.scan(buf[old..comp.processed_len])) |done| {
                if (done) {
                    const total = self.resp_scanner.totalBytesRead();
                    if (RecvResponse.init(buf[0..total], &self.resp_scanner)) |resp| {
                        comp.response = resp;
                        comp.buffer.head = total;
                        comp.buffer.count = comp.processed_len - total;
                        comp.callback(comp.context, comp, &result);
                    } else |err| {
                        comp.callback(comp.context, comp, &err);
                        self.close();
                        return;
                    }
                } else {
                    if (old + received == buf.len) {
                        const new_len = 2 * buf.len;
                        if (comp.header_buf_max_len < new_len) {
                            const err = error.HeaderTooLong;
                            comp.callback(comp.context, comp, &err);
                            self.close();
                            return;
                        }

                        self.io.recvWithTimeout(
                            *Self,
                            self,
                            recvResponseHeaderCallback,
                            linked_completion,
                            self.socket,
                            buf[comp.processed_len..],
                            linked_completion.main_completion.operation.recv.flags,
                            @intCast(u63, linked_completion.linked_completion.operation.link_timeout.timespec.tv_nsec),
                        );
                    }
                }
            } else |err| {
                comp.callback(comp.context, comp, &err);
                self.close();
                return;
            }
        } else |err| {
            comp.callback(comp.context, comp, &err);
            self.close();
        }
    }

    pub fn recvWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: IO.RecvError!usize,
        ) void,
        completion: *Completion,
        buffer: *DynamicByteBuffer,
        flags: u32,
        timeout_ns: u63,
    ) void {
        assert(buffer.head == 0);
        assert(buffer.count == 0);

        completion.* = .{
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const IO.RecvError!usize, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .buffer = buffer,
        };
        self.io.recvWithTimeout(
            *Self,
            self,
            recvCallback,
            &completion.linked_completion,
            self.socket,
            buffer.buf,
            flags,
            timeout_ns,
        );
    }
    fn recvCallback(
        self: *Self,
        linked_completion: *IO.LinkedCompletion,
        result: IO.RecvError!usize,
    ) void {
        std.debug.print("Client.recvCallback result={}\n", .{result});
        const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
        if (result) |received| {
            comp.buffer.count = received;
            comp.callback(comp.context, comp, &result);
        } else |err| {
            comp.callback(comp.context, comp, &result);
            self.close();
        }
    }

    fn close(self: *Self) void {
        os.closeSocket(self.socket);
        self.done = true;
    }
};

test "http.Client" {
    try struct {
        const Context = @This();
        const FifoType = std.fifo.LinearFifo(u8, .Dynamic);
        const response_header_max_len = 4096;

        client: Client,
        buffer: FifoType,
        completion: Client.Completion = undefined,
        content_length: ?u64 = null,
        content_read_so_far: u64 = undefined,
        recv_timeout_ns: u63 = 5 * time.ns_per_s,

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const allocator = std.heap.page_allocator;

            var self: Context = .{
                .client = Client.init(&io),
                .buffer = FifoType.init(allocator),
            };
            defer self.buffer.deinit();
            std.debug.print("self=0x{x}, client=0x{x}\n", .{ @ptrToInt(&self), @ptrToInt(&self.client) });

            const address = try std.net.Address.parseIp4("127.0.0.1", 3131);
            try self.client.connectWithTimeout(
                *Context,
                &self,
                connectCallback,
                &self.completion,
                address,
                500 * time.ns_per_ms,
            );

            while (!self.client.done) {
                try io.tick();
            }
        }

        fn connectCallback(
            self: *Context,
            completion: *Client.Completion,
            result: IO.ConnectError!void,
        ) void {
            std.debug.print("connectCallback result={}\n", .{result});
            std.debug.print("connectCallback, self=0x{x}, client=0x{x}, socket={}\n", .{ @ptrToInt(self), @ptrToInt(&self.client), self.client.socket });
            var w = self.buffer.writer();
            std.fmt.format(w, "{s} {s} {s}\r\n", .{
                (Method{ .get = undefined }).toText(),
                "/",
                // "/" ++ "a" ** 8192,
                Version.http1_1.toText(),
            }) catch unreachable;
            std.fmt.format(w, "Host: example.com\r\n\r\n", .{}) catch unreachable;
            std.debug.print("calling self.client.sendFullWithTimeout, socket={}\n", .{self.client.socket});
            self.client.sendFullWithTimeout(
                *Context,
                self,
                sendCallback,
                &self.completion,
                &self.buffer,
                if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
                500 * time.ns_per_ms,
            );
        }
        fn sendCallback(
            self: *Context,
            completion: *Client.Completion,
            result: IO.SendError!usize,
        ) void {
            std.debug.print("sendCallback, processed_len={}, result={}\n", .{ completion.processed_len, result });
            if (result) |_| {
                self.buffer.head = 0;
                self.buffer.count = 0;
                self.buffer.ensureCapacity(1024) catch unreachable;
                self.client.recvResponseHeader(
                    *Context,
                    self,
                    recvResponseHeaderCallback,
                    &self.completion,
                    &self.buffer,
                    response_header_max_len,
                    if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
                    self.recv_timeout_ns,
                );
            } else |_| {}
        }
        fn recvResponseHeaderCallback(
            self: *Context,
            completion: *Client.Completion,
            result: Client.RecvResponseHeaderError!usize,
        ) void {
            std.debug.print("recvResponseHeaderCallback, processed_len={}, result={}\n", .{ completion.processed_len, result });
            if (result) |received| {
                const resp = completion.response;
                if (resp.headers.getContentLength()) |len| {
                    self.content_length = len;
                    if (len) |l| {
                        std.debug.print("content-length is {}\n", .{l});
                    } else {
                        std.debug.print("no content-length\n", .{});
                    }
                } else |err| {
                    std.debug.print("invalid content-length, err={s}\n", .{@errorName(err)});
                }

                const chunk = completion.buffer.readableSlice(0);
                std.debug.print("Response:\n{s} {} {s}\n{s}{s}\nchunk_len={}\n", .{
                    resp.version.toText(),
                    resp.status_code.code(),
                    resp.reason_phrase,
                    resp.headers.fields,
                    chunk,
                    chunk.len,
                });
                if (chunk.len == self.content_length.?) {
                    self.client.close();
                    return;
                }

                self.content_read_so_far = chunk.len;
                self.buffer.head = 0;
                self.buffer.count = 0;
                self.client.recvWithTimeout(
                    *Context,
                    self,
                    recvCallback,
                    &self.completion,
                    &self.buffer,
                    if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
                    self.recv_timeout_ns,
                );
            } else |err| {
                std.debug.print("recvResponseHeaderCallback err={s}\n", .{@errorName(err)});
            }
        }
        fn recvCallback(
            self: *Context,
            completion: *Client.Completion,
            result: IO.RecvError!usize,
        ) void {
            std.debug.print("recvCallback, result={}\n", .{result});
            if (result) |received| {
                self.content_read_so_far += received;
                std.debug.print("body chunk: {s}\n", .{completion.buffer.readableSlice(0)});
                std.debug.print("content_read_so_far={}, content_length={}\n", .{ self.content_read_so_far, self.content_length.? });
                if (self.content_read_so_far == self.content_length.?) {
                    self.client.close();
                    return;
                }

                self.buffer.head = 0;
                self.buffer.count = 0;
                self.client.recvWithTimeout(
                    *Context,
                    self,
                    recvCallback,
                    &self.completion,
                    &self.buffer,
                    if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
                    self.recv_timeout_ns,
                );
            } else |err| {
                std.debug.print("recvCallback err={s}\n", .{@errorName(err)});
            }
        }
    }.runTest();
}
