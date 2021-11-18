const std = @import("std");
const mem = std.mem;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const RecvResponseScanner = @import("recv_response.zig").RecvResponseScanner;
const RecvResponse = @import("recv_response.zig").RecvResponse;
const Method = @import("method.zig").Method;
const Version = @import("version.zig").Version;

pub const Client = struct {
    const Self = @This();

    pub const Config = struct {
        recv_buf_ini_len: usize = 1024,
        recv_buf_max_len: usize = 8192,
        send_buf_len: usize = 4096,
    };

    pub const ConnectCompletion = struct {
        linked_completion: IO.LinkedCompletion = undefined,
        context: ?*c_void = null,
        callback: fn (ctx: ?*c_void, comp: *ConnectCompletion, result: IO.ConnectError!void) void = undefined,
    };

    pub const SendCompletion = struct {
        linked_completion: IO.LinkedCompletion = undefined,
        context: ?*c_void = null,
        buf: []const u8 = undefined,
        sent_len: usize = 0,
        callback: fn (ctx: ?*c_void, comp: *SendCompletion, last_result: IO.SendError!usize) void = undefined,
    };

    io: *IO,
    allocator: *mem.Allocator,
    config: *const Config,
    socket: os.socket_t = undefined,
    send_buf: []u8,
    recv_buf: []u8,
    done: bool = false,
    req_headers_len: usize = 0,
    req_content_length: ?u64 = null,
    send_buf_data_len: usize = 0,
    send_buf_sent_len: usize = 0,
    send_bytes_so_far: usize = 0,
    resp_scanner: RecvResponseScanner,
    resp_headers_buf: ?[]u8 = null,
    content_length: ?u64 = null,
    content_length_read_so_far: u64 = 0,

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
            .resp_scanner = RecvResponseScanner{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.send_buf);
        self.allocator.free(self.recv_buf);
    }

    pub fn connectWithTimeout(
        self: *Self,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *ConnectCompletion,
            result: IO.ConnectError!void,
        ) void,
        completion: *ConnectCompletion,
        addr: std.net.Address,
        connect_timeout_ns: u63,
    ) !void {
        self.socket = try os.socket(addr.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);
        std.debug.print("Client.connectWithTimeout, client=0x{x}, socket={}\n", .{@ptrToInt(self), self.socket});

        completion.* = .{
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*c_void, comp: *ConnectCompletion, res: IO.ConnectError!void) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        res,
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
        const comp = @fieldParentPtr(ConnectCompletion, "linked_completion", linked_completion);
        comp.callback(comp.context, comp, result);
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
            completion: *SendCompletion,
            last_result: IO.SendError!usize,
        ) void,
        completion: *SendCompletion,
        buf: []const u8,
        send_flags: u32,
        timeout_ns: u63,
    ) void {
        std.debug.print("Client.sendFullWithTimeout socket={}\n", .{self.socket});
        completion.* = .{
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*c_void, comp: *SendCompletion, last_res: IO.SendError!usize) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        last_res,
                    );
                }
            }.wrapper,
            .buf = buf,
            .sent_len = 0,
        };
        std.debug.print("Client.sendFullWithTimeout calling sendWithTimeout socket={}\n", .{self.socket});
        self.io.sendWithTimeout(
            *Self,
            self,
            sendCallback,
            &completion.linked_completion,
            self.socket,
            buf,
            send_flags,
            timeout_ns,
        );
    }
    fn sendCallback(
        self: *Self,
        linked_completion: *IO.LinkedCompletion,
        result: IO.SendError!usize,
    ) void {
        std.debug.print("Client.sendCallback result={}\n", .{result});
        const comp = @fieldParentPtr(SendCompletion, "linked_completion", linked_completion);
        if (result) |sent| {
            comp.sent_len += sent;
            if (comp.sent_len < comp.buf.len) {
                self.io.sendWithTimeout(
                    *Self,
                    self,
                    sendCallback,
                    linked_completion,
                    self.socket,
                    comp.buf[self.send_buf_sent_len..],
                    linked_completion.main_completion.operation.send.flags,
                    @intCast(u63, linked_completion.linked_completion.operation.link_timeout.timespec.tv_nsec),
                );
                return;
            }

            comp.callback(comp.context, comp, result);
        } else |err| {
            comp.callback(comp.context, comp, result);
            self.close();
        }
    }
    // fn recvCallback(
    //     self: *Self,
    //     comp: *IO.LinkedCompletion,
    //     result: IO.RecvError!usize,
    // ) void {
    //     // std.debug.print("MyContext.recvCallback, result={}\n", .{result});
    //     if (result) |received| {
    //         if (received == 0) {
    //             std.debug.print("recvCallback, closed from server\n", .{});
    //             self.close();
    //             return;
    //         }

    //         switch (self.state) {
    //             .ReceivingHeaders => {
    //                 const old = self.resp_scanner.totalBytesRead();
    //                 if (self.resp_scanner.scan(self.recv_buf[old .. old + received])) |done| {
    //                     if (done) {
    //                         self.state = .ReceivingContent;
    //                         const total = self.resp_scanner.totalBytesRead();
    //                         if (http.RecvResponse.init(self.recv_buf[0..total], &self.resp_scanner)) |resp| {
    //                             std.debug.print("response version={}, status_code={}, reason_phrase={s}\n", .{
    //                                 resp.version, resp.status_code, resp.reason_phrase,
    //                             });
    //                             std.debug.print("response headers=\n{s}\n", .{
    //                                 resp.headers.fields,
    //                             });
    //                             self.content_length = if (resp.headers.getContentLength()) |len| len else |err| {
    //                                 std.debug.print("bad response, invalid content-length, err={s}\n", .{@errorName(err)});
    //                                 self.close();
    //                                 return;
    //                             };
    //                             if (self.content_length) |len| {
    //                                 std.debug.print("content_length={}\n", .{len});
    //                                 const actual_content_chunk_len = old + received - total;
    //                                 self.content_length_read_so_far += actual_content_chunk_len;
    //                                 std.debug.print("first content chunk length={},\ncontent=\n{s}", .{
    //                                     actual_content_chunk_len,
    //                                     self.recv_buf[total .. old + received],
    //                                 });
    //                                 if (actual_content_chunk_len < len) {
    //                                     self.io.recvWithTimeout(
    //                                         *Client,
    //                                         self,
    //                                         recvCallback,
    //                                         &self.linked_completion,
    //                                         self.socket,
    //                                         self.recv_buf,
    //                                         0,
    //                                         self.recv_timeout_ns,
    //                                     );
    //                                     return;
    //                                 }
    //                             } else {
    //                                 std.debug.print("no content_length in response headers\n", .{});
    //                             }
    //                         } else |err| {
    //                             std.debug.print("invalid response header fields, err={s}\n", .{@errorName(err)});
    //                         }
    //                     } else {
    //                         if (old + received == self.recv_buf.len) {
    //                             const new_len = self.recv_buf.len + self.config.recv_buf_ini_len;
    //                             if (self.config.recv_buf_max_len < new_len) {
    //                                 std.debug.print("response header fields too long.\n", .{});
    //                                 self.close();
    //                                 return;
    //                             }
    //                             self.recv_buf = self.allocator.realloc(self.recv_buf, new_len) catch unreachable;
    //                         }
    //                         self.io.recvWithTimeout(
    //                             *Client,
    //                             self,
    //                             recvCallback,
    //                             &self.linked_completion,
    //                             self.socket,
    //                             self.recv_buf[old + received ..],
    //                             0,
    //                             self.recv_timeout_ns,
    //                         );
    //                         return;
    //                     }
    //                 } else |err| {
    //                     std.debug.print("got error while reading response headers, {s}\n", .{@errorName(err)});
    //                 }
    //             },
    //             .ReceivingContent => {
    //                 std.debug.print("{s}", .{self.recv_buf[0..received]});
    //                 self.content_length_read_so_far += received;
    //                 if (self.content_length_read_so_far < self.content_length.?) {
    //                     self.io.recvWithTimeout(
    //                         *Client,
    //                         self,
    //                         recvCallback,
    //                         &self.linked_completion,
    //                         self.socket,
    //                         self.recv_buf,
    //                         0,
    //                         self.recv_timeout_ns,
    //                     );
    //                     return;
    //                 }
    //             },
    //             else => {
    //                 std.debug.print("MyContext.recvCallback unexpected state {}\n", .{self.state});
    //             },
    //         }
    //     } else |err| {
    //         std.debug.print("MyContext.recvCallback, err={s}\n", .{@errorName(err)});
    //     }
    //     self.close();
    // }

    fn close(self: *Self) void {
        os.closeSocket(self.socket);
        self.done = true;
    }
};

test "http.Client" {
    try struct {
        const Context = @This();
        const FifoType = std.fifo.LinearFifo(u8, .Dynamic);

        client: Client,
        send_buf: FifoType,
        send_completion: Client.SendCompletion = undefined,

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const allocator = std.heap.page_allocator;
            const config = Client.Config{};

            var self: Context = .{
                .client = try Client.init(allocator, &io, &config),
                .send_buf = FifoType.init(allocator),
            };
            defer self.client.deinit();
            defer self.send_buf.deinit();
            std.debug.print("self=0x{x}, client=0x{x}\n", .{@ptrToInt(&self), @ptrToInt(&self.client)});

            const address = try std.net.Address.parseIp4("127.0.0.1", 3131);
            var connect_comp: Client.ConnectCompletion = undefined;
            try self.client.connectWithTimeout(
                *Context,
                &self,
                connectCallback,
                &connect_comp,
                address,
                500 * time.ns_per_ms,
            );

            while (!self.client.done) {
                try io.tick();
            }
        }

        fn connectCallback(
            self: *Context,
            completion: *Client.ConnectCompletion,
            result: IO.ConnectError!void,
        ) void {
            std.debug.print("connectCallback result={}\n", .{result});
            std.debug.print("connectCallback, self=0x{x}, client=0x{x}, socket={}\n", .{@ptrToInt(self), @ptrToInt(&self.client), self.client.socket});
            var w = self.send_buf.writer();
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
                &self.send_completion,
                self.send_buf.readableSlice(0),
                if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0,
                500 * time.ns_per_ms,
            );
        }
        fn sendCallback(
            self: *Context,
            completion: *Client.SendCompletion,
            last_result: IO.SendError!usize,
        ) void {
            std.debug.print("sendCallback, sent_len={}, last_result={}\n", .{ completion.sent_len, last_result });
        }
    }.runTest();
}
