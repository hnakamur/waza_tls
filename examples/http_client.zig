const std = @import("std");
const mem = std.mem;
const os = std.os;
const time = std.time;
const IO = @import("tigerbeetle-io").IO;
const http = @import("hutaback");

const Client = struct {
    pub const Config = struct {
        recv_buf_ini_len: usize = 1024,
        recv_buf_max_len: usize = 8192,
        send_buf_len: usize = 4096,
    };

    io: *IO,
    allocator: mem.Allocator,
    config: *const Config,
    linked_completion: IO.LinkedCompletion = undefined,
    socket: os.socket_t = undefined,
    send_buf: []u8,
    recv_buf: []u8,
    connect_timeout_ns: u63 = 2 * time.ns_per_s,
    send_timeout_ns: u63 = 2 * time.ns_per_s,
    recv_timeout_ns: u63 = 2 * time.ns_per_s,
    done: bool = false,
    req_headers_len: u32 = 0,
    req_content_length: ?u64 = null,
    send_buf_data_len: u32 = 0,
    send_buf_sent_len: u32 = 0,
    send_bytes_so_far: u64 = 0,
    state: enum {
        Initial,
        SendingHeaders,
        SendingContent,
        ReceivingHeaders,
        ReceivingContent,
    } = .Initial,
    resp_scanner: http.RecvResponseScanner,
    resp_headers_buf: ?[]u8 = null,
    content_length: ?u64 = null,
    content_length_read_so_far: u64 = 0,

    const Self = @This();

    pub fn init(
        allocator: mem.Allocator,
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
            .resp_scanner = http.RecvResponseScanner{},
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.send_buf);
        self.allocator.free(self.recv_buf);
    }

    fn connect(self: *Self, addr: std.net.Address) !void {
        self.socket = try os.socket(addr.any.family, os.SOCK.STREAM | os.SOCK.CLOEXEC, 0);

        self.io.connectWithTimeout(
            *Self,
            self,
            connectCallback,
            &self.linked_completion,
            self.socket,
            addr,
            self.connect_timeout_ns,
        );
    }
    fn connectCallback(
        self: *Self,
        comp: *IO.LinkedCompletion,
        result: IO.ConnectError!void,
    ) void {
        _ = comp;
        if (result) |_| {
            self.state = .SendingHeaders;
            var fbs = std.io.fixedBufferStream(self.send_buf);
            var w = fbs.writer();
            std.fmt.format(w, "{s} {s} {s}\r\n", .{
                (http.Method{ .get = undefined }).toBytes(),
                "/",
                // "/" ++ "a" ** 8192,
                http.Version.http1_1.toBytes(),
            }) catch unreachable;
            std.fmt.format(w, "Host: example.com\r\n", .{}) catch unreachable;
            std.fmt.format(w, "\r\n", .{}) catch unreachable;
            const pos = fbs.getPos() catch unreachable;
            self.req_headers_len = @intCast(u32, pos);
            self.req_content_length = 0;
            self.state = .SendingContent;

            // self.req_content_length = 8000;
            // std.fmt.format(w, "Content-Length: {}\r\n", .{self.req_content_length.?}) catch unreachable;

            // std.fmt.format(w, "X-Foo: ", .{}) catch unreachable;
            // var pos = fbs.getPos() catch unreachable;
            // std.debug.print("pos={}, self.send_buf.len={}\n", .{ pos, self.send_buf.len });
            // const foo_header_len = 6;
            //     self.send_buf_data_len = @intCast(u32, std.math.min(
            //         pos + foo_header_len,
            //         self.send_buf.len,
            //     ));
            // while (pos < self.send_buf_data_len) : (pos += 1) {
            //     self.send_buf[pos] = 'f';
            // }
            // std.debug.print("self.send_buf={s}\n", .{self.send_buf});
            self.send_buf_data_len = @intCast(u32, self.req_headers_len);
            self.send_buf_sent_len = 0;
            // self.req_headers_len += self.send_buf_data_len;
            self.io.sendWithTimeout(
                *Self,
                self,
                sendCallback,
                &self.linked_completion,
                self.socket,
                self.send_buf[0..self.send_buf_data_len],
                0,
                self.send_timeout_ns,
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
        _ = comp;
        std.debug.print("MyContext.sendCallback, result={}\n", .{result});
        if (result) |sent| {
            self.send_buf_sent_len += @intCast(u32, sent);
            self.send_bytes_so_far += sent;
            if (self.send_buf_sent_len < self.send_buf_data_len) {
                self.io.sendWithTimeout(
                    *Client,
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
                    var fbs = std.io.fixedBufferStream(self.send_buf);
                    var w = fbs.writer();
                    std.fmt.format(w, "gggg\r\n\r\n", .{}) catch unreachable;
                    var pos = fbs.getPos() catch unreachable;
                    self.req_headers_len += @intCast(u32, pos);
                    while (pos < self.send_buf.len) : (pos += 1) {
                        self.send_buf[pos] = 'g';
                    }
                    std.debug.print("self.send_buf={s}\n", .{self.send_buf});
                    self.send_buf_data_len = @intCast(u32, self.send_buf.len);
                    self.send_buf_sent_len = 0;
                    self.io.sendWithTimeout(
                        *Self,
                        self,
                        sendCallback,
                        &self.linked_completion,
                        self.socket,
                        self.send_buf[0..self.send_buf_data_len],
                        0,
                        self.send_timeout_ns,
                    );
                },
                .SendingContent => {
                    std.debug.print("sendCallback state=.SendingContent, req_content_length={}, send_bytes_so_far={}, req_headers_len={}\n", .{
                        self.req_content_length.?,
                        self.send_bytes_so_far,
                        self.req_headers_len,
                    });
                    self.send_buf_data_len = @intCast(u32, std.math.min(
                        self.req_content_length.? - (self.send_bytes_so_far - self.req_headers_len),
                        self.send_buf.len,
                    ));
                    if (self.send_buf_data_len > 0) {
                        var pos: usize = 0;
                        while (pos < self.send_buf_data_len) : (pos += 1) {
                            self.send_buf[pos] = 'h';
                        }
                        self.send_buf_sent_len = 0;
                        self.io.sendWithTimeout(
                            *Self,
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

                    self.state = .ReceivingHeaders;
                    self.io.recvWithTimeout(
                        *Self,
                        self,
                        recvCallback,
                        &self.linked_completion,
                        self.socket,
                        self.recv_buf,
                        0,
                        self.recv_timeout_ns,
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
        _ = comp;
        // std.debug.print("MyContext.recvCallback, result={}\n", .{result});
        if (result) |received| {
            if (received == 0) {
                std.debug.print("recvCallback, closed from server\n", .{});
                self.close();
                return;
            }

            switch (self.state) {
                .ReceivingHeaders => {
                    const old = self.resp_scanner.totalBytesRead();
                    if (self.resp_scanner.scan(self.recv_buf[old .. old + received])) |done| {
                        if (done) {
                            self.state = .ReceivingContent;
                            const total = self.resp_scanner.totalBytesRead();
                            if (http.RecvResponse.init(self.recv_buf[0..total], &self.resp_scanner)) |resp| {
                                std.debug.print("response version={}, status_code={}, reason_phrase={s}\n", .{
                                    resp.version, resp.status_code, resp.reason_phrase,
                                });
                                std.debug.print("response headers=\n{s}\n", .{
                                    resp.headers.fields,
                                });
                                self.content_length = if (resp.headers.getContentLength()) |len| len else |err| {
                                    std.debug.print("bad response, invalid content-length, err={s}\n", .{@errorName(err)});
                                    self.close();
                                    return;
                                };
                                if (self.content_length) |len| {
                                    std.debug.print("content_length={}\n", .{len});
                                    const actual_content_chunk_len = old + received - total;
                                    self.content_length_read_so_far += actual_content_chunk_len;
                                    std.debug.print("first content chunk length={},\ncontent=\n{s}", .{
                                        actual_content_chunk_len,
                                        self.recv_buf[total .. old + received],
                                    });
                                    if (actual_content_chunk_len < len) {
                                        self.io.recvWithTimeout(
                                            *Client,
                                            self,
                                            recvCallback,
                                            &self.linked_completion,
                                            self.socket,
                                            self.recv_buf,
                                            0,
                                            self.recv_timeout_ns,
                                        );
                                        return;
                                    }
                                } else {
                                    std.debug.print("no content_length in response headers\n", .{});
                                }
                            } else |err| {
                                std.debug.print("invalid response header fields, err={s}\n", .{@errorName(err)});
                            }
                        } else {
                            if (old + received == self.recv_buf.len) {
                                const new_len = self.recv_buf.len + self.config.recv_buf_ini_len;
                                if (self.config.recv_buf_max_len < new_len) {
                                    std.debug.print("response header fields too long.\n", .{});
                                    self.close();
                                    return;
                                }
                                self.recv_buf = self.allocator.realloc(self.recv_buf, new_len) catch unreachable;
                            }
                            self.io.recvWithTimeout(
                                *Client,
                                self,
                                recvCallback,
                                &self.linked_completion,
                                self.socket,
                                self.recv_buf[old + received ..],
                                0,
                                self.recv_timeout_ns,
                            );
                            return;
                        }
                    } else |err| {
                        std.debug.print("got error while reading response headers, {s}\n", .{@errorName(err)});
                    }
                },
                .ReceivingContent => {
                    std.debug.print("{s}", .{self.recv_buf[0..received]});
                    self.content_length_read_so_far += received;
                    if (self.content_length_read_so_far < self.content_length.?) {
                        self.io.recvWithTimeout(
                            *Client,
                            self,
                            recvCallback,
                            &self.linked_completion,
                            self.socket,
                            self.recv_buf,
                            0,
                            self.recv_timeout_ns,
                        );
                        return;
                    }
                },
                else => {
                    std.debug.print("MyContext.recvCallback unexpected state {}\n", .{self.state});
                },
            }
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
