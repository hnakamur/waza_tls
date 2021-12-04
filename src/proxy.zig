const std = @import("std");
const mem = std.mem;
const net = std.net;
const GenClient = @import("client.zig").Client;
const GenServer = @import("server.zig").Server;
const IO = @import("tigerbeetle-io").IO;

const http_log = std.log.scoped(.http);

pub fn Proxy(comptime Context: type) type {
    return struct {
        const Self = @This();
        const Server = GenServer(Self, Handler);
        const Client = GenClient(Handler);

        const Handler = struct {
            conn: *Server.Conn = undefined,
            client: Client = undefined,
            client_connected: bool = false,
            resp_first_fragment: []u8 = undefined,
            resp_first_fragment_len: usize = undefined,

            pub fn init(self: *Handler) !void {
                const allocator = self.conn.server.allocator;
                const io = self.conn.server.io;
                const client_config = &self.conn.server.context.client_config;
                self.client = try Client.init(allocator, io, self, client_config);
                self.resp_first_fragment = try allocator.alloc(u8, client_config.response_content_fragment_buf_len);
            }

            pub fn deinit(self: *Handler) void {
                self.client.deinit();
                const allocator = self.conn.server.allocator;
                allocator.free(self.resp_first_fragment);
            }

            pub fn start(self: *Handler) void {
                http_log.debug("Proxy.Handler.start", .{});
                self.conn.recvRequestHeader(recvRequestHeaderCallback);
            }

            pub fn recvRequestHeaderCallback(self: *Handler, result: Server.RecvRequestHeaderError!usize) void {
                http_log.debug("Handler.recvRequestHeaderCallback start, result={}", .{result});
                if (result) |_| {
                    if (self.client_connected) {
                        self.sendRequestHeader();
                    } else {
                        if (self.client.connect(self.conn.server.context.upstream_address, connectCallback)) |_| {} else |err| {
                            http_log.err("Proxy.Handler.recvRequestHeaderCallback connect err={s}", .{@errorName(err)});
                        }
                    }
                } else |err| {
                    http_log.err("Handler.recvRequestHeaderCallback err={s}", .{@errorName(err)});
                }
            }
            fn connectCallback(
                self: *Handler,
                result: IO.ConnectError!void,
            ) void {
                http_log.debug("Proxy.Handler.connectCallback start, result={}", .{result});
                if (result) |_| {
                    self.client_connected = true;
                    self.sendRequestHeader();
                } else |err| {
                    http_log.err("Proxy.Handler.connectCallback err={s}", .{@errorName(err)});
                }
            }
            fn sendRequestHeader(
                self: *Handler,
            ) void {
                // TODO: build a modified request.
                self.client.sendFull(self.conn.request.buf, sendRequestHeaderCallback);
            }
            fn sendRequestHeaderCallback(
                self: *Handler,
                result: IO.SendError!usize,
            ) void {
                http_log.debug("Proxy.Handler.sendRequestHeaderCallback start, result={}", .{result});
                if (result) |_| {
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }
                    self.recvResponseHeader();
                } else |err| {
                    http_log.err("Proxy.Handler.sendRequestHeaderCallback err={s}", .{@errorName(err)});
                }
            }
            pub fn recvRequestContentFragmentCallback(self: *Handler, result: Server.RecvRequestContentFragmentError!usize) void {
                http_log.debug("Handler.recvRequestContentFragmentCallback start, result={}", .{result});
                if (result) |received| {
                    self.sendRequestContentFragment(received);
                } else |err| {
                    http_log.err("Handler.recvRequestContentFragmentCallback err={s}", .{@errorName(err)});
                }
            }
            fn sendRequestContentFragment(
                self: *Handler,
                send_len: usize,
            ) void {
                self.client.sendFull(
                    self.conn.request_content_fragment_buf.?[0..send_len],
                    sendRequestContentFragmentCallback,
                );
            }
            fn sendRequestContentFragmentCallback(
                self: *Handler,
                result: IO.SendError!usize,
            ) void {
                http_log.debug("Proxy.Handler.sendRequestContentFragmentCallback start, result={}", .{result});
                if (result) |_| {
                    if (!self.conn.fullyReadRequestContent()) {
                        self.conn.recvRequestContentFragment(recvRequestContentFragmentCallback);
                        return;
                    }
                    self.recvResponseHeader();
                } else |err| {
                    http_log.err("Proxy.Handler.sendRequestContentFragmentCallback err={s}", .{@errorName(err)});
                }
            }

            fn recvResponseHeader(
                self: *Handler,
            ) void {
                self.client.recvResponseHeader(recvResponseHeaderCallback);
            }
            fn recvResponseHeaderCallback(
                self: *Handler,
                result: Client.RecvResponseHeaderError!usize,
            ) void {
                http_log.debug("Proxy.Handler.recvResponseHeaderCallback start, result={}", .{result});
                if (result) |_| {
                    self.sendResponseHeader();
                } else |err| {
                    http_log.err("Proxy.Handler.recvResponseHeaderCallback err={s}", .{@errorName(err)});
                }
            }
            fn sendResponseHeader(
                self: *Handler,
            ) void {
                if (self.client.response_content_fragment_buf) |buf| {
                    self.resp_first_fragment_len = buf.len;
                    mem.copy(u8, self.resp_first_fragment, buf);
                } else {
                    self.resp_first_fragment_len = 0;
                }
                // TODO: build a modified response.
                self.conn.sendFull(self.client.response.buf, sendResponseHeaderCallback);
            }
            fn sendResponseHeaderCallback(
                self: *Handler,
                last_result: IO.SendError!usize,
            ) void {
                http_log.debug("Proxy.Handler.sendResponseHeaderCallback start, last_result={}", .{last_result});
                if (last_result) |_| {
                    if (self.resp_first_fragment_len > 0) {
                        self.conn.sendFull(
                            self.resp_first_fragment[0..self.resp_first_fragment_len],
                            sendResponseContentFragmentCallback,
                        );
                        return;
                    }

                    if (!self.client.fullyReadResponseContent()) {
                        self.client.recvResponseContentFragment(recvResponseContentFragmentCallback);
                        return;
                    }

                    self.conn.finishSend();
                } else |err| {
                    http_log.err("Proxy.Handler.sendResponseHeaderCallback err={s}", .{@errorName(err)});
                }
            }
            fn recvResponseContentFragmentCallback(
                self: *Handler,
                result: Client.RecvResponseContentFragmentError!usize,
            ) void {
                http_log.debug("Proxy.Handler.recvResponseContentFragmentCallback start, result={}", .{result});
                if (result) |received| {
                    self.sendResponseContentFragment(received);
                } else |err| {
                    http_log.err("Proxy.HandlerrecvResponseContentFragmentCallback err={s}", .{@errorName(err)});
                }
            }
            fn sendResponseContentFragment(
                self: *Handler,
                send_len: usize,
            ) void {
                self.conn.sendFull(
                    self.client.response_content_fragment_buf.?[0..send_len],
                    sendResponseContentFragmentCallback,
                );
            }
            fn sendResponseContentFragmentCallback(
                self: *Handler,
                last_result: IO.SendError!usize,
            ) void {
                http_log.debug("Proxy.Handler.sendResponseContentFragmentCallback start, last_result={}", .{last_result});
                if (last_result) |_| {
                    if (!self.client.fullyReadResponseContent()) {
                        self.client.recvResponseContentFragment(recvResponseContentFragmentCallback);
                        return;
                    }

                    self.conn.finishSend();
                } else |err| {
                    http_log.err("Proxy.Handler.sendResponseContentFragmentCallback err={s}", .{@errorName(err)});
                }
            }
        };

        allocator: *mem.Allocator,
        io: *IO,
        context: *Context,
        listen_address: net.Address,
        upstream_address: net.Address,
        client_config: Client.Config,
        server: Server = undefined,

        pub fn init(
            allocator: *mem.Allocator,
            io: *IO,
            context: *Context,
            listen_address: net.Address,
            upstream_address: net.Address,
            server_config: Server.Config,
            client_config: Client.Config,
        ) !*Self {
            var self = try allocator.create(Self);
            self.* = Self{
                .allocator = allocator,
                .io = io,
                .context = context,
                .listen_address = listen_address,
                .upstream_address = upstream_address,
                .client_config = client_config,
            };

            self.server = try Server.init(
                allocator,
                io,
                self,
                listen_address,
                server_config,
            );

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.server.deinit();
            self.allocator.destroy(self);
        }
    };
}
