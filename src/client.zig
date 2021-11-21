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

const recv_flags = if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0;
const send_flags = if (std.Target.current.os.tag == .linux) os.MSG_NOSIGNAL else 0;

pub fn Client(comptime Context: type) type {
    return struct {
        const Self = @This();

        pub const Completion = struct {
            linked_completion: IO.LinkedCompletion = undefined,
            context: ?*c_void = null,
            buffer: *DynamicByteBuffer = undefined,
            processed_len: usize = undefined,
            header_buf_max_len: usize = undefined,
            response: RecvResponse = undefined,
            callback: fn (ctx: ?*c_void, result: *const c_void) void = undefined,
        };

        io: *IO,
        context: *Context,
        socket: os.socket_t = undefined,
        completion: Completion = undefined,
        resp_scanner: RecvResponseScanner = undefined,
        connect_timeout_ns: u63 = 5 * time.ns_per_s,
        send_timeout_ns: u63 = 5 * time.ns_per_s,
        recv_timeout_ns: u63 = 5 * time.ns_per_s,
        done: bool = false,

        pub fn init(io: *IO, context: *Context) Self {
            return Self{
                .io = io,
                .context = context,
            };
        }

        pub fn connect(
            self: *Self,
            context: *Context,
            comptime callback: fn (
                context: *Context,
                result: IO.ConnectError!void,
            ) void,
            addr: std.net.Address,
        ) !void {
            self.socket = try os.socket(addr.any.family, os.SOCK_STREAM | os.SOCK_CLOEXEC, 0);

            self.completion = .{
                .context = context,
                .callback = struct {
                    fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            @intToPtr(*const IO.ConnectError!void, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
            };
            self.io.connectWithTimeout(
                *Self,
                self,
                connectCallback,
                &self.completion.linked_completion,
                self.socket,
                addr,
                self.connect_timeout_ns,
            );
        }
        fn connectCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.ConnectError!void,
        ) void {
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            comp.callback(comp.context, &result);
            if (result) |_| {} else |err| {
                self.close();
            }
        }

        pub fn sendFull(
            self: *Self,
            context: *Context,
            comptime callback: fn (
                context: *Context,
                last_result: IO.SendError!usize,
            ) void,
            buffer: *DynamicByteBuffer,
        ) void {
            self.completion = .{
                .context = context,
                .callback = struct {
                    fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            @intToPtr(*const IO.SendError!usize, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
                .buffer = buffer,
                .processed_len = 0,
            };
            self.io.sendWithTimeout(
                *Self,
                self,
                sendCallback,
                &self.completion.linked_completion,
                self.socket,
                buffer.readableSlice(0),
                send_flags,
                self.send_timeout_ns,
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
                        send_flags,
                    );
                    return;
                }

                comp.callback(comp.context, &result);
            } else |err| {
                comp.callback(comp.context, &result);
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
            context: *Context,
            comptime callback: fn (
                context: *Context,
                result: RecvResponseHeaderError!usize,
            ) void,
            buffer: *DynamicByteBuffer,
            header_buf_max_len: usize,
        ) void {
            assert(buffer.head == 0);
            assert(buffer.count == 0);
            self.completion = .{
                .context = context,
                .callback = struct {
                    fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
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
                &self.completion.linked_completion,
                self.socket,
                buffer.buf,
                recv_flags,
                self.recv_timeout_ns,
            );
        }
        fn recvResponseHeaderCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.RecvError!usize,
        ) void {
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            if (result) |received| {
                if (received == 0) {
                    const err = error.UnexpectedEof;
                    comp.callback(comp.context, &err);
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
                            comp.callback(comp.context, &result);
                        } else |err| {
                            comp.callback(comp.context, &err);
                            self.close();
                            return;
                        }
                    } else {
                        if (old + received == buf.len) {
                            const new_len = 2 * buf.len;
                            if (comp.header_buf_max_len < new_len) {
                                const err = error.HeaderTooLong;
                                comp.callback(comp.context, &err);
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
                    comp.callback(comp.context, &err);
                    self.close();
                    return;
                }
            } else |err| {
                comp.callback(comp.context, &err);
                self.close();
            }
        }

        pub fn recv(
            self: *Self,
            context: *Context,
            comptime callback: fn (
                context: *Context,
                result: IO.RecvError!usize,
            ) void,
            buffer: *DynamicByteBuffer,
        ) void {
            assert(buffer.head == 0);
            assert(buffer.count == 0);

            self.completion = .{
                .context = context,
                .callback = struct {
                    fn wrapper(ctx: ?*c_void, res: *const c_void) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
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
                &self.completion.linked_completion,
                self.socket,
                buffer.buf,
                recv_flags,
                self.recv_timeout_ns,
            );
        }
        fn recvCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.RecvError!usize,
        ) void {
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            if (result) |received| {
                comp.buffer.count = received;
                comp.callback(comp.context, &result);
            } else |err| {
                comp.callback(comp.context, &result);
                self.close();
            }
        }

        pub fn close(self: *Self) void {
            os.closeSocket(self.socket);
            self.done = true;
        }
    };
}
