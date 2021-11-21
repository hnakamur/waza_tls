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

    pub fn close(self: *Self) void {
        os.closeSocket(self.socket);
        self.done = true;
    }
};
