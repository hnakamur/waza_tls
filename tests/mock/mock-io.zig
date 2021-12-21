const std = @import("std");
const assert = std.debug.assert;
const os = std.os;

const FIFO = @import("fifo.zig").FIFO;

const tigerbeetle_io_log = if (false) std.log.scoped(.@"tigerbeetle-io") else blk: {
    break :blk struct {
        pub fn debug(
            comptime format: []const u8,
            args: anytype,
        ) void {
            _ = format;
            _ = args;
        }
    };
};

pub const IO = struct {
    /// Operations queued.
    queued: FIFO(Completion) = .{},

    /// Completions that are ready to have their callbacks run.
    completed: FIFO(Completion) = .{},

    pub fn init(_: u12, _: u32) !IO {
        return IO{};
    }

    pub fn deinit(_: *IO) void {}

    /// Pass all queued submissions to the kernel and peek for completions.
    pub fn tick(
        self: *IO,
        comptime Context: type,
        context: Context,
        setResult: fn (
            context: Context,
            completion: *Completion,
        ) void,
    ) !void {
        {
            var copy = self.queued;
            self.queued = .{};
            while (copy.pop()) |completion| {
                setResult(context, completion);
                self.completed.push(completion);
            }
        }

        // Run completions only after all completions have been flushed:
        // Loop on a copy of the linked list, having reset the list first, so that any synchronous
        // append on running a completion is executed only the next time round the event loop,
        // without creating an infinite loop.
        {
            var copy = self.completed;
            self.completed = .{};
            while (copy.pop()) |completion| {
                completion.complete();
            }
        }
    }

    fn enqueue(self: *IO, completion: *Completion) void {
        self.queued.push(completion);
    }

    fn enqueueLinked(self: *IO, completion1: *Completion, completion2: *Completion) void {
        self.queued.push(completion1);
        self.queued.push(completion2);
    }

    /// This struct holds the data needed for a single io_uring operation
    pub const Completion = struct {
        io: *IO,
        result: i32 = undefined,
        next: ?*Completion = null,
        operation: Operation,
        linked: bool = false,
        // This is one of the usecases for anyopaque outside of C code and as such anyopaque will
        // be replaced with anyopaque eventually: https://github.com/ziglang/zig/issues/323
        context: ?*anyopaque,
        callback: fn (context: ?*anyopaque, completion: *Completion, result: *const anyopaque) void,

        pub fn err(self: *const Completion) os.E {
            if (self.result > -4096 and self.result < 0) {
                return @intToEnum(os.E, -self.result);
            }
            return .SUCCESS;
        }

        fn complete(completion: *Completion) void {
            switch (completion.operation) {
                .accept => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.AGAIN => error.Again,
                        os.E.BADF => error.FileDescriptorInvalid,
                        os.E.CANCELED => error.Canceled,
                        os.E.CONNABORTED => error.ConnectionAborted,
                        os.E.FAULT => unreachable,
                        os.E.INVAL => error.SocketNotListening,
                        os.E.MFILE => error.ProcessFdQuotaExceeded,
                        os.E.NFILE => error.SystemFdQuotaExceeded,
                        os.E.NOBUFS => error.SystemResources,
                        os.E.NOMEM => error.SystemResources,
                        os.E.NOTSOCK => error.FileDescriptorNotASocket,
                        os.E.OPNOTSUPP => error.OperationNotSupported,
                        os.E.PERM => error.PermissionDenied,
                        os.E.PROTO => error.ProtocolFailure,
                        else => |errno| os.unexpectedErrno(errno),
                    } else @intCast(os.socket_t, completion.result);
                    completion.callback(completion.context, completion, &result);
                },
                .cancel => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.ALREADY => error.AlreadyInProgress,
                        os.E.NOENT => error.NotFound,
                        else => |errno| os.unexpectedErrno(errno),
                    } else assert(completion.result == 0);
                    completion.callback(completion.context, completion, &result);
                },
                .close => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {}, // A success, see https://github.com/ziglang/zig/issues/2425
                        os.E.BADF => error.FileDescriptorInvalid,
                        os.E.CANCELED => error.Canceled,
                        os.E.DQUOT => error.DiskQuota,
                        os.E.IO => error.InputOutput,
                        os.E.NOSPC => error.NoSpaceLeft,
                        else => |errno| os.unexpectedErrno(errno),
                    } else assert(completion.result == 0);
                    completion.callback(completion.context, completion, &result);
                },
                .connect => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.ACCES => error.AccessDenied,
                        os.E.ADDRINUSE => error.AddressInUse,
                        os.E.ADDRNOTAVAIL => error.AddressNotAvailable,
                        os.E.AFNOSUPPORT => error.AddressFamilyNotSupported,
                        os.E.AGAIN, os.E.INPROGRESS => error.Again,
                        os.E.ALREADY => error.OpenAlreadyInProgress,
                        os.E.BADF => error.FileDescriptorInvalid,
                        os.E.CANCELED => error.Canceled,
                        os.E.CONNREFUSED => error.ConnectionRefused,
                        os.E.CONNRESET => error.ConnectionResetByPeer,
                        os.E.FAULT => unreachable,
                        os.E.ISCONN => error.AlreadyConnected,
                        os.E.NETUNREACH => error.NetworkUnreachable,
                        os.E.NOENT => error.FileNotFound,
                        os.E.NOTSOCK => error.FileDescriptorNotASocket,
                        os.E.PERM => error.PermissionDenied,
                        os.E.PROTOTYPE => error.ProtocolNotSupported,
                        os.E.TIMEDOUT => error.ConnectionTimedOut,
                        else => |errno| os.unexpectedErrno(errno),
                    } else assert(completion.result == 0);
                    completion.callback(completion.context, completion, &result);
                },
                .fsync => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.BADF => error.FileDescriptorInvalid,
                        os.E.CANCELED => error.Canceled,
                        os.E.DQUOT => error.DiskQuota,
                        os.E.INVAL => error.ArgumentsInvalid,
                        os.E.IO => error.InputOutput,
                        os.E.NOSPC => error.NoSpaceLeft,
                        os.E.ROFS => error.ReadOnlyFileSystem,
                        else => |errno| os.unexpectedErrno(errno),
                    } else assert(completion.result == 0);
                    completion.callback(completion.context, completion, &result);
                },
                .link_timeout => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            // TODO: maybe we should enqueue the linked target completion
                            // just before this with linked field being set to true.
                            tigerbeetle_io_log.debug("Completion.complete 0x{x} op={s} got EINTR calling enqueue", .{ @ptrToInt(completion), @tagName(completion.operation) });
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.CANCELED => error.Canceled,
                        os.E.TIME => {}, // A success.
                        else => |errno| os.unexpectedErrno(errno),
                    } else unreachable;
                    completion.callback(completion.context, completion, &result);
                },
                .openat => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.ACCES => error.AccessDenied,
                        os.E.BADF => error.FileDescriptorInvalid,
                        os.E.BUSY => error.DeviceBusy,
                        os.E.CANCELED => error.Canceled,
                        os.E.EXIST => error.PathAlreadyExists,
                        os.E.FAULT => unreachable,
                        os.E.FBIG => error.FileTooBig,
                        os.E.INVAL => error.ArgumentsInvalid,
                        os.E.ISDIR => error.IsDir,
                        os.E.LOOP => error.SymLinkLoop,
                        os.E.MFILE => error.ProcessFdQuotaExceeded,
                        os.E.NAMETOOLONG => error.NameTooLong,
                        os.E.NFILE => error.SystemFdQuotaExceeded,
                        os.E.NODEV => error.NoDevice,
                        os.E.NOENT => error.FileNotFound,
                        os.E.NOMEM => error.SystemResources,
                        os.E.NOSPC => error.NoSpaceLeft,
                        os.E.NOTDIR => error.NotDir,
                        os.E.OPNOTSUPP => error.FileLocksNotSupported,
                        os.E.OVERFLOW => error.FileTooBig,
                        os.E.PERM => error.AccessDenied,
                        os.E.AGAIN => error.Again,
                        else => |errno| os.unexpectedErrno(errno),
                    } else @intCast(os.fd_t, completion.result);
                    completion.callback(completion.context, completion, &result);
                },
                .read => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.AGAIN => error.Again,
                        os.E.BADF => error.NotOpenForReading,
                        os.E.CANCELED => error.Canceled,
                        os.E.CONNRESET => error.ConnectionResetByPeer,
                        os.E.FAULT => unreachable,
                        os.E.INVAL => error.Alignment,
                        os.E.IO => error.InputOutput,
                        os.E.ISDIR => error.IsDir,
                        os.E.NOBUFS => error.SystemResources,
                        os.E.NOMEM => error.SystemResources,
                        os.E.NXIO => error.Unseekable,
                        os.E.OVERFLOW => error.Unseekable,
                        os.E.SPIPE => error.Unseekable,
                        else => |errno| os.unexpectedErrno(errno),
                    } else @intCast(usize, completion.result);
                    completion.callback(completion.context, completion, &result);
                },
                .recv, .recvmsg => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.AGAIN => error.Again,
                        os.E.BADF => error.FileDescriptorInvalid,
                        os.E.CANCELED => error.Canceled,
                        os.E.CONNREFUSED => error.ConnectionRefused,
                        os.E.FAULT => unreachable,
                        os.E.INVAL => unreachable,
                        os.E.NOMEM => error.SystemResources,
                        os.E.NOTCONN => error.SocketNotConnected,
                        os.E.NOTSOCK => error.FileDescriptorNotASocket,
                        os.E.CONNRESET => error.ConnectionResetByPeer,
                        else => |errno| os.unexpectedErrno(errno),
                    } else @intCast(usize, completion.result);
                    completion.callback(completion.context, completion, &result);
                },
                .send, .sendmsg => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            tigerbeetle_io_log.debug("Completion.complete 0x{x} op={s} got EINTR calling enqueue", .{ @ptrToInt(completion), @tagName(completion.operation) });
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.ACCES => error.AccessDenied,
                        os.E.AGAIN => error.Again,
                        os.E.ALREADY => error.FastOpenAlreadyInProgress,
                        os.E.AFNOSUPPORT => error.AddressFamilyNotSupported,
                        os.E.BADF => error.FileDescriptorInvalid,
                        os.E.CANCELED => error.Canceled,
                        os.E.CONNRESET => error.ConnectionResetByPeer,
                        os.E.DESTADDRREQ => unreachable,
                        os.E.FAULT => unreachable,
                        os.E.INVAL => unreachable,
                        os.E.ISCONN => unreachable,
                        os.E.MSGSIZE => error.MessageTooBig,
                        os.E.NOBUFS => error.SystemResources,
                        os.E.NOMEM => error.SystemResources,
                        os.E.NOTCONN => error.SocketNotConnected,
                        os.E.NOTSOCK => error.FileDescriptorNotASocket,
                        os.E.OPNOTSUPP => error.OperationNotSupported,
                        os.E.PIPE => error.BrokenPipe,
                        else => |errno| os.unexpectedErrno(errno),
                    } else @intCast(usize, completion.result);
                    completion.callback(completion.context, completion, &result);
                },
                .timeout => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.CANCELED => error.Canceled,
                        os.E.TIME => {}, // A success.
                        else => |errno| os.unexpectedErrno(errno),
                    } else unreachable;
                    completion.callback(completion.context, completion, &result);
                },
                .timeout_remove => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.CANCELED => error.Canceled,
                        os.E.BUSY => error.AlreadyInProgress,
                        os.E.NOENT => error.NotFound,
                        else => |errno| os.unexpectedErrno(errno),
                    } else assert(completion.result == 0);
                    completion.callback(completion.context, completion, &result);
                },
                .write => {
                    const result = if (completion.result < 0) switch (completion.err()) {
                        os.E.INTR => {
                            completion.io.enqueue(completion);
                            return;
                        },
                        os.E.AGAIN => error.Again,
                        os.E.BADF => error.NotOpenForWriting,
                        os.E.CANCELED => error.Canceled,
                        os.E.DESTADDRREQ => error.NotConnected,
                        os.E.DQUOT => error.DiskQuota,
                        os.E.FAULT => unreachable,
                        os.E.FBIG => error.FileTooBig,
                        os.E.INVAL => error.Alignment,
                        os.E.IO => error.InputOutput,
                        os.E.NOSPC => error.NoSpaceLeft,
                        os.E.NXIO => error.Unseekable,
                        os.E.OVERFLOW => error.Unseekable,
                        os.E.PERM => error.AccessDenied,
                        os.E.PIPE => error.BrokenPipe,
                        os.E.SPIPE => error.Unseekable,
                        else => |errno| os.unexpectedErrno(errno),
                    } else @intCast(usize, completion.result);
                    completion.callback(completion.context, completion, &result);
                },
            }
        }
    };

    pub const LinkedCompletion = struct {
        main_completion: Completion = undefined,
        linked_completion: Completion = undefined,
        main_result: ?union(enum) {
            connect: ConnectError!void,
            recv: RecvError!usize,
            send: SendError!usize,
        } = null,
        linked_result: ?TimeoutError!void = null,
    };

    /// This union encodes the set of operations supported as well as their arguments.
    const Operation = union(enum) {
        accept: struct {
            socket: os.socket_t,
            address: os.sockaddr = undefined,
            address_size: os.socklen_t = @sizeOf(os.sockaddr),
            flags: u32,
        },
        cancel: struct {
            target_completion: *Completion,
        },
        close: struct {
            fd: os.fd_t,
        },
        connect: struct {
            socket: os.socket_t,
            address: std.net.Address,
        },
        fsync: struct {
            fd: os.fd_t,
            flags: u32,
        },
        link_timeout: struct {
            timespec: os.timespec,
        },
        openat: struct {
            fd: os.fd_t,
            path: [*:0]const u8,
            flags: u32,
            mode: os.mode_t,
        },
        read: struct {
            fd: os.fd_t,
            buffer: []u8,
            offset: u64,
        },
        recv: struct {
            socket: os.socket_t,
            buffer: []u8,
            flags: u32,
        },
        recvmsg: struct {
            socket: os.socket_t,
            msg: *os.msghdr,
            flags: u32,
        },
        send: struct {
            socket: os.socket_t,
            buffer: []const u8,
            flags: u32,
        },
        sendmsg: struct {
            socket: os.socket_t,
            msg: *const os.msghdr_const,
            flags: u32,
        },
        timeout: struct {
            timespec: os.timespec,
        },
        timeout_remove: struct {
            timeout_completion: *Completion,
        },
        write: struct {
            fd: os.fd_t,
            buffer: []const u8,
            offset: u64,
        },
    };

    pub const AcceptError = error{
        WouldBlock,
        FileDescriptorInvalid,
        ConnectionAborted,
        SocketNotListening,
        ProcessFdQuotaExceeded,
        SystemFdQuotaExceeded,
        SystemResources,
        FileDescriptorNotASocket,
        OperationNotSupported,
        PermissionDenied,
        ProtocolFailure,
        Canceled,
    } || os.UnexpectedError;

    pub fn accept(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: AcceptError!os.socket_t,
        ) void,
        completion: *Completion,
        socket: os.socket_t,
        flags: u32,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const AcceptError!os.socket_t, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .accept = .{
                    .socket = socket,
                    .address = undefined,
                    .address_size = @sizeOf(os.sockaddr),
                    .flags = flags,
                },
            },
        };
        self.enqueue(completion);
    }

    pub const CancelError = error{ AlreadyInProgress, NotFound } || os.UnexpectedError;

    pub fn cancel(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: CancelError!void,
        ) void,
        completion: *Completion,
        cancel_completion: *Completion,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const CancelError!void, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .cancel = .{
                    .target_completion = cancel_completion,
                },
            },
        };
        self.enqueue(completion);
    }

    pub const CancelTimeoutError = error{
        AlreadyInProgress,
        NotFound,
        Canceled,
    } || os.UnexpectedError;

    pub fn cancelTimeout(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: CancelTimeoutError!void,
        ) void,
        completion: *Completion,
        timeout_completion: *Completion,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const CancelTimeoutError!void, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .timeout_remove = .{
                    .timeout_completion = timeout_completion,
                },
            },
        };
        self.enqueue(completion);
    }

    pub const CloseError = error{
        FileDescriptorInvalid,
        DiskQuota,
        InputOutput,
        NoSpaceLeft,
        Canceled,
    } || os.UnexpectedError;

    pub fn close(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: CloseError!void,
        ) void,
        completion: *Completion,
        fd: os.fd_t,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const CloseError!void, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .close = .{ .fd = fd },
            },
        };
        self.enqueue(completion);
    }

    pub const ConnectError = error{
        AccessDenied,
        AddressInUse,
        AddressNotAvailable,
        AddressFamilyNotSupported,
        WouldBlock,
        OpenAlreadyInProgress,
        FileDescriptorInvalid,
        ConnectionRefused,
        AlreadyConnected,
        NetworkUnreachable,
        FileNotFound,
        FileDescriptorNotASocket,
        PermissionDenied,
        ProtocolNotSupported,
        ConnectionTimedOut,
        Canceled,
    } || os.UnexpectedError;

    pub fn connect(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: ConnectError!void,
        ) void,
        completion: *Completion,
        socket: os.socket_t,
        address: std.net.Address,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const ConnectError!void, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .connect = .{
                    .socket = socket,
                    .address = address,
                },
            },
        };
        self.enqueue(completion);
    }

    pub fn connectWithTimeout(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *LinkedCompletion,
            result: ConnectError!void,
        ) void,
        completion: *LinkedCompletion,
        socket: os.socket_t,
        address: std.net.Address,
        timeout_ns: u63,
    ) void {
        completion.main_completion = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    const linked_comp = @fieldParentPtr(LinkedCompletion, "main_completion", comp);
                    linked_comp.main_result = .{
                        .connect = @intToPtr(*const ConnectError!void, @ptrToInt(res)).*,
                    };
                    if (linked_comp.linked_result) |_| {
                        callback(
                            @intToPtr(Context, @ptrToInt(ctx)),
                            linked_comp,
                            linked_comp.main_result.?.connect,
                        );
                    }
                }
            }.wrapper,
            .operation = .{
                .connect = .{
                    .socket = socket,
                    .address = address,
                },
            },
            .linked = true,
        };
        completion.linked_completion = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    const linked_comp = @fieldParentPtr(LinkedCompletion, "linked_completion", comp);
                    linked_comp.linked_result = @intToPtr(*const TimeoutError!void, @ptrToInt(res)).*;
                    if (linked_comp.main_result) |main_result| {
                        callback(
                            @intToPtr(Context, @ptrToInt(ctx)),
                            linked_comp,
                            main_result.connect,
                        );
                    }
                }
            }.wrapper,
            .operation = .{
                .link_timeout = .{
                    .timespec = .{ .tv_sec = 0, .tv_nsec = timeout_ns },
                },
            },
        };
        completion.main_result = null;
        completion.linked_result = null;
        self.enqueueLinked(
            &completion.main_completion,
            &completion.linked_completion,
        );
    }

    pub const FsyncError = error{
        FileDescriptorInvalid,
        DiskQuota,
        ArgumentsInvalid,
        InputOutput,
        NoSpaceLeft,
        ReadOnlyFileSystem,
        Canceled,
    } || os.UnexpectedError;

    pub fn fsync(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: FsyncError!void,
        ) void,
        completion: *Completion,
        fd: os.fd_t,
        flags: u32,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const FsyncError!void, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .fsync = .{
                    .fd = fd,
                    .flags = flags,
                },
            },
        };
        self.enqueue(completion);
    }

    pub const OpenatError = error{
        AccessDenied,
        FileDescriptorInvalid,
        DeviceBusy,
        PathAlreadyExists,
        FileTooBig,
        ArgumentsInvalid,
        IsDir,
        SymLinkLoop,
        ProcessFdQuotaExceeded,
        NameTooLong,
        SystemFdQuotaExceeded,
        NoDevice,
        FileNotFound,
        SystemResources,
        NoSpaceLeft,
        NotDir,
        FileLocksNotSupported,
        WouldBlock,
        Canceled,
    } || os.UnexpectedError;

    pub fn openat(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: OpenatError!os.fd_t,
        ) void,
        completion: *Completion,
        fd: os.fd_t,
        path: [*:0]const u8,
        flags: u32,
        mode: os.mode_t,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const OpenatError!os.fd_t, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .openat = .{
                    .fd = fd,
                    .path = path,
                    .flags = flags,
                    .mode = mode,
                },
            },
        };
        self.enqueue(completion);
    }

    pub const ReadError = error{
        WouldBlock,
        NotOpenForReading,
        ConnectionResetByPeer,
        Alignment,
        InputOutput,
        IsDir,
        SystemResources,
        Unseekable,
        Canceled,
    } || os.UnexpectedError;

    pub fn read(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: ReadError!usize,
        ) void,
        completion: *Completion,
        fd: os.fd_t,
        buffer: []u8,
        offset: u64,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const ReadError!usize, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .read = .{
                    .fd = fd,
                    .buffer = buffer,
                    .offset = offset,
                },
            },
        };
        self.enqueue(completion);
    }

    pub const RecvError = error{
        WouldBlock,
        FileDescriptorInvalid,
        ConnectionRefused,
        SystemResources,
        SocketNotConnected,
        FileDescriptorNotASocket,
        Canceled,
    } || os.UnexpectedError;

    pub fn recv(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: RecvError!usize,
        ) void,
        completion: *Completion,
        socket: os.socket_t,
        buffer: []u8,
        flags: u32,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const RecvError!usize, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .recv = .{
                    .socket = socket,
                    .buffer = buffer,
                    .flags = flags,
                },
            },
        };
        self.enqueue(completion);
    }

    pub fn recvWithTimeout(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *LinkedCompletion,
            result: RecvError!usize,
        ) void,
        completion: *LinkedCompletion,
        socket: os.socket_t,
        buffer: []u8,
        recv_flags: u32,
        timeout_ns: u63,
    ) void {
        completion.main_completion = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    const linked_comp = @fieldParentPtr(LinkedCompletion, "main_completion", comp);
                    linked_comp.main_result = .{
                        .recv = @intToPtr(*const RecvError!usize, @ptrToInt(res)).*,
                    };
                    if (linked_comp.linked_result) |_| {
                        callback(
                            @intToPtr(Context, @ptrToInt(ctx)),
                            linked_comp,
                            linked_comp.main_result.?.recv,
                        );
                    }
                }
            }.wrapper,
            .operation = .{
                .recv = .{
                    .socket = socket,
                    .buffer = buffer,
                    .flags = recv_flags,
                },
            },
            .linked = true,
        };
        completion.linked_completion = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    const linked_comp = @fieldParentPtr(LinkedCompletion, "linked_completion", comp);
                    linked_comp.linked_result = @intToPtr(*const TimeoutError!void, @ptrToInt(res)).*;
                    if (linked_comp.main_result) |main_result| {
                        callback(
                            @intToPtr(Context, @ptrToInt(ctx)),
                            linked_comp,
                            main_result.recv,
                        );
                    }
                }
            }.wrapper,
            .operation = .{
                .link_timeout = .{
                    .timespec = .{ .tv_sec = 0, .tv_nsec = timeout_ns },
                },
            },
        };
        completion.main_result = null;
        completion.linked_result = null;
        self.enqueueLinked(
            &completion.main_completion,
            &completion.linked_completion,
        );
    }

    pub const SendError = error{
        AccessDenied,
        WouldBlock,
        FastOpenAlreadyInProgress,
        AddressFamilyNotSupported,
        FileDescriptorInvalid,
        ConnectionResetByPeer,
        MessageTooBig,
        SystemResources,
        SocketNotConnected,
        FileDescriptorNotASocket,
        OperationNotSupported,
        BrokenPipe,
        Canceled,
    } || os.UnexpectedError;

    pub fn send(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: SendError!usize,
        ) void,
        completion: *Completion,
        socket: os.socket_t,
        buffer: []const u8,
        flags: u32,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const SendError!usize, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .send = .{
                    .socket = socket,
                    .buffer = buffer,
                    .flags = flags,
                },
            },
        };
        self.enqueue(completion);
    }

    pub fn sendWithTimeout(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *LinkedCompletion,
            result: SendError!usize,
        ) void,
        completion: *LinkedCompletion,
        socket: os.socket_t,
        buffer: []const u8,
        send_flags: u32,
        timeout_ns: u63,
    ) void {
        completion.main_completion = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    const linked_comp = @fieldParentPtr(LinkedCompletion, "main_completion", comp);
                    linked_comp.main_result = .{
                        .send = @intToPtr(*const SendError!usize, @ptrToInt(res)).*,
                    };
                    if (linked_comp.linked_result) |_| {
                        callback(
                            @intToPtr(Context, @ptrToInt(ctx)),
                            linked_comp,
                            linked_comp.main_result.?.send,
                        );
                    }
                }
            }.wrapper,
            .operation = .{
                .send = .{
                    .socket = socket,
                    .buffer = buffer,
                    .flags = send_flags,
                },
            },
            .linked = true,
        };
        completion.linked_completion = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    const linked_comp = @fieldParentPtr(LinkedCompletion, "linked_completion", comp);
                    linked_comp.linked_result = @intToPtr(*const TimeoutError!void, @ptrToInt(res)).*;
                    if (linked_comp.main_result) |main_result| {
                        callback(
                            @intToPtr(Context, @ptrToInt(ctx)),
                            linked_comp,
                            main_result.send,
                        );
                    }
                }
            }.wrapper,
            .operation = .{
                .link_timeout = .{
                    .timespec = .{ .tv_sec = 0, .tv_nsec = timeout_ns },
                },
            },
        };
        completion.main_result = null;
        completion.linked_result = null;
        self.enqueueLinked(
            &completion.main_completion,
            &completion.linked_completion,
        );
    }

    pub const TimeoutError = error{Canceled} || os.UnexpectedError;

    pub fn timeout(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: TimeoutError!void,
        ) void,
        completion: *Completion,
        nanoseconds: u63,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const TimeoutError!void, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .timeout = .{
                    .timespec = .{ .tv_sec = 0, .tv_nsec = nanoseconds },
                },
            },
        };
        self.enqueue(completion);
    }

    pub const WriteError = error{
        WouldBlock,
        NotOpenForWriting,
        NotConnected,
        DiskQuota,
        FileTooBig,
        Alignment,
        InputOutput,
        NoSpaceLeft,
        Unseekable,
        AccessDenied,
        BrokenPipe,
        Canceled,
    } || os.UnexpectedError;

    pub fn write(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: WriteError!usize,
        ) void,
        completion: *Completion,
        fd: os.fd_t,
        buffer: []const u8,
        offset: u64,
    ) void {
        completion.* = .{
            .io = self,
            .context = context,
            .callback = struct {
                fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                    callback(
                        @intToPtr(Context, @ptrToInt(ctx)),
                        comp,
                        @intToPtr(*const WriteError!usize, @ptrToInt(res)).*,
                    );
                }
            }.wrapper,
            .operation = .{
                .write = .{
                    .fd = fd,
                    .buffer = buffer,
                    .offset = offset,
                },
            },
        };
        self.enqueue(completion);
    }
};
