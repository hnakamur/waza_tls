const std = @import("std");
const os = std.os;

const FIFO = @import("fifo.zig").FIFO;

pub const IO = struct {
    /// Operations not yet submitted to the kernel and waiting on available space in the
    /// submission queue.
    unqueued: FIFO(Completion) = .{},

    /// Completions that are ready to have their callbacks run.
    completed: FIFO(Completion) = .{},

    pub fn init(entries: u12, flags: u32) !IO {
        std.debug.print("mock IO init, entries={}, flags={}\n", .{entries, flags});
        return IO{};
    }

    pub fn deinit(self: *IO) void {
        std.debug.print("mock IO deinit\n", .{});
    }

    /// Pass all queued submissions to the kernel and peek for completions.
    pub fn tick(self: *IO) !void {
    }
    
    /// This struct holds the data needed for a single io_uring operation
    pub const Completion = struct {
        io: *IO,
        result: i32 = undefined,
        next: ?*Completion = null,
        operation: Operation,
        linked: bool = false,
        // This is one of the usecases for c_void outside of C code and as such c_void will
        // be replaced with anyopaque eventually: https://github.com/ziglang/zig/issues/323
        context: ?*c_void,
        callback: fn (context: ?*c_void, completion: *Completion, result: *const c_void) void,

        fn prep(completion: *Completion, sqe: *io_uring_sqe) void {
        }

        fn complete(completion: *Completion) void {
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
            timespec: os.__kernel_timespec,
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
        send: struct {
            socket: os.socket_t,
            buffer: []const u8,
            flags: u32,
        },
        timeout: struct {
            timespec: os.__kernel_timespec,
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
                fn wrapper(ctx: ?*c_void, comp: *Completion, res: *const c_void) void {
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
