const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const math = std.math;
const mem = std.mem;
const os = std.os;
const time = std.time;
const native_endian = builtin.cpu.arch.endian();
const BytesView = @import("parser/bytes.zig").BytesView;
const IO = @import("tigerbeetle-io").IO;

const http_log = std.log.scoped(.http);
// const http_log = @import("nop_log.zig").scoped(.http);

const recv_flags = if (builtin.os.tag == .linux) os.MSG.NOSIGNAL else 0;
const send_flags = if (builtin.os.tag == .linux) os.MSG.NOSIGNAL else 0;

pub fn Client(comptime Context: type) type {
    return struct {
        const Self = @This();

        pub const Config = struct {
            connect_timeout_ns: u63 = 5 * time.ns_per_s,
            send_timeout_ns: u63 = 5 * time.ns_per_s,
            recv_timeout_ns: u63 = 5 * time.ns_per_s,
            response_buf_len: usize = 1024,

            fn validate(self: Config) !void {
                assert(self.connect_timeout_ns > 0);
                assert(self.send_timeout_ns > 0);
                assert(self.recv_timeout_ns > 0);
                assert(self.response_buf_len > 0);
            }
        };

        const Completion = struct {
            linked_completion: IO.LinkedCompletion = undefined,
            buffer: []u8 = undefined,
            callback: fn (ctx: ?*anyopaque, comp: *Completion, result: *const anyopaque) void = undefined,
        };

        allocator: mem.Allocator,
        io: *IO,
        context: *Context,
        config: *const Config,
        socket: os.socket_t = undefined,
        response_buf: []u8 = undefined,
        done: bool = false,

        pub fn init(allocator: mem.Allocator, io: *IO, context: *Context, config: *const Config) !Self {
            try config.validate();
            const response_buf = try allocator.alloc(u8, config.response_buf_len);
            return Self{
                .allocator = allocator,
                .io = io,
                .context = context,
                .config = config,
                .response_buf = response_buf,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.response_buf);
        }

        pub fn connect(
            self: *Self,
            addr: std.net.Address,
            comptime callback: fn (
                context: *Context,
                completion: *Completion,
                result: IO.ConnectError!void,
            ) void,
            completion: *Completion,
        ) !void {
            self.socket = try os.socket(addr.any.family, os.SOCK.DGRAM, 0);
            http_log.debug("dns.Client.connect socket={}", .{self.socket});

            completion.* = .{
                .callback = struct {
                    fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            comp,
                            @intToPtr(*const IO.ConnectError!void, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
            };
            http_log.debug("dns.Client.connect main_completion=0x{x}, linked_completion=0x{x}", .{
                @ptrToInt(&completion.linked_completion.main_completion),
                @ptrToInt(&completion.linked_completion.linked_completion),
            });
            self.io.connectWithTimeout(
                *Self,
                self,
                connectCallback,
                &completion.linked_completion,
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
            http_log.debug("dns.Client.connectCallback result={}, client=0x{x}", .{ result, @ptrToInt(self) });
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            comp.callback(self.context, comp, &result);
            if (result) |_| {} else |err| {
                http_log.debug("Client.connectCallback before calling close, err={s}", .{@errorName(err)});
                self.close();
            }
        }

        pub fn sendQuery(
            self: *Self,
            query: *const QueryMessage,
            comptime callback: fn (
                context: *Context,
                completion: *Completion,
                result: anyerror!usize,
            ) void,
            completion: *Completion,
        ) void {
            const query_len = query.calcEncodedLen() catch |err| {
                const err_result: anyerror!usize = err;
                callback(self.context, completion, err_result);
                return;
            };
            var buffer = self.allocator.alloc(u8, query_len) catch |err| {
                const err_result: anyerror!usize = err;
                callback(self.context, completion, err_result);
                return;
            };
            if (query.encode(buffer)) |_| {} else |err| {
                const err_result: anyerror!usize = err;
                callback(self.context, completion, err_result);
                return;
            }
            completion.* = .{
                .callback = struct {
                    fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            comp,
                            @intToPtr(*anyerror!usize, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
                .buffer = buffer,
            };
            self.io.sendWithTimeout(
                *Self,
                self,
                sendQueryCallback,
                &completion.linked_completion,
                self.socket,
                buffer,
                send_flags,
                self.config.send_timeout_ns,
            );
        }
        fn sendQueryCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.SendError!usize,
        ) void {
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            if (result) |sent| {
                const buf = comp.buffer;
                if (sent < buf.len) {
                    http_log.info("dns.Client.sendQueryCallback, sent={} < buf.len={}, timeout_result={}", .{
                        sent,
                        buf.len,
                        linked_completion.linked_result,
                    });
                    self.allocator.free(comp.buffer);
                    const err_result: anyerror!usize = error.ShortSend;
                    comp.callback(self.context, comp, &err_result);
                    return;
                }

                self.allocator.free(comp.buffer);
                const ok_result: anyerror!usize = sent;
                comp.callback(self.context, comp, &ok_result);
            } else |err| {
                self.allocator.free(comp.buffer);
                const err_result: anyerror!usize = err;
                comp.callback(self.context, comp, &err_result);
                self.close();
            }
        }

        pub fn recvResponse(
            self: *Self,
            comptime callback: fn (
                context: *Context,
                completion: *Completion,
                result: anyerror!usize,
            ) void,
            completion: *Completion,
        ) void {
            completion.* = .{
                .callback = struct {
                    fn wrapper(ctx: ?*anyopaque, comp: *Completion, res: *const anyopaque) void {
                        callback(
                            @intToPtr(*Context, @ptrToInt(ctx)),
                            comp,
                            @intToPtr(*const anyerror!usize, @ptrToInt(res)).*,
                        );
                    }
                }.wrapper,
            };

            http_log.debug(
                "dns.Client.recvResponse socket={}, self.response_buf.len={}",
                .{ self.socket, self.response_buf.len },
            );
            self.io.recvWithTimeout(
                *Self,
                self,
                recvResponseWithTimeoutCallback,
                &completion.linked_completion,
                self.socket,
                self.response_buf,
                recv_flags,
                self.config.recv_timeout_ns,
            );
            http_log.debug("dns.Client.recvResponse exit", .{});
        }
        fn recvResponseCallback(
            self: *Self,
            main_completion: *IO.Completion,
            result: IO.RecvError!usize,
        ) void {
            http_log.debug("dns.Client.recvResponseCallback result={}", .{result});
            const linked_completion = @fieldParentPtr(IO.LinkedCompletion, "main_completion", main_completion);
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            if (result) |received| {
                const ok_result: anyerror!usize = received;
                comp.callback(self.context, comp, &ok_result);
            } else |err| {
                const err_result: anyerror!usize = err;
                comp.callback(self.context, comp, &err_result);
                self.close();
            }
        }
        fn recvResponseWithTimeoutCallback(
            self: *Self,
            linked_completion: *IO.LinkedCompletion,
            result: IO.RecvError!usize,
        ) void {
            http_log.debug("dns.Client.recvResponseCallback result={}", .{result});
            const comp = @fieldParentPtr(Completion, "linked_completion", linked_completion);
            if (result) |received| {
                const ok_result: anyerror!usize = received;
                comp.callback(self.context, comp, &ok_result);
            } else |err| {
                const err_result: anyerror!usize = err;
                comp.callback(self.context, comp, &err_result);
                self.close();
            }
        }

        pub fn close(self: *Self) void {
            http_log.debug("dns.Client.close start. self=0x{x}", .{@ptrToInt(self)});
            os.closeSocket(self.socket);
            self.done = true;
            http_log.debug("dns.Client.close exit.", .{});
        }
    };
}

const qtype_len = @sizeOf(u16);
const qclass_len = @sizeOf(u16);

pub const QueryMessage = struct {
    header: Header,
    question: Question,

    pub fn calcEncodedLen(self: *const QueryMessage) !usize {
        return header_len + try calcNameEncodedLen(self.question.name) + qtype_len + qclass_len;
    }

    pub fn encode(self: *const QueryMessage, dest: []u8) !usize {
        self.header.encode(dest[0..header_len]);
        const name_len = try encodeName(self.question.name, dest[header_len..]);
        const qtype_pos = header_len + name_len;
        const qclass_pos = qtype_pos + qtype_len;
        const qclass_end_pos = qclass_pos + qclass_len;
        mem.writeIntBig(u16, dest[qtype_pos..][0..2], @enumToInt(self.question.qtype));
        mem.writeIntBig(u16, dest[qclass_pos..][0..2], @enumToInt(self.question.qclass));
        return qclass_end_pos;
    }
};

pub const ResponseMessage = struct {
    header: Header,
    question: Question,
    answer: Answer,

    pub fn decode(allocator: mem.Allocator, input: *BytesView) !ResponseMessage {
        try input.ensureLen(header_len);
        const header = Header.decode(input.getBytes(header_len)[0..header_len]);
        input.advance(header_len);

        const question = try Question.decode(allocator, input);
        const answer = try Answer.decode(allocator, input, header.ancount);
        return ResponseMessage{
            .header = header,
            .question = question,
            .answer = answer,
        };
    }

    pub fn deinit(self: *ResponseMessage, allocator: mem.Allocator) void {
        self.question.deinit(allocator);
        self.answer.deinit(allocator);
    }
};

const header_len: usize = 12;

pub const Header = packed struct {
    id: u16,

    qr: Qr = .query,
    opcode: Opcode = .query,
    // authoritative
    aa: u1 = 0,
    // truncated
    tc: u1 = 0,
    // recursion desired
    rd: u1 = 1,
    // recursion available
    ra: u1 = 0,
    // zero (reserved for future use)
    z: u3 = 0,

    rcode: Rcode = .no_error,

    qdcount: u16 = 1,
    ancount: u16 = 0,
    nscount: u16 = 0,
    arcount: u16 = 0,

    pub fn decode(bytes: *const [header_len]u8) Header {
        return .{
            .id = @as(u16, bytes[0]) << 8 | @as(u16, bytes[1]),
            .qr = @intToEnum(Qr, @truncate(u1, bytes[2] >> 7)),
            .opcode = @intToEnum(Opcode, @truncate(u4, bytes[2] << 1 >> 4)),
            .aa = @truncate(u1, bytes[2] << 5 >> 7),
            .tc = @truncate(u1, bytes[2] << 6 >> 7),
            .rd = @truncate(u1, bytes[2] << 7 >> 7),
            .ra = @truncate(u1, bytes[3] >> 7),
            .z = @truncate(u3, bytes[3] << 1 >> 4),
            .rcode = @intToEnum(Rcode, @truncate(u4, bytes[3] << 4 >> 4)),
            .qdcount = @as(u16, bytes[4]) << 8 | @as(u16, bytes[5]),
            .ancount = @as(u16, bytes[6]) << 8 | @as(u16, bytes[7]),
            .nscount = @as(u16, bytes[8]) << 8 | @as(u16, bytes[9]),
            .arcount = @as(u16, bytes[10]) << 8 | @as(u16, bytes[11]),
        };
    }

    pub fn encode(self: *const Header, dest: *[header_len]u8) void {
        dest[0] = @truncate(u8, self.id >> 8);
        dest[1] = @truncate(u8, self.id);

        dest[2] = @as(u8, @enumToInt(self.qr)) << 7 |
            @as(u8, @enumToInt(self.opcode)) << 3 |
            @as(u8, self.aa) << 2 |
            @as(u8, self.tc) << 1 |
            @as(u8, self.rd);
        dest[3] = @as(u8, self.ra) << 7 |
            @as(u8, self.z) << 4 |
            @as(u8, @enumToInt(self.rcode));

        dest[4] = @truncate(u8, self.qdcount >> 8);
        dest[5] = @truncate(u8, self.qdcount);

        dest[6] = @truncate(u8, self.ancount >> 8);
        dest[7] = @truncate(u8, self.ancount);

        dest[8] = @truncate(u8, self.nscount >> 8);
        dest[9] = @truncate(u8, self.nscount);

        dest[10] = @truncate(u8, self.arcount >> 8);
        dest[11] = @truncate(u8, self.arcount);
    }
};

const Type = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    TXT = 16,
    AAAA = 28,
    _,
};

const QType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    TXT = 16,
    AAAA = 28,
    @"*" = 255,
    _,
};

const Class = enum(u16) {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    _,
};

const QClass = enum(u16) {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    @"*" = 255,
    _,
};

const Qr = enum(u1) {
    query = 0,
    response = 1,
};

const Opcode = enum(u4) {
    query = 0,
    iquery = 1,
    status = 2,
    notify = 4,
    update = 5,
    _,
};

const Rcode = enum(u4) {
    no_error = 0,
    format_error,
    server_failure,
    name_error,
    not_implemented,
    refused,
    _,
};

pub const Question = struct {
    name: []const u8,
    qtype: QType,
    qclass: QClass = QClass.IN,

    pub fn decode(allocator: mem.Allocator, input: *BytesView) !Question {
        const name = try decodeDomainName(allocator, input);
        try input.ensureLen(qtype_len + qclass_len);
        const qtype = @intToEnum(
            QType,
            mem.readIntBig(u16, input.getBytes(qtype_len)[0..qtype_len]),
        );
        const qclass = @intToEnum(
            QClass,
            mem.readIntBig(u16, input.getBytesPos(qtype_len, qclass_len)[0..qclass_len]),
        );
        input.advance(qtype_len + qclass_len);
        return Question{
            .name = name,
            .qtype = qtype,
            .qclass = qclass,
        };
    }

    pub fn deinit(self: *const Question, allocator: mem.Allocator) void {
        allocator.free(self.name);
    }

    pub fn encode(self: *const Question, dest: []u8) !usize {
        var pos = try encodeName(self.name, dest);

        dest[pos] = @truncate(u8, @enumToInt(self.qtype) >> 8);
        dest[pos + 1] = @truncate(u8, @enumToInt(self.qtype));

        dest[pos + 2] = @truncate(u8, @enumToInt(self.qclass) >> 8);
        dest[pos + 3] = @truncate(u8, @enumToInt(self.qclass));

        return pos + 4;
    }

    pub fn format(
        self: *const Question,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try out_stream.print(
            "Question{{ .name = \"{s}\", .qtype = {}, .qclass = {} }}",
            .{ self.name, self.qtype, self.qclass },
        );
    }
};

pub const Answer = struct {
    records: std.ArrayListUnmanaged(Rr),

    pub fn decode(allocator: mem.Allocator, input: *BytesView, rr_count: usize) !Answer {
        var records = try std.ArrayListUnmanaged(Rr).initCapacity(allocator, rr_count);
        var i: usize = 0;
        while (i < rr_count) : (i += 1) {
            const rr = try Rr.decode(allocator, input);
            try records.append(allocator, rr);
        }
        return Answer{ .records = records };
    }

    pub fn deinit(self: *Answer, allocator: mem.Allocator) void {
        for (self.records.items) |*record| {
            record.deinit(allocator);
        }
        self.records.deinit(allocator);
    }

    pub fn format(
        self: *const Answer,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try out_stream.writeAll("[");
        for (self.records.items) |*record, i| {
            if (i > 0) {
                try out_stream.writeAll(", ");
            }
            try std.fmt.format(out_stream, "{}", .{record});
        }
        try out_stream.writeAll("]");
    }
};

pub const Rr = struct {
    name: []const u8,
    rr_type: Type,
    class: Class,
    ttl: u32,
    rd_length: u16,
    rdata: Rdata,

    pub fn decode(allocator: mem.Allocator, input: *BytesView) !Rr {
        const name = try decodeDomainName(allocator, input);
        const type_len = @sizeOf(Type);
        const class_len = @sizeOf(Class);
        const ttl_len = @sizeOf(u32);
        const rd_length_len = @sizeOf(u16);
        const header_rest_len = type_len + class_len + ttl_len + rd_length_len;
        try input.ensureLen(header_rest_len);
        const rr_type = @intToEnum(
            Type,
            mem.readIntBig(u16, input.getBytes(type_len)[0..2]),
        );
        const class = @intToEnum(
            Class,
            mem.readIntBig(u16, input.getBytesPos(type_len, class_len)[0..2]),
        );
        const ttl = mem.readIntBig(u32, input.getBytesPos(type_len + class_len, ttl_len)[0..4]);
        const rd_length = mem.readIntBig(
            u16,
            input.getBytesPos(type_len + class_len + ttl_len, rd_length_len)[0..2],
        );
        input.advance(header_rest_len);

        const rdata = try Rdata.decode(allocator, input, rr_type, rd_length);
        return Rr{
            .name = name,
            .rr_type = rr_type,
            .class = class,
            .ttl = ttl,
            .rd_length = rd_length,
            .rdata = rdata,
        };
    }

    pub fn deinit(self: *const Rr, allocator: mem.Allocator) void {
        allocator.free(self.name);
        self.rdata.deinit(allocator);
    }

    pub fn format(
        self: *const Rr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try out_stream.print(
            "Rr{{ .name = \"{s}\", .rr_type = {}, .class = {}, .ttl = {}, .rd_length = {}, .rdata = {} }}",
            .{ self.name, self.rr_type, self.class, self.ttl, self.rd_length, self.rdata },
        );
    }
};

const ipv4_addr_len = 4;

const Ip4Addr = struct {
    // network order
    bytes: [ipv4_addr_len]u8,

    pub fn format(
        self: *const Ip4Addr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        const bytes: []const u8 = &self.bytes;
        try std.fmt.format(out_stream, "{}.{}.{}.{}", .{
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
        });
    }
};

const ipv6_addr_len = 16;

const Ip6Addr = struct {
    // network order
    bytes: [ipv6_addr_len]u8,

    pub fn format(
        self: *const Ip6Addr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        if (mem.eql(u8, &self.bytes, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
            try std.fmt.format(out_stream, "::ffff:{}.{}.{}.{}", .{
                self.bytes[12],
                self.bytes[13],
                self.bytes[14],
                self.bytes[15],
            });
            return;
        }
        const big_endian_parts = @ptrCast(*align(1) const [8]u16, &self.bytes);
        const native_endian_parts = switch (native_endian) {
            .Big => big_endian_parts.*,
            .Little => blk: {
                var buf: [8]u16 = undefined;
                for (big_endian_parts) |part, i| {
                    buf[i] = mem.bigToNative(u16, part);
                }
                break :blk buf;
            },
        };
        var i: usize = 0;
        var abbrv = false;
        while (i < native_endian_parts.len) : (i += 1) {
            if (native_endian_parts[i] == 0) {
                if (!abbrv) {
                    try out_stream.writeAll(if (i == 0) "::" else ":");
                    abbrv = true;
                }
                continue;
            }
            try std.fmt.format(out_stream, "{x}", .{native_endian_parts[i]});
            if (i != native_endian_parts.len - 1) {
                try out_stream.writeAll(":");
            }
        }
    }
};

pub const Rdata = union(Type) {
    A: Ip4Addr,
    NS: []const u8,
    CNAME: []const u8,
    TXT: []const u8,
    AAAA: Ip6Addr,

    pub fn decode(allocator: mem.Allocator, input: *BytesView, rr_type: Type, rd_length: u16) !Rdata {
        try input.ensureLen(rd_length);
        switch (rr_type) {
            .A => {
                if (rd_length != ipv4_addr_len) return error.InvalidRdLength;
                const bytes = input.getBytes(ipv4_addr_len)[0..ipv4_addr_len].*;
                input.advance(ipv4_addr_len);
                return Rdata{ .A = Ip4Addr{ .bytes = bytes } };
            },
            .CNAME => {
                const domain = try decodeDomainName(allocator, input);
                return Rdata{ .CNAME = domain };
            },
            .TXT => {
                const length: usize = input.peekByte().?;
                input.advance(1);
                if (length != rd_length - 1) return error.InvalidRdata;
                const txt = try allocator.dupe(u8, input.getBytes(length));
                input.advance(length);
                return Rdata{ .TXT = txt };
            },
            .NS => {
                const domain = try decodeDomainName(allocator, input);
                return Rdata{ .NS = domain };
            },
            .AAAA => {
                if (rd_length != ipv6_addr_len) return error.InvalidRdLength;
                const bytes = input.getBytes(ipv6_addr_len)[0..ipv6_addr_len].*;
                input.advance(ipv6_addr_len);
                return Rdata{ .AAAA = Ip6Addr{ .bytes = bytes } };
            },
            else => return error.UnsupportedRdType,
        }
    }

    pub fn deinit(self: *const Rdata, allocator: mem.Allocator) void {
        switch (self.*) {
            Type.CNAME, Type.NS, Type.TXT => |str| allocator.free(str),
            else => {},
        }
    }

    pub fn format(
        self: *const Rdata,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try out_stream.writeAll("Rdata{ ");
        switch (self.*) {
            Type.A => |*a| try out_stream.print(".A = {}", .{a}),
            Type.NS => |n| try out_stream.print(".NS = {s}", .{n}),
            Type.CNAME => |n| try out_stream.print(".CNAME = {s}", .{n}),
            Type.TXT => |t| try out_stream.print(".TXT = \"{s}\"", .{t}),
            Type.AAAA => |*a| try out_stream.print(".AAAA = {}", .{a}),
            // else => {},
        }
        try out_stream.writeAll(" }");
    }
};

// returned slice must be freed after use.
fn decodeDomainName(allocator: mem.Allocator, input: *BytesView) ![]u8 {
    const decoded_len = try calcLabelsDecodedLen(input.bytes, input.pos);
    var dest = try allocator.alloc(u8, decoded_len);
    _ = try decodeLabels(input.bytes, input.pos, dest);
    const end_pos = try getLabelsEndPos(input.bytes, input.pos);
    input.advance(end_pos - input.pos);
    return dest;
}

pub const name_max_len: usize = 63;
pub const name_max_encoded_len: usize = name_max_len + 2;

fn calcNameEncodedLen(name: []const u8) !usize {
    if (name.len > name_max_len) {
        return error.InvalidName;
    }
    var dest_pos: usize = 0;
    var start: usize = 0;
    while (true) {
        const pos = mem.indexOfScalarPos(u8, name, start, '.');
        const end = pos orelse name.len;
        var label_len: usize = end - start;
        dest_pos += 1 + label_len;

        if (pos) |p| {
            start = p + 1;
        } else {
            return dest_pos + 1;
        }
    }
}

const offset_mask = 0xC0;

fn calcLabelsDecodedLen(answer: []const u8, start_pos: usize) !usize {
    var i: usize = start_pos;
    var min_pos: usize = start_pos;
    var label_len: usize = 0;
    var dest_pos: usize = 0;
    while (i < answer.len) {
        label_len = answer[i];
        std.log.debug("i={}, answer[i]=0x{x}", .{ i, label_len });
        if (label_len == 0) {
            return dest_pos;
        }
        if (label_len & offset_mask == offset_mask) {
            std.log.debug("found pointer, answer[i]&0x3F={}, answer[i+1]=0x{x}", .{ label_len & 0x3F, answer[i + 1] });
            i = (label_len & @bitReverse(u8, offset_mask)) << 8 | answer[i + 1];
            if (i >= min_pos) {
                return error.InvalidName;
            }
            min_pos = i;
            std.log.debug("pointer offset={}", .{i});
        } else {
            if (dest_pos > 0) {
                dest_pos += 1;
                std.log.debug("add 1 for dot, dest_pos={}", .{dest_pos});
            }
            dest_pos += label_len;
            std.log.debug("add label_len={}, dest_pos={}", .{ label_len, dest_pos });
            i += 1 + label_len;
        }
    }
    return error.InvalidName;
}

fn decodeLabels(answer: []const u8, start_pos: usize, dest: []u8) !usize {
    var i: usize = start_pos;
    var min_pos: usize = start_pos;
    var label_len: usize = 0;
    var dest_pos: usize = 0;
    while (i < answer.len) {
        label_len = answer[i];
        std.log.debug("i={}, answer[i]=0x{x}", .{ i, label_len });
        if (label_len == 0) {
            return dest_pos;
        }
        if (label_len & offset_mask == offset_mask) {
            std.log.debug("found pointer, answer[i]&0x3F={}, answer[i+1]=0x{x}", .{ label_len & 0x3F, answer[i + 1] });
            i = (label_len & @bitReverse(u8, offset_mask)) << 8 | answer[i + 1];
            if (i >= min_pos) {
                return error.InvalidName;
            }
            min_pos = i;
            std.log.debug("pointer offset={}", .{i});
        } else {
            if (dest_pos > 0) {
                dest[dest_pos] = '.';
                dest_pos += 1;
                std.log.debug("add 1 for dot, dest_pos={}", .{dest_pos});
            }
            i += 1;
            mem.copy(u8, dest[dest_pos..], answer[i .. i + label_len]);
            dest_pos += label_len;
            std.log.debug("add label_len={}, dest_pos={}", .{ label_len, dest_pos });
            i += label_len;
        }
    }
    return error.InvalidName;
}

fn getLabelsEndPos(data: []const u8, start_pos: usize) !usize {
    var i: usize = start_pos;
    var label_len: usize = 0;
    while (i < data.len) {
        label_len = data[i];
        if (label_len == 0) {
            return i + 1;
        }
        if (label_len & offset_mask == offset_mask) {
            return i + 2;
        }
        i += 1 + label_len;
    }
    return error.InvalidName;
}

fn encodeName(name: []const u8, dest: []u8) !usize {
    if (name.len > name_max_len) {
        return error.InvalidName;
    }
    var dest_pos: usize = 0;
    var start: usize = 0;
    while (true) {
        const pos = mem.indexOfScalarPos(u8, name, start, '.');
        const end = pos orelse name.len;
        var label_len: usize = end - start;

        dest[dest_pos] = @truncate(u8, label_len);
        mem.copy(u8, dest[dest_pos + 1 ..], name[start..end]);
        dest_pos += 1 + label_len;

        if (pos) |p| {
            start = p + 1;
        } else {
            dest[dest_pos] = '\x00';
            return dest_pos + 1;
        }
    }
}

test "dns.Response/A" {
    const allocator = testing.allocator;

    // example.com A IN 93.184.216.34
    const data = "\xab\xcd\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00" ++
        "\x00\x01\x00\x01" ++
        "\xc0\x0c" ++
        "\x00\x01\x00\x01" ++
        "\x00\x00\x49\xea" ++
        "\x00\x04" ++
        "\x5d\xb8\xd8\x22";

    var input = BytesView.init(data, true);
    var resp: ResponseMessage = try ResponseMessage.decode(allocator, &input);
    defer resp.deinit(allocator);

    std.debug.print("response={}", .{resp});
}

test "dns.Response/NS" {
    const allocator = testing.allocator;

    // $ dig +short -t ns example.com
    // a.iana-servers.net.
    // b.iana-servers.net.

    const data = "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00" ++
        "\x00\x02" ++
        "\x00\x01" ++
        "\xc0\x0c" ++
        "\x00\x02\x00\x01" ++
        "\x00\x00\x4e\x83" ++
        "\x00\x14" ++
        "\x01\x61\x0c\x69\x61\x6e\x61\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74\x00" ++
        "\xc0\x0c\x00\x02\x00\x01\x00\x00\x4e\x83" ++
        "\x00\x04\x01\x62\xc0\x2b";

    var input = BytesView.init(data, true);
    var resp: ResponseMessage = try ResponseMessage.decode(allocator, &input);
    defer resp.deinit(allocator);

    std.debug.print("response={}", .{resp});
}

test "dns.Response/CNAME" {
    const allocator = testing.allocator;

    // $ dig +short -t cname www.sakura.ad.jp
    // site-112800350116.gslb3.sakura.ne.jp.

    const data = "\xab\xcd\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x03\x77\x77\x77\x06\x73\x61\x6b\x75\x72\x61\x02\x61\x64\x02\x6a\x70\x00" ++
        "\x00\x05\x00\x01" ++
        "\xc0\x0c" ++
        "\x00\x05\x00\x01" ++
        "\x00\x00\x0b\x63" ++
        "\x00\x24" ++
        "\x11\x73\x69\x74\x65\x2d\x31\x31\x32\x38\x30\x30\x33\x35\x30\x31\x31\x36\x05\x67\x73\x6c\x62\x33\x06\x73\x61\x6b\x75\x72\x61\x02\x6e\x65\xc0\x1a";

    var input = BytesView.init(data, true);
    var resp: ResponseMessage = try ResponseMessage.decode(allocator, &input);
    defer resp.deinit(allocator);

    std.debug.print("response={}", .{resp});
}

test "dns.Response/AAAA" {
    const allocator = testing.allocator;

    // $ dig +short -t aaaa example.com
    // 2606:2800:220:1:248:1893:25c8:1946

    const data = "\xab\xcd\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00" ++
        "\x00\x1c\x00\x01\xc0\x0c" ++
        "\x00\x1c\x00\x01\x00\x00\x46\xbe" ++
        "\x00\x10" ++
        "\x26\x06\x28\x00\x02\x20\x00\x01\x02\x48\x18\x93\x25\xc8\x19\x46";

    var input = BytesView.init(data, true);
    var resp: ResponseMessage = try ResponseMessage.decode(allocator, &input);
    defer resp.deinit(allocator);

    std.debug.print("response={}", .{resp});
}

test "dns.calcLabelsDecodedLen" {
    // testing.log_level = .debug;

    const answer = "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x03\x77\x77\x77\x06\x73\x61\x6b\x75\x72\x61\x02\x61\x64\x02\x6a\x70\x00" ++
        "\x00\x01" ++
        "\x00\x01" ++
        "\xc0\x0c" ++
        "\x00\x05" ++
        "\x00\x01" ++
        "\x00\x00\x0c\x50" ++
        "\x00\x24" ++
        "\x11\x73\x69\x74\x65\x2d\x31\x31\x32\x38\x30\x30\x33\x35\x30\x31\x31\x36\x05\x67\x73\x6c\x62\x33\x06\x73\x61\x6b\x75\x72\x61\x02\x6e\x65\xc0\x1a" ++
        "\xc0\x2e" ++
        "\x00\x01" ++
        "\x00\x01" ++
        "\x00\x00\x00\x0a" ++
        "\x00\x04" ++
        "\xa3\x2b\x18\x46";
    const start_pos = 12 + 18 + 2 * 5 + 4 + 2;
    try testing.expectEqual(@as(anyerror!usize, 36), calcLabelsDecodedLen(answer, start_pos));
}

test "dns.calcLabelsDecodedLen loop" {
    // testing.log_level = .debug;

    const answer = "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x03\x77\x77\x77\x06\x73\x61\x6b\x75\x72\x61\x02\x61\x64\x02\x6a\x70\xc0\x0c";
    const start_pos = 12;
    try testing.expectError(error.InvalidName, calcLabelsDecodedLen(answer, start_pos));
}

test "dns.decodeLabels" {
    // testing.log_level = .debug;

    const answer = "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x03\x77\x77\x77\x06\x73\x61\x6b\x75\x72\x61\x02\x61\x64\x02\x6a\x70\x00" ++
        "\x00\x01" ++
        "\x00\x01" ++
        "\xc0\x0c" ++
        "\x00\x05" ++
        "\x00\x01" ++
        "\x00\x00\x0c\x50" ++
        "\x00\x24" ++
        "\x11\x73\x69\x74\x65\x2d\x31\x31\x32\x38\x30\x30\x33\x35\x30\x31\x31\x36\x05\x67\x73\x6c\x62\x33\x06\x73\x61\x6b\x75\x72\x61\x02\x6e\x65\xc0\x1a" ++
        "\xc0\x2e" ++
        "\x00\x01" ++
        "\x00\x01" ++
        "\x00\x00\x00\x0a" ++
        "\x00\x04" ++
        "\xa3\x2b\x18\x46";
    const start_pos = 12 + 18 + 2 * 5 + 4 + 2;
    var decoded_buf = [_]u8{0} ** 36;
    try testing.expectEqual(@as(usize, 36), try decodeLabels(answer, start_pos, &decoded_buf));
    try testing.expectEqualStrings("site-112800350116.gslb3.sakura.ne.jp", &decoded_buf);
}

test "dns.decodeLabelsLoop" {
    // testing.log_level = .debug;

    const answer = "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x03\x77\x77\x77\x06\x73\x61\x6b\x75\x72\x61\x02\x61\x64\x02\x6a\x70\xc0\x0c" ++
        "\x00\x01" ++
        "\x00\x01" ++
        "\xc0\x0c" ++
        "\x00\x05" ++
        "\x00\x01" ++
        "\x00\x00\x0c\x50" ++
        "\x00\x24" ++
        "\x11\x73\x69\x74\x65\x2d\x31\x31\x32\x38\x30\x30\x33\x35\x30\x31\x31\x36\x05\x67\x73\x6c\x62\x33\x06\x73\x61\x6b\x75\x72\x61\x02\x6e\x65\xc0\x1a" ++
        "\xc0\x2e" ++
        "\x00\x01" ++
        "\x00\x01" ++
        "\x00\x00\x00\x0a" ++
        "\x00\x04" ++
        "\xa3\x2b\x18\x46";
    const start_pos = 12 + 18 + 2 * 5 + 4 + 2;
    var decoded_buf = [_]u8{0} ** 36;
    try testing.expectError(error.InvalidName, decodeLabels(answer, start_pos, &decoded_buf));
}

const testing = std.testing;

test "dns.encodeQuestion" {
    var hdr = Header{
        .id = 0xABCD,
        .rd = 1,
        .qdcount = 1,
    };

    var question = Question{
        .name = "example.com",
        .qtype = .A,
        .qclass = .IN,
    };

    var encoded_buf = [_]u8{0} ** (@sizeOf(Header) + name_max_encoded_len + @sizeOf(u16) * 2);
    hdr.encode(encoded_buf[0..header_len]);
    const expected_header = "\xAB\xCD" ++ // ID
        "\x01\x00" ++ // Recursion
        "\x00\x01" ++ // QDCOUNT
        "\x00\x00" ++ // ANCOUNT
        "\x00\x00" ++ // NSCOUNT
        "\x00\x00"; // ARCOUNT
    try testing.expectEqualSlices(u8, expected_header, encoded_buf[0..header_len]);

    const expected_question =
        "\x07example\x03com\x00" ++ // NAME
        "\x00\x01" ++ // QTYPE = A
        "\x00\x01"; // QCLASS =IN
    const q_len = try question.encode(encoded_buf[header_len..]);
    try testing.expectEqualSlices(u8, expected_question, encoded_buf[header_len .. header_len + q_len]);
}

test "dns.send/recv" {
    const net = std.net;
    const linux = os.linux;
    const IO_Uring = linux.IO_Uring;

    var ring = IO_Uring.init(4, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const address = try net.Address.parseIp4("8.8.8.8", 53);
    const client = try os.socket(address.any.family, os.SOCK.DGRAM, 0);
    defer os.close(client);

    const connect = try ring.connect(0xcccccccc, client, &address.any, address.getOsSockLen());
    connect.flags |= linux.IOSQE_IO_LINK;

    const query = QueryMessage{
        .header = Header{ .id = 0xABCD },
        .question = Question{
            .name = "www.sakura.ad.jp",
            .qtype = .CNAME,
        },
    };

    const allocator = testing.allocator;
    const query_len = try query.calcEncodedLen();
    var query_buf = try allocator.alloc(u8, query_len);
    defer allocator.free(query_buf);
    _ = try query.encode(query_buf);
    _ = try ring.send(0xeeeeeeee, client, query_buf, 0);
    // send.flags |= linux.IOSQE_IO_LINK;

    var buffer_recv = [_]u8{0} ** 1024;
    _ = try ring.recv(0xffffffff, client, buffer_recv[0..], 0);
    const nr_wait = try ring.submit();

    var i: usize = 0;
    while (i < nr_wait) : (i += 1) {
        const cqe = try ring.copy_cqe();
        std.debug.print("i={}, cqe.user_data=0x{x}, res={}\n", .{ i, cqe.user_data, cqe.res });
        if (cqe.user_data == 0xffffffff and cqe.res > 0) {
            // std.debug.print("raw_answer", .{});
            // for (buffer_recv[0..@intCast(usize, cqe.res)]) |b| {
            //     std.debug.print("\\x{x:0>2}", .{b});
            // }
            // std.debug.print("\n", .{});

            var input = BytesView.init(buffer_recv[0..@intCast(usize, cqe.res)], true);
            var resp: ResponseMessage = try ResponseMessage.decode(allocator, &input);
            defer resp.deinit(allocator);
            std.debug.print("response={}\n", .{resp});
        }
    }
}

test "dns.Client" {
    testing.log_level = .debug;

    try struct {
        const Context = @This();
        const MyClient = Client(Context);

        allocator: mem.Allocator,
        client: MyClient = undefined,
        connect_completion: MyClient.Completion = undefined,
        send_completion: MyClient.Completion = undefined,
        recv_completion: MyClient.Completion = undefined,
        query: ?QueryMessage = null,
        response: ?ResponseMessage = null,

        fn deinit(self: *Context) void {
            self.client.deinit();
            if (self.response) |*r| r.deinit(self.allocator);
        }

        fn connectCallback(
            self: *Context,
            completion: *MyClient.Completion,
            result: IO.ConnectError!void,
        ) void {
            _ = completion;
            std.log.debug("Context.connectCallback start, result={}", .{result});
            if (result) |_| {
                self.query = QueryMessage{
                    .header = Header{ .id = 0xABCD },
                    .question = Question{
                        .name = "www.sakura.ad.jp",
                        .qtype = .A,
                    },
                };
                self.client.sendQuery(&self.query.?, sendQueryCallback, &self.send_completion);
            } else |err| {
                std.log.err("Context.connectCallback err={s}", .{@errorName(err)});
            }
        }

        fn sendQueryCallback(
            self: *Context,
            completion: *MyClient.Completion,
            result: anyerror!usize,
        ) void {
            _ = completion;
            if (result) |sent| {
                std.log.debug("Context.sendQueryCallback sent={}", .{sent});
                self.client.recvResponse(recvResponseCallback, &self.recv_completion);
            } else |err| {
                std.log.err("Context.sendQueryCallback err={s}", .{@errorName(err)});
            }
        }

        fn recvResponseCallback(
            self: *Context,
            completion: *MyClient.Completion,
            result: anyerror!usize,
        ) void {
            _ = completion;
            if (result) |received| {
                std.log.debug("Context.recvResponseCallback received={}", .{received});

                var input = BytesView.init(self.client.response_buf[0..received], true);
                if (ResponseMessage.decode(self.allocator, &input)) |resp| {
                    self.response = resp;
                } else |err| {
                    std.log.err("Context.recvResponseCallback decode err={s}", .{@errorName(err)});
                }
                self.client.close();
            } else |err| {
                std.log.err("Context.recvResponseCallback err={s}", .{@errorName(err)});
            }
        }

        fn runTest() !void {
            var io = try IO.init(32, 0);
            defer io.deinit();

            const address = try std.net.Address.parseIp4("8.8.8.8", 53);

            const allocator = testing.allocator;

            var self: Context = .{
                .allocator = allocator,
            };
            defer self.deinit();

            self.client = try MyClient.init(allocator, &io, &self, &.{});

            try self.client.connect(address, connectCallback, &self.connect_completion);

            while (!self.client.done) {
                try io.tick();
            }

            std.debug.print("response={}\n", .{self.response});
        }
    }.runTest();
}
