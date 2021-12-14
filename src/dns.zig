const std = @import("std");
const io = std.io;
const math = std.math;
const mem = std.mem;
const builtin = @import("builtin");
const Endian = std.builtin.Endian;
const network_byte_order = Endian.Big;
const native_endian = builtin.cpu.arch.endian();

const Type = enum {
    None = 0,
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
};

const QType = enum {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
    AXFR = 252,
    MAILB,
    MAILA,
    @"*",
};

const Class = enum {
    IN = 1,
    CS,
    CH,
    HS,
};

const QClass = enum {
    IN = 1,
    CS,
    CH,
    HS,
    @"*" = 255,
};

const Rcode = enum(u4) {
    no_error = 0,
    format_error,
    server_failure,
    name_error,
    not_implemented,
    refused,
};

pub const MsgHdr = packed struct {
    _id: u16 = undefined,
    qr: u1 = undefined,
    opcode: u4 = undefined,
    aa: u1 = undefined,
    tc: u1 = undefined,
    rd: u1 = undefined,
    ra: u1 = undefined,
    zz: u3 = undefined,
    rcode: u4 = undefined,
    _qdcount: u16 = undefined,
    _ancount: u16 = undefined,
    _nscount: u16 = undefined,
    _arcount: u16 = undefined,

    pub fn id(self: *const MsgHdr) u16 {
        return fromNetworkU16(self._id);
    }

    pub fn setId(self: *MsgHdr, value: u16) void {
        self._id = toNetworkU16(value);
    }

    pub fn qdcount(self: *const MsgHdr) u16 {
        return fromNetworkU16(self._qdcount);
    }

    pub fn setQdcount(self: *MsgHdr, value: u16) void {
        self._qdcount = toNetworkU16(value);
    }

    pub fn ancount(self: *const MsgHdr) u16 {
        return fromNetworkU16(self._ancount);
    }

    pub fn setAncount(self: *MsgHdr, value: u16) void {
        self._ancount = toNetworkU16(value);
    }

    pub fn nscount(self: *const MsgHdr) u16 {
        return fromNetworkU16(self._nscount);
    }

    pub fn setNscount(self: *MsgHdr, value: u16) void {
        self._nscount = toNetworkU16(value);
    }

    pub fn arcount(self: *const MsgHdr) u16 {
        return fromNetworkU16(self._arcount);
    }

    pub fn setArcount(self: *MsgHdr, value: u16) void {
        self._arcount = toNetworkU16(value);
    }
};

fn fromNetworkU16(value: u16) u16 {
    return if (native_endian == network_byte_order) value else @byteSwap(u16, value);
}

fn toNetworkU16(value: u16) u16 {
    return if (native_endian == network_byte_order) value else @byteSwap(u16, value);
}

const name_max_len: usize = 63;
const name_max_encoded_len: usize = name_max_len + 2;

const NameError = error{
    InvalidInput,
};

fn decodeName(comptime WriterType: type, writer: WriterType, labels: []const u8) (NameError || WriterType.Error)!usize {
    var i: usize = 0;
    var len: usize = 0;
    while (i < labels.len) : (i += 1) {
        if (len > 0) {
            try writer.writeByte(labels[i]);
            len -= 1;
        } else {
            len = labels[i];
            if (len == 0) {
                return if (i > 0) i + 1 else error.InvalidInput;
            }
            if (i > 0) {
                try writer.writeByte('.');
            }
        }
    }
    return error.InvalidInput;
}

const EncodeNameError = NameError || io.Writer.Error;

fn encodeName(comptime WriterType: type, writer: WriterType, name: []const u8) (NameError || WriterType.Error)!usize {
    if (name.len > name_max_len) {
        return error.InvalidInput;
    }
    var start: usize = 0;
    while (true) {
        const pos = mem.indexOfScalarPos(u8, name, start, '.');
        const end = pos orelse name.len;
        var label_len: usize = end - start;

        try writer.writeByte(@truncate(u8, label_len));
        try writer.writeAll(name[start..end]);

        if (pos) |p| {
            start = p + 1;
        } else {
            try writer.writeByte('\x00');
            return name.len;
        }
    }
}

const testing = std.testing;

test "dns.MsgHdr" {
    try testing.expectEqual(@as(usize, 12), @sizeOf(MsgHdr));

    var h = MsgHdr{};
    var i: u16 = 0;
    while (true) : (i += 1) {
        h.setId(i);
        try testing.expectEqual(i, h.id());

        if (i == math.maxInt(u16)) break;
    }

    i = 0;
    while (true) : (i += 1) {
        h.setQdcount(i);
        try testing.expectEqual(i, h.qdcount());

        if (i == math.maxInt(u16)) break;
    }

    i = 0;
    while (true) : (i += 1) {
        h.setAncount(i);
        try testing.expectEqual(i, h.ancount());

        if (i == math.maxInt(u16)) break;
    }

    i = 0;
    while (true) : (i += 1) {
        h.setNscount(i);
        try testing.expectEqual(i, h.nscount());

        if (i == math.maxInt(u16)) break;
    }

    i = 0;
    while (true) : (i += 1) {
        h.setArcount(i);
        try testing.expectEqual(i, h.arcount());

        if (i == math.maxInt(u16)) break;
    }
}

test "dns.encodeName/decodeName" {
    const hostname = "example.com";

    var encoded_buf = [_]u8{0} ** (2 * name_max_len);
    var fbs = io.fixedBufferStream(&encoded_buf);
    try testing.expectEqual(hostname.len, try encodeName(@TypeOf(fbs.writer()), fbs.writer(), hostname));
    const encoded_name = fbs.getWritten();
    try testing.expectEqualSlices(u8, "\x07example\x03com\x00", encoded_name);

    var decoded_buf = [_]u8{0} ** name_max_len;
    var fbs2 = io.fixedBufferStream(&decoded_buf);
    try testing.expectEqual(encoded_name.len, try decodeName(@TypeOf(fbs2.writer()), fbs2.writer(), encoded_name));
    try testing.expectEqualSlices(u8, hostname, fbs2.getWritten());
}

test "dns.encodeName/decodeName longest" {
    const hostname = "a." ** 31 ++ "a";

    var encoded_buf = [_]u8{0} ** name_max_encoded_len;
    var fbs = io.fixedBufferStream(&encoded_buf);
    try testing.expectEqual(hostname.len, try encodeName(@TypeOf(fbs.writer()), fbs.writer(), hostname));
    const encoded_name = fbs.getWritten();
    try testing.expectEqualSlices(u8, "\x01a" ** 32 ++ "\x00", encoded_name);

    var decoded_buf = [_]u8{0} ** name_max_len;
    var fbs2 = io.fixedBufferStream(&decoded_buf);
    try testing.expectEqual(encoded_name.len, try decodeName(@TypeOf(fbs2.writer()), fbs2.writer(), encoded_name));
    try testing.expectEqualSlices(u8, hostname, fbs2.getWritten());
}

test "dns.decodeName/incomplete input" {
    const encoded_buf = "\x07example";
    var decoded_buf = [_]u8{0} ** name_max_len;
    var fbs = io.fixedBufferStream(&decoded_buf);
    try testing.expectError(error.InvalidInput, decodeName(@TypeOf(fbs.writer()), fbs.writer(), encoded_buf));
}

test "dns.encodeName/too long name" {
    const too_long_name = [_]u8{'a'} ** (name_max_len + 1);
    var encoded_buf = [_]u8{0} ** (2 * name_max_len);
    var fbs = io.fixedBufferStream(&encoded_buf);
    try testing.expectError(error.InvalidInput, encodeName(@TypeOf(fbs.writer()), fbs.writer(), &too_long_name));
}
