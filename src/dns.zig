const std = @import("std");
const io = std.io;
const math = std.math;
const mem = std.mem;
const net = std.net;
const Endian = std.builtin.Endian;

const Type = enum(u16) {
    A = 1,
    NS = 2,
    // MD = 3,
    // MF = 4,
    CNAME = 5,
    // SOA = 6,
    // MB = 7,
    // MG = 8,
    // MR = 9,
    // NULL = 10,
    // PTR = 12,
    // HINFO = 13,
    // MINFO = 14,
    // MX = 15,
    TXT = 16,
    // RP = 17,
    // AFSDB = 18,
    // X25 = 19,
    // ISDN = 20,
    // RT = 21,
    // NSAPPTR = 23,
    // SIG = 24,
    // KEY = 25,
    // PX = 26,
    // GPOS = 27,
    AAAA = 28,
    // LOC = 29,
    // NXT = 30,
    // EID = 31,
    // NIMLOC = 32,
    // SRV = 33,
    // ATMA = 34,
    // NAPTR = 35,
    // KX = 36,
    // CERT = 37,
    // DNAME = 39,
    // OPT = 41, // EDNS
    // APL = 42,
    // DS = 43,
    // SSHFP = 44,
    // RRSIG = 46,
    // NSEC = 47,
    // DNSKEY = 48,
    // DHCID = 49,
    // NSEC3 = 50,
    // NSEC3PARAM = 51,
    // TLSA = 52,
    // SMIMEA = 53,
    // HIP = 55,
    // NINFO = 56,
    // RKEY = 57,
    // TALINK = 58,
    // CDS = 59,
    // CDNSKEY = 60,
    // OPENPGPKEY = 61,
    // CSYNC = 62,
    // ZONEMD = 63,
    // SVCB = 64,
    // HTTPS = 65,
    // SPF = 99,
    // UINFO = 100,
    // UID = 101,
    // GID = 102,
    // UNSPEC = 103,
    // NID = 104,
    // L32 = 105,
    // L64 = 106,
    // LP = 107,
    // EUI48 = 108,
    // EUI64 = 109,
};

const QType = enum(u16) {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAPPTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    EID = 31,
    NIMLOC = 32,
    SRV = 33,
    ATMA = 34,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    DNAME = 39,
    OPT = 41, // EDNS
    APL = 42,
    DS = 43,
    SSHFP = 44,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    HIP = 55,
    NINFO = 56,
    RKEY = 57,
    TALINK = 58,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    SPF = 99,
    UINFO = 100,
    UID = 101,
    GID = 102,
    UNSPEC = 103,
    NID = 104,
    L32 = 105,
    L64 = 106,
    LP = 107,
    EUI48 = 108,
    EUI64 = 109,

    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    @"*" = 255,
};

const Class = enum {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
};

const QClass = enum(u16) {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    @"*" = 255,
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

pub const header_len: usize = 12;

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

pub const name_max_len: usize = 63;
pub const name_max_encoded_len: usize = name_max_len + 2;

pub const NameError = error{
    InvalidName,
};

pub const DecodeQuestionError = error{
    OutOfMemory,
} || NameError;

pub const Question = struct {
    name: []const u8 = undefined,
    qtype: QType = undefined,
    qclass: QClass = QClass.IN,

    pub fn decode(allocator: *mem.Allocator, data: []const u8) DecodeQuestionError!Question {
        const len = try calcLabelsDecodedLen(data, 0);
        var name = try allocator.alloc(u8, len);
        _ = try decodeLabels(data, 0, name);
        const pos = try getLabelsEndPos(data, 0);
        const qtype = @intToEnum(QType, mem.readInt(u16, @ptrCast(*const [2]u8, data[pos .. pos + 2]), Endian.Big));
        const qclass = @intToEnum(QClass, mem.readInt(u16, @ptrCast(*const [2]u8, data[pos + 2 .. pos + 4]), Endian.Big));
        return Question{
            .name = name,
            .qtype = qtype,
            .qclass = qclass,
        };
    }

    pub fn deinit(self: *const Question, allocator: *mem.Allocator) void {
        allocator.free(self.name);
    }

    pub fn encode(self: *const Question, dest: []u8) NameError!usize {
        var pos = try encodeName(self.name, dest);

        dest[pos] = @truncate(u8, @enumToInt(self.qtype) >> 8);
        dest[pos + 1] = @truncate(u8, @enumToInt(self.qtype));

        dest[pos + 2] = @truncate(u8, @enumToInt(self.qclass) >> 8);
        dest[pos + 3] = @truncate(u8, @enumToInt(self.qclass));

        return pos + 4;
    }
};

test "dns.Question" {
    const allocator = testing.allocator;

    const data = "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x03\x77\x77\x77\x06\x73\x61\x6b\x75\x72\x61\x02\x61\x64\x02\x6a\x70\x00" ++
        "\x00\x01" ++
        "\x00\x01";

    const question = try Question.decode(allocator, data[header_len..]);
    defer question.deinit(allocator);

    try testing.expectEqualStrings("www.sakura.ad.jp", question.name);
    try testing.expectEqual(QType.A, question.qtype);
    try testing.expectEqual(QClass.IN, question.qclass);
}

pub const QueryMessageError = error{
    InvalidHeader,
    InvalidQuestion,
    OutOfMemory,
} || NameError;

const qtype_len = @sizeOf(u16);
const qclass_len = @sizeOf(u16);

pub const QueryMessage = struct {
    header: Header,
    question: Question,

    pub fn getEndPos(data: []const u8) QueryMessageError!usize {
        if (data.len < header_len) return error.InvalidHeader;
        const label_len = try getLabelsEndPos(data[header_len..], 0);
        if (data[header_len + label_len ..].len < qtype_len + qclass_len) return error.InvalidQuestion;
        return header_len + label_len + qtype_len + qclass_len;
    }

    pub fn decode(allocator: *mem.Allocator, data: []const u8) QueryMessageError!QueryMessage {
        const header = Header.decode(data[0..header_len]);
        const question = try Question.decode(allocator, data[header_len..]);
        return QueryMessage{
            .header = header,
            .question = question,
        };
    }

    pub fn deinit(self: *const QueryMessage, allocator: *mem.Allocator) void {
        self.question.deinit(allocator);
    }

    pub fn calcEncodedLen(self: *const QueryMessage) NameError!usize {
        return header_len + try calcNameEncodedLen(self.question.name) + qtype_len + qclass_len;
    }

    pub fn encode(self: *const QueryMessage, dest: []u8) NameError!usize {
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

test "dns.Header" {
    const header = Header{ .id = 0xABCD };
    var header_buf: [header_len]u8 = undefined;
    header.encode(&header_buf);

    for (&header_buf) |b| {
        std.debug.print("\\x{x:0>2}", .{b});
    }
    std.debug.print("\n", .{});
}

test "dns.QueryMessage" {
    const allocator = testing.allocator;

    const encoded_data = "\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++
        "\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00" ++
        "\x00\x01\x00\x01";
    const query = try QueryMessage.decode(allocator, encoded_data);
    defer query.deinit(allocator);

    std.debug.print("query={}\n", .{query});
    const encoded_len = try query.calcEncodedLen();
    var encoded_buf = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded_buf);
    const pos = try query.encode(encoded_buf);
    try testing.expectEqual(encoded_len, pos);
    try testing.expectEqualSlices(u8, encoded_data, encoded_buf);
}

pub const ResponseMessageError = error{
    InvalidHeader,
    InvalidQuestion,
    InvalidAnswer,
    OutOfMemory,
} || NameError;

pub const ResponseMessage = struct {
    header: Header,
    question: Question,
    answer: Answer,

    pub fn decode(allocator: *mem.Allocator, data: []const u8) ResponseMessageError!ResponseMessage {
        const header = Header.decode(data[0..header_len]);
        const question = try Question.decode(allocator, data[header_len..]);
        const answer_pos = header_len + try Question.getEndPos(data[header_len..]);
        const answer = try Answer.decode(allocator, data, answer_pos);
        return ResponseMessage{
            .header = header,
            .question = question,
            .answer = answer,
        };
    }

    pub fn deinit(self: *const ResponseMessage, allocator: *mem.Allocator) void {
        self.question.deinit(allocator);
        self.answer.deinit(allocator);
    }
};

const AnswerError = error{
    InvalidAnswer,
    OutOfMemory,
} || NameError;

pub const Answer = struct {
    records: std.ArrayListUnmanaged(Rr),

    pub fn decode(
        allocator: *mem.Allocator,
        data: []const u8,
        start_pos: usize,
        count: usize,
    ) !Answer {
        var i: usize = 0;
        var pos: usize = start_pos;
    }

    pub fn deinit(self: *const Answer, allocator: *mem.Allocator) void {
        for (self.records) |*record| {
            record.deinit(allocator);
        }
        self.records.deinit(allocator);
    }
};

pub const Rr = struct {
    name: []const u8,
    @"type": Type,
    class: Class,
    ttl: u32,
    rd_length: u16,
    rdata: Rdata,

    pub fn getEndPos(
        data: []const u8,
        start_pos: usize,
    ) !usize {}

    // pub fn decode(
    //     allocator: *mem.Allocator,
    //     data: []const u8,
    //     start_pos: usize,
    // ) !Rr {}

    pub fn deinit(self: *const Rr, allocator: *mem.Allocator) void {
        self.rdata.deinit(allocator);
    }
};

pub const Rdata = union(Type) {
    A: net.Ip4Address,
    NS: []const u8,
    CNAME: []const u8,
    TXT: []const u8,
    AAAA: net.Ip6Address,

    pub fn deinit(self: *const Rdata, allocator: *mem.Allocator) void {
        switch (self.*) {
            Type.CNAME, Type.NS, Type.TXT => |str| allocator.free(str),
            else => {},
        }
    }
};

test "dns.Rdata" {
    const allocator = testing.allocator;

    const rdata = Rdata{ .NS = try allocator.dupe(u8, "example.com") };
    defer rdata.deinit(allocator);
}

fn calcNameEncodedLen(name: []const u8) NameError!usize {
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

fn encodeName(name: []const u8, dest: []u8) NameError!usize {
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

const offset_mask = 0xC0;

fn calcLabelsDecodedLen(answer: []const u8, start_pos: usize) NameError!usize {
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
    try testing.expectEqual(@as(NameError!usize, 36), calcLabelsDecodedLen(answer, start_pos));
}

test "dns.calcLabelsDecodedLen loop" {
    // testing.log_level = .debug;

    const answer = "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
        "\x03\x77\x77\x77\x06\x73\x61\x6b\x75\x72\x61\x02\x61\x64\x02\x6a\x70\xc0\x0c";
    const start_pos = 12;
    try testing.expectError(error.InvalidName, calcLabelsDecodedLen(answer, start_pos));
}

fn decodeLabels(answer: []const u8, start_pos: usize, dest: []u8) NameError!usize {
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

fn getLabelsEndPos(data: []const u8, start_pos: usize) NameError!usize {
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

test "dns.parseAnswer" {
    const answer = "\xab\xcd\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" ++
        "\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00" ++
        "\x00\x01\x00\x01" ++
        "\xc0\x0c" ++
        "\x00\x01" ++
        "\x00\x01" ++
        "\x00\x00\x48\x19" ++
        "\x00\x04" ++
        "\x5d\xb8\xd8\x22";
    const hdr = Header.decode(answer[0..header_len]);
    std.debug.print("hdr={}\n", .{hdr});

    // "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
    // "\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00" ++
    // "\x00\x01\x00\x01" ++
    // "\xc0\x0c" ++
    // "\x00\x01" ++
    // "\x00\x01" ++
    // "\x00\x00\x01\x2c" ++
    // "\x00\x04" ++
    // "\x68\x10\x85\xe5" ++
    // "\xc0\x0c" ++
    // "\x00\x01" ++
    // "\x00\x01" ++
    // "\x00\x00\x01\x2c" ++
    // "\x00\x04" ++
    // "\x68\x10\x84\xe5";

    // "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
    // "\x03\x77\x77\x77\x06\x73\x61\x6b\x75\x72\x61\x02\x61\x64\x02\x6a\x70\x00" ++
    // "\x00\x01" ++
    // "\x00\x01" ++
    // "\xc0\x0c" ++
    // "\x00\x05" ++
    // "\x00\x01" ++
    // "\x00\x00\x0c\x50"++
    // "\x00\x24" ++
    // "\x11\x73\x69\x74\x65\x2d\x31\x31\x32\x38\x30\x30\x33\x35\x30\x31\x31\x36\x05\x67\x73\x6c\x62\x33\x06\x73\x61\x6b\x75\x72\x61\x02\x6e\x65\xc0\x1a" ++
    // "\xc0\x2e" ++
    // "\x00\x01" ++
    // "\x00\x01" ++
    // "\x00\x00\x00\x0a" ++
    // "\x00\x04" ++
    // "\xa3\x2b\x18\x46";

    // "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
    // "\x0a\x63\x6c\x6f\x75\x64\x66\x6c\x61\x72\x65\x03\x63\x6f\x6d\x00" ++
    // "\x00\x1c" ++
    // "\x00\x01" ++
    // "\xc0\x0c" ++
    // "\x00\x1c\x00\x01" ++
    // "\x00\x00\x01\x2c" ++
    // "\x00\x10" ++
    // "\x26\x06\x47\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x10\x85\xe5" ++
    // "\xc0\x0c" ++
    // "\x00\x1c\x00\x01" ++
    // "\x00\x00\x01\x2c" ++
    // "\x00\x10" ++
    // "\x26\x06\x47\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x10\x84\xe5";

    // "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
    // "\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00" ++
    // "\x00\x10" ++
    // "\x00\x01" ++
    // "\xc0\x0c" ++
    // "\x00\x10\x00\x01" ++
    // "\x00\x00\x54\x60" ++
    // "\x00\x0c" ++
    // "\x0b\x76\x3d\x73\x70\x66\x31\x20\x2d\x61\x6c\x6c" ++
    // "\xc0\x0c" ++
    // "\x00\x10\x00\x01" ++
    // "\x00\x00\x54\x60" ++
    // "\x00\x21" ++
    // "\x20\x79\x78\x76\x79\x39\x6d\x34\x62\x6c\x72\x73\x77\x67\x72\x73\x7a\x38\x6e\x64\x6a\x68\x34\x36\x37\x6e\x32\x79\x37\x6d\x67\x6c\x32";

    // NS response
    // "\xab\xcd\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++
    // "\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00" ++
    // "\x00\x02" ++
    // "\x00\x01" ++
    // "\xc0\x0c" ++
    // "\x00\x02\x00\x01" ++
    // "\x00\x00\x4e\x83" ++
    // "\x00\x14" ++
    // "\x01\x61\x0c\x69\x61\x6e\x61\x2d\x73\x65\x72\x76\x65\x72\x73\x03\x6e\x65\x74\x00" ++
    // "\xc0\x0c\x00\x02\x00\x01\x00\x00\x4e\x83" +
    // "\x00\x04\x01\x62\xc0\x2b";

    // var name_buf = [_]u8{0} ** name_max_len;
    // try decodeName(answer[header_len..], &name_buf);
}

test "dns.send/recv" {
    const os = std.os;
    const linux = os.linux;
    const IO_Uring = linux.IO_Uring;

    var ring = IO_Uring.init(4, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const address = try net.Address.parseIp4("8.8.8.8", 53);
    const client = try os.socket(address.any.family, os.SOCK_DGRAM, 0);
    defer os.close(client);

    const connect = try ring.connect(0xcccccccc, client, &address.any, address.getOsSockLen());
    connect.flags |= linux.IOSQE_IO_LINK;

    var hdr = Header{
        .id = 0xABCD,
        .rd = 1,
        .qdcount = 1,
    };

    var question = Question{
        // .name = "www.sakura.ad.jp",
        // .name = "cloudflare.com",
        .name = "example.com",
        .qtype = .NS,
        .qclass = .IN,
    };

    var buffer_send = [_]u8{0} ** (@sizeOf(Header) + name_max_encoded_len + @sizeOf(u16) * 2);
    hdr.encode(buffer_send[0..header_len]);
    const q_len = try question.encode(buffer_send[header_len..]);
    const send = try ring.send(0xeeeeeeee, client, buffer_send[0 .. header_len + q_len], 0);
    send.flags |= linux.IOSQE_IO_LINK;

    var buffer_recv = [_]u8{0} ** 1024;
    const recv = try ring.recv(0xffffffff, client, buffer_recv[0..], 0);
    const nr_wait = try ring.submit();

    var i: usize = 0;
    while (i < nr_wait) : (i += 1) {
        const cqe = try ring.copy_cqe();
        std.debug.print("i={}, cqe.user_data=0x{x}, res={}\n", .{ i, cqe.user_data, cqe.res });
        if (cqe.user_data == 0xffffffff and cqe.res > 0) {
            std.debug.print("answer", .{});
            for (buffer_recv[0..@intCast(usize, cqe.res)]) |b| {
                std.debug.print("\\x{x:0>2}", .{b});
            }
            std.debug.print("\n", .{});
        }
    }
}
