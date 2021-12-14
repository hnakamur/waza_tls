const std = @import("std");
const io = std.io;
const math = std.math;
const mem = std.mem;

const Type = enum {
    A = 1,
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

const QType = enum(u16) {
    A = 1,
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

const QClass = enum(u16) {
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

pub const header_len: usize = 12;

pub const Header = packed struct {
    id: u16 = 0,

    qr: u1 = 0,
    opcode: u4 = 0,
    aa: u1 = 0,
    tc: u1 = 0,
    rd: u1 = 0,

    ra: u1 = 0,
    z: u3 = 0,
    rcode: u4 = 0,

    qdcount: u16 = 0,
    ancount: u16 = 0,
    nscount: u16 = 0,
    arcount: u16 = 0,

    pub fn fromBytes(bytes: [header_len]u8) Header {
        return .{
            .id = @as(u16, bytes[0]) << 8 | @as(u16, bytes[1]),
            .qr = bytes[2] >> 7,
            .opcode = bytes[2] << 1 >> 4,
            .aa = bytes[2] << 5 >> 7,
            .tc = bytes[2] << 6 >> 7,
            .rd = bytes[2] << 7 >> 7,
            .ra = bytes[3] >> 7,
            .z = bytes[3] << 1 >> 4,
            .rcode = bytes[3] << 4 >> 4,
            .qdcount = @as(u16, bytes[4]) << 8 | @as(u16, bytes[5]),
            .ancount = @as(u16, bytes[6]) << 8 | @as(u16, bytes[7]),
            .nscount = @as(u16, bytes[8]) << 8 | @as(u16, bytes[9]),
            .arcount = @as(u16, bytes[10]) << 8 | @as(u16, bytes[11]),
        };
    }

    pub fn encode(self: *const Header, dest: []u8) usize {
        dest[0] = @truncate(u8, self.id >> 8);
        dest[1] = @truncate(u8, self.id);

        dest[2] = @as(u8, self.qr) << 7 |
            @as(u8, self.opcode << 3) |
            @as(u8, self.aa) << 2 |
            @as(u8, self.tc) << 1 |
            @as(u8, self.rd);
        dest[3] = @as(u8, self.ra) << 7 |
            @as(u8, self.z) << 4 |
            @as(u8, self.rcode);

        dest[4] = @truncate(u8, self.qdcount >> 8);
        dest[5] = @truncate(u8, self.qdcount);

        dest[6] = @truncate(u8, self.ancount >> 8);
        dest[7] = @truncate(u8, self.ancount);

        dest[8] = @truncate(u8, self.nscount >> 8);
        dest[9] = @truncate(u8, self.nscount);

        dest[10] = @truncate(u8, self.arcount >> 8);
        dest[11] = @truncate(u8, self.arcount);

        return header_len;
    }
};

pub const name_max_len: usize = 63;
pub const name_max_encoded_len: usize = name_max_len + 2;

pub const NameError = error{
    InvalidName,
};

pub const Question = struct {
    name: []const u8 = undefined,
    qtype: QType = undefined,
    qclass: QClass = QClass.IN,

    pub fn encode(self: *const Question, dest: []u8) NameError!usize {
        var pos = try encodeName(self.name, dest);

        dest[pos] = @truncate(u8, @enumToInt(self.qtype) >> 8);
        dest[pos + 1] = @truncate(u8, @enumToInt(self.qtype));

        dest[pos + 2] = @truncate(u8, @enumToInt(self.qclass) >> 8);
        dest[pos + 3] = @truncate(u8, @enumToInt(self.qclass));

        return pos + 4;
    }
};

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

fn decodeName(labels: []const u8, dest: []u8) NameError!usize {
    var i: usize = 0;
    var len: usize = 0;
    var dest_pos: usize = 0;
    while (i < labels.len) : (i += 1) {
        if (len > 0) {
            dest[dest_pos] = labels[i];
            dest_pos += 1;
            len -= 1;
        } else {
            len = labels[i];
            if (len == 0) {
                return dest_pos;
            }
            if (i > 0) {
                dest[dest_pos] = '.';
                dest_pos += 1;
            }
        }
    }
    return error.InvalidName;
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
    const hdr_len = hdr.encode(encoded_buf[0..]);
    const expected_header = "\xAB\xCD" ++ // ID
        "\x01\x00" ++ // Recursion
        "\x00\x01" ++ // QDCOUNT
        "\x00\x00" ++ // ANCOUNT
        "\x00\x00" ++ // NSCOUNT
        "\x00\x00"; // ARCOUNT
    try testing.expectEqualSlices(u8, expected_header, encoded_buf[0..hdr_len]);

    const expected_question =
        "\x07example\x03com\x00" ++ // NAME
        "\x00\x01" ++ // QTYPE = A
        "\x00\x01"; // QCLASS =IN
    const q_len = try question.encode(encoded_buf[hdr_len..]);
    try testing.expectEqualSlices(u8, expected_question, encoded_buf[hdr_len .. hdr_len + q_len]);
}

test "dns.encodeName/decodeName" {
    const hostname = "example.com";

    var encoded_buf = [_]u8{0} ** (2 * name_max_len);
    const encoded_len = try encodeName(hostname, &encoded_buf);
    try testing.expectEqual(@as(usize, 13), encoded_len);
    const encoded_name = encoded_buf[0..encoded_len];
    try testing.expectEqualSlices(u8, "\x07example\x03com\x00", encoded_name);

    var decoded_buf = [_]u8{0} ** name_max_len;
    const decoded_len = try decodeName(encoded_name, &decoded_buf);
    try testing.expectEqual(hostname.len, decoded_len);
    try testing.expectEqualSlices(u8, hostname, decoded_buf[0..decoded_len]);
}

test "dns.encodeName/decodeName longest" {
    const hostname = "a." ** 31 ++ "a";

    var encoded_buf = [_]u8{0} ** (2 * name_max_len);
    const encoded_len = try encodeName(hostname, &encoded_buf);
    try testing.expectEqual(@as(usize, 65), encoded_len);
    const encoded_name = encoded_buf[0..encoded_len];
    try testing.expectEqualSlices(u8, "\x01a" ** 32 ++ "\x00", encoded_name);

    var decoded_buf = [_]u8{0} ** name_max_len;
    const decoded_len = try decodeName(encoded_name, &decoded_buf);
    try testing.expectEqual(hostname.len, decoded_len);
    try testing.expectEqualSlices(u8, hostname, decoded_buf[0..decoded_len]);
}

test "dns.decodeName/incomplete input" {
    const encoded_buf = "\x07example";
    var decoded_buf = [_]u8{0} ** name_max_len;
    try testing.expectError(error.InvalidName, decodeName(encoded_buf, &decoded_buf));
}

test "dns.encodeName/too long name" {
    const too_long_name = [_]u8{'a'} ** (name_max_len + 1);
    var encoded_buf = [_]u8{0} ** (2 * name_max_len);
    var fbs = io.fixedBufferStream(&encoded_buf);
    try testing.expectError(error.InvalidName, encodeName(&too_long_name, &encoded_buf));
}
