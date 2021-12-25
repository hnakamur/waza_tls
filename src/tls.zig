const std = @import("std");
const builtin = std.builtin;
const assert = std.debug.assert;
const fifo = std.fifo;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const BytesView = @import("parser/bytes.zig").BytesView;

const ProtocolVersion = enum(u16) {
    v1_3 = 0x0304,
    v1_2 = 0x0303,
    v1_0 = 0x0301,
};

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const CipherSuite = enum(u16) {
    // TLS 1.3 cipher suites.
    TLS_AES_128_GCM_SHA256 = 0x1301,
};

const MsgType = enum(u8) {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    CertificateStatus = 22,
    KeyUpdate = 24,
    NextProtocol = 67, // Not IANA assigned
    MessageHash = 254, // synthetic message
};

const random_length = 32;

const ClientHelloMsg = struct {
    raw: ?[]const u8 = null,
    vers: ProtocolVersion = undefined,
    random: []const u8 = undefined,
    session_id: []const u8 = undefined,
    cipher_suites: []const CipherSuite = undefined,
    compression_methods: []const CompressionMethod = &[_]CompressionMethod{.none},
    server_name: ?[]const u8 = null,
    ocsp_stapling: bool = undefined,
    supported_curves: []const CurveId = &[_]CurveId{},
    supported_points: []const u8 = &[_]u8{},
    ticket_supported: bool = false,
    session_ticket: []const u8 = "",
    supported_signature_algorithms: []const SignatureScheme = &[_]SignatureScheme{},
    supported_signature_algorithms_cert: []const SignatureScheme = &[_]SignatureScheme{},
    secure_renegotiation_supported: bool = false,
    secure_renegotiation: []const u8 = "",
    alpn_protocols: []const []const u8 = &[_][]u8{},
    scts: bool = false,
    supported_versions: []const ProtocolVersion = &[_]ProtocolVersion{},
    cookie: []const u8 = "",
    key_shares: []const KeyShare = &[_]KeyShare{},
    early_data: bool = false,
    psk_modes: []const PskMode = &[_]PskMode{},
    psk_identities: []const PskIdentity = &[_]PskIdentity{},
    psk_binders: []const []const u8 = &[_][]u8{},

    fn deinit(self: *ClientHelloMsg, allocator: mem.Allocator) void {
        if (self.raw) |raw| {
            allocator.free(raw);
            self.raw = null;
        }
    }

    fn marshal(self: *ClientHelloMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw) |raw| {
            return raw;
        }

        var buf = fifo.LinearFifo(u8, .Dynamic).init(allocator);
        var writer = buf.writer();
        try self.writeTo(writer);
        const raw = buf.readableSlice(0);
        assert(raw.ptr == buf.buf.ptr);
        self.raw = raw;
        return raw;
    }

    fn writeTo(self: *const ClientHelloMsg, writer: anytype) !void {
        try writeInt(u8, MsgType.ClientHello, writer);
        try writeLengthPrefixed(u24, *const ClientHelloMsg, writeMsgWithoutLen, self, writer);
    }

    fn writeMsgWithoutLen(self: *const ClientHelloMsg, writer: anytype) !void {
        try writeInt(u16, self.vers, writer);
        assert(self.random.len == random_length);
        try writeBytes(self.random, writer);
        try writeLenAndBytes(u8, self.session_id, writer);
        try writeLenAndIntSlice(u16, u16, CipherSuite, self.cipher_suites, writer);
        try writeLenAndIntSlice(u8, u8, CompressionMethod, self.compression_methods, writer);

        const ext_len: usize = try countLength(*const ClientHelloMsg, writeExtensions, self);
        if (ext_len > 0) {
            try writeInt(u16, ext_len, writer);
            try self.writeExtensions(writer);
        }
    }

    fn writeExtensions(self: *const ClientHelloMsg, writer: anytype) !void {
        if (self.server_name) |server_name| {
            // RFC 6066, Section 3
            try writeInt(u16, ExtensionType.ServerName, writer);
            const len3 = intTypeLen(u8) + intTypeLen(u16) + server_name.len;
            const len2 = intTypeLen(u16) + len3;
            const len1 = intTypeLen(u16) + len2;
            try writeInt(u16, len1, writer);
            try writeInt(u16, len2, writer);
            try writeInt(u8, 0, writer); // name_type = host_name;
            try writeLenAndBytes(u16, server_name, writer);
        }
        if (self.ocsp_stapling) {
            // RFC 4366, Section 3.6
            try writeInt(u16, ExtensionType.StatusRequest, writer);
            try writeBytes("\x00\x05" ++ // u16 length
                "\x01" ++ // status_type = ocsp
                "\x00\x00" ++ // empty responder_id_list
                "\x00\x00", // empty request_extensions
                writer);
        }
        if (self.supported_curves.len > 0) {
            // RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
            try writeInt(u16, ExtensionType.SupportedCurves, writer);
            try writeLenLenAndIntSlice(
                u16,
                u16,
                u16,
                CurveId,
                self.supported_curves,
                writer,
            );
        }
        if (self.supported_points.len > 0) {
            // RFC 4492, Section 5.1.2
            try writeInt(u16, ExtensionType.SupportedPoints, writer);
            try writeLenLenAndBytes(u16, u8, self.supported_points, writer);
        }
        if (self.ticket_supported) {
            // RFC 5077, Section 3.2
            try writeInt(u16, ExtensionType.SessionTicket, writer);
            try writeLenAndBytes(u16, self.session_ticket, writer);
        }
        if (self.supported_signature_algorithms.len > 0) {
            // RFC 5246, Section 7.4.1.4.1
            try writeInt(u16, ExtensionType.SignatureAlgorithms, writer);
            try writeLenLenAndIntSlice(
                u16,
                u16,
                u16,
                SignatureScheme,
                self.supported_signature_algorithms,
                writer,
            );
        }
        if (self.supported_signature_algorithms_cert.len > 0) {
            // RFC 8446, Section 4.2.3
            try writeInt(u16, ExtensionType.SignatureAlgorithmsCert, writer);
            try writeLenLenAndIntSlice(
                u16,
                u16,
                u16,
                SignatureScheme,
                self.supported_signature_algorithms_cert,
                writer,
            );
        }
        if (self.secure_renegotiation_supported) {
            // RFC 5746, Section 3.2
            try writeInt(u16, ExtensionType.RenegotiationInfo, writer);
            try writeLenLenAndBytes(u16, u8, self.secure_renegotiation, writer);
        }
        if (self.alpn_protocols.len > 0) {
            // RFC 7301, Section 3.1
            try writeInt(u16, ExtensionType.Alpn, writer);
            var len2: usize = 0;
            for (self.alpn_protocols) |proto| {
                len2 += intTypeLen(u8) + proto.len;
            }
            const len1 = intTypeLen(u16) + len2;
            try writeInt(u16, len1, writer);
            try writeInt(u16, len2, writer);
            for (self.alpn_protocols) |proto| {
                try writeLenAndBytes(u8, proto, writer);
            }
        }
        if (self.scts) {
            // RFC 6962, Section 3.3.1
            try writeInt(u16, ExtensionType.Sct, writer);
            try writeInt(u16, 0, writer); // empty extension_data
        }
        if (self.cookie.len > 0) {
            // RFC 8446, Section 4.2.2
            try writeInt(u16, ExtensionType.Cookie, writer);
            try writeLenLenAndBytes(u16, u16, self.cookie, writer);
        }
        if (self.key_shares.len > 0) {
            // RFC 8446, Section 4.2.8
            try writeInt(u16, ExtensionType.KeyShare, writer);
            var len2: usize = 0;
            for (self.key_shares) |*ks| {
                len2 += intTypeLen(u16) * 2 + ks.data.len;
            }
            const len1 = intTypeLen(u16) + len2;
            try writeInt(u16, len1, writer);
            try writeInt(u16, len2, writer);
            for (self.key_shares) |*ks| {
                try writeInt(u16, ks.group, writer);
                try writeLenAndBytes(u16, ks.data, writer);
            }
        }
        if (self.early_data) {
            // RFC 8446, Section 4.2.10
            try writeInt(u16, ExtensionType.EarlyData, writer);
            try writeInt(u16, 0, writer); // empty extension_data
        }
        if (self.psk_modes.len > 0) {
            // RFC 8446, Section 4.2.9
            try writeInt(u16, ExtensionType.PskModes, writer);
            try writeLenLenAndIntSlice(u16, u8, u8, PskMode, self.psk_modes, writer);
        }
        if (self.psk_identities.len > 0) { // pre_shared_key must be the last extension
            // RFC 8446, Section 4.2.11
            try writeInt(u16, ExtensionType.PreSharedKey, writer);
            var len2i: usize = 0;
            for (self.psk_identities) |*psk| {
                len2i += intTypeLen(u16) + psk.label.len + intTypeLen(u32);
            }
            var len2b: usize = 0;
            for (self.psk_binders) |binder| {
                len2b += intTypeLen(u8) + binder.len;
            }
            const len1 = intTypeLen(u16) + len2i + len2b;
            try writeInt(u16, len1, writer);
            try writeInt(u16, len2i, writer);
            for (self.psk_identities) |*psk| {
                try writeLenAndBytes(u16, psk.label, writer);
                try writeInt(u32, psk.obfuscated_ticket_age, writer);
            }
            try writeInt(u16, len2b, writer);
            for (self.psk_binders) |binder| {
                try writeLenAndBytes(u8, binder, writer);
            }
        }
    }
};

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
const SignatureScheme = enum(u16) {
    // RSASSA-PKCS1-v1_5 algorithms.
    Pkcs1WithSha256 = 0x0401,
};

const CurveId = enum(u16) {
    x25519 = 29,
};

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
const KeyShare = struct {
    group: CurveId,
    data: []u8,
};

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
const PskMode = enum(u8) {
    plain = 0,
    dhe = 1,
};

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
const PskIdentity = struct {
    label: []u8,
    obfuscated_ticket_age: u32,
};

// TLS compression types.
const CompressionMethod = enum(u8) {
    none = 0,
};

// TLS extension numbers
const ExtensionType = enum(u16) {
    ServerName = 0,
    StatusRequest = 5,
    SupportedCurves = 10, // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
    SupportedPoints = 11,
    SignatureAlgorithms = 13,
    Alpn = 16,
    Sct = 18,
    SessionTicket = 35,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskModes = 45,
    CertificateAuthorities = 47,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    RenegotiationInfo = 0xff01,
};

fn writeLengthPrefixed(
    comptime LenType: type,
    comptime Context: type,
    comptime writeToFn: fn (context: Context, writer: anytype) anyerror!void,
    context: Context,
    writer: anytype,
) !void {
    const len = try countLength(Context, writeToFn, context);
    try writeInt(LenType, len, writer);
    try writeToFn(context, writer);
}

fn countLength(
    comptime Context: type,
    comptime writeToFn: fn (context: Context, writer: anytype) anyerror!void,
    context: Context,
) !usize {
    var cnt_writer = io.countingWriter(io.null_writer);
    try writeToFn(context, cnt_writer.writer());
    return cnt_writer.bytes_written;
}

fn writeLenLenAndBytes(
    comptime LenType1: type,
    comptime LenType2: type,
    bytes: []const u8,
    writer: anytype,
) !void {
    const len1 = intTypeLen(LenType2) + bytes.len;
    try writeInt(LenType1, len1, writer);
    try writeLenAndBytes(LenType2, bytes, writer);
}

test "writeLenLenAndBytes" {
    const Case = struct {
        fn run(
            comptime LenType1: type,
            comptime LenType2: type,
            values: []const u8,
            want: []const u8,
        ) !void {
            var buf = [_]u8{0} ** 64;
            var fbs = io.fixedBufferStream(&buf);
            try writeLenLenAndBytes(LenType1, LenType2, values, fbs.writer());
            try testing.expectEqualSlices(u8, want, fbs.getWritten());
        }
    };

    try Case.run(u16, u8, "", "\x00\x01\x00");
    try Case.run(u16, u8, "123", "\x00\x04\x03123");
    try Case.run(u16, u16, "123", "\x00\x05\x00\x03123");
}

fn writeLenAndBytes(comptime LenType: type, bytes: []const u8, writer: anytype) !void {
    try writeInt(LenType, bytes.len, writer);
    try writeBytes(bytes, writer);
}

test "writeLenAndBytes" {
    const Case = struct {
        fn run(
            comptime LenType: type,
            values: []const u8,
            want: []const u8,
        ) !void {
            var buf = [_]u8{0} ** 64;
            var fbs = io.fixedBufferStream(&buf);
            try writeLenAndBytes(LenType, values, fbs.writer());
            try testing.expectEqualSlices(u8, want, fbs.getWritten());
        }
    };

    try Case.run(u8, "", "\x00");
    try Case.run(u8, "123", "\x03123");
    try Case.run(u16, "123", "\x00\x03123");
}

fn writeBytes(bytes: []const u8, writer: anytype) !void {
    try writer.writeAll(bytes);
}

fn writeLenLenAndIntSlice(
    comptime LenType1: type,
    comptime LenType2: type,
    comptime IntType: type,
    comptime ElemType: type,
    values: []const ElemType,
    writer: anytype,
) !void {
    const len2 = intTypeLen(IntType) * values.len;
    const len1 = intTypeLen(LenType2) + len2;
    try writeInt(LenType1, len1, writer);
    try writeInt(LenType2, len2, writer);
    try writeIntSlice(IntType, ElemType, values, writer);
}

test "writeLenLenAndIntSlice" {
    // testing.log_level = .debug;
    const Case = struct {
        fn run(
            comptime LenType1: type,
            comptime LenType2: type,
            comptime IntType: type,
            comptime ElemType: type,
            values: []const ElemType,
            want: []const u8,
        ) !void {
            var buf = [_]u8{0} ** 64;
            var fbs = io.fixedBufferStream(&buf);
            try writeLenLenAndIntSlice(LenType1, LenType2, IntType, ElemType, values, fbs.writer());
            std.log.debug("LenType1={}, LenType2={}, IntType={}, ElemType={}, values={any},\n got=0x{x},\nwant=0x{x}\n", .{
                LenType1,                   LenType2, IntType, ElemType, values, fmt.fmtSliceHexLower(fbs.getWritten()),
                fmt.fmtSliceHexLower(want),
            });
            try testing.expectEqualSlices(u8, want, fbs.getWritten());
        }
    };

    try Case.run(u16, u16, u8, u8, &[_]u8{}, "\x00\x02\x00\x00");
    try Case.run(u16, u16, u8, u8, "123", "\x00\x05\x00\x03123");
    try Case.run(
        u16,
        u16,
        u16,
        ProtocolVersion,
        &[_]ProtocolVersion{ .v1_3, .v1_2 },
        "\x00\x06\x00\x04\x03\x04\x03\x03",
    );
}

fn writeLenAndIntSlice(
    comptime LenType: type,
    comptime IntType: type,
    comptime ElemType: type,
    values: []const ElemType,
    writer: anytype,
) !void {
    const len = intTypeLen(IntType) * values.len;
    try writeInt(LenType, len, writer);
    try writeIntSlice(IntType, ElemType, values, writer);
}

fn intTypeLen(comptime IntType: type) usize {
    return (@typeInfo(IntType).Int.bits + 7) / 8;
}

test "writeLenAndIntSlice" {
    const Case = struct {
        fn run(
            comptime LenType: type,
            comptime IntType: type,
            comptime ElemType: type,
            values: []const ElemType,
            want: []const u8,
        ) !void {
            var buf = [_]u8{0} ** 64;
            var fbs = io.fixedBufferStream(&buf);
            try writeLenAndIntSlice(LenType, IntType, ElemType, values, fbs.writer());
            try testing.expectEqualSlices(u8, want, fbs.getWritten());
        }
    };

    try Case.run(u16, u8, u8, &[_]u8{}, "\x00\x00");
    try Case.run(u16, u8, u8, "123", "\x00\x03123");
    try Case.run(
        u16,
        u16,
        ProtocolVersion,
        &[_]ProtocolVersion{ .v1_3, .v1_2 },
        "\x00\x04\x03\x04\x03\x03",
    );
}

fn writeIntSlice(
    comptime IntType: type,
    comptime ElemType: type,
    values: []const ElemType,
    writer: anytype,
) !void {
    for (values) |value| {
        try writeInt(IntType, value, writer);
    }
}

test "writeIntSlice" {
    const Case = struct {
        fn run(
            comptime IntType: type,
            comptime ElemType: type,
            values: []const ElemType,
            want: []const u8,
        ) !void {
            var buf = [_]u8{0} ** 64;
            var fbs = io.fixedBufferStream(&buf);
            try writeIntSlice(IntType, ElemType, values, fbs.writer());
            try testing.expectEqualSlices(u8, want, fbs.getWritten());
        }
    };

    try Case.run(u8, ProtocolVersion, &[_]ProtocolVersion{}, "");
    try Case.run(u16, ProtocolVersion, &[_]ProtocolVersion{ .v1_3, .v1_2 }, "\x03\x04\x03\x03");
}

fn writeInt(comptime T: type, val: anytype, writer: anytype) !void {
    try writer.writeIntBig(T, toInt(T, val));
}

test "writeInt" {
    const Case = struct {
        fn run(comptime IntType: type, val: anytype, want: []const u8) !void {
            var buf = [_]u8{0} ** 64;
            var fbs = io.fixedBufferStream(&buf);
            try writeInt(IntType, val, fbs.writer());
            try testing.expectEqualSlices(u8, want, fbs.getWritten());
        }
    };

    try Case.run(u16, 0x1234, "\x12\x34");
    try Case.run(u16, ProtocolVersion.v1_3, "\x03\x04");
}

fn toInt(comptime T: type, val: anytype) T {
    return switch (@typeInfo(@TypeOf(val))) {
        .ComptimeInt, .Int => @intCast(T, val),
        .Enum => @intCast(T, @enumToInt(val)),
        else => @panic("invalid type for writeIntBig"),
    };
}

const testing = std.testing;

test "ClientHelloMsg" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const Case = struct {
        fn run(msg: ClientHelloMsg, want: []const u8) !void {
            var copy = msg;
            const got = try copy.marshal(allocator);
            defer copy.deinit(allocator);
            if (!mem.eql(u8, got, want)) {
                std.log.warn("msg={},\n got={x},\nwant={x}\n", .{
                    msg,
                    fmt.fmtSliceHexLower(got),
                    fmt.fmtSliceHexLower(want),
                });
            }
            try testing.expectEqualSlices(u8, want, got);
        }
    };

    try Case.run(ClientHelloMsg{
        .vers = .v1_3,
        .random = &[_]u8{0} ** 32,
        .session_id = &[_]u8{0} ** 32,
        .cipher_suites = &[_]CipherSuite{.TLS_AES_128_GCM_SHA256},
        .compression_methods = &[_]CompressionMethod{.none},
    }, "\x12\x34");

    // var session_id = [_]u8{0} ** 32;
    // var msg = ClientHelloMsg{
    //     .vers = .v1_3,
    //     .random = &[_]u8{0} ** 32,
    //     .session_id = &session_id,
    //     .cipher_suites = &[_]CipherSuite{.TLS_AES_128_GCM_SHA256},
    //     .compression_methods = &[_]CompressionMethod{.none},
    //     .server_name = "example.com",
    //     .supported_curves = &[_]CurveId{.x25519},
    //     .supported_points = &[_]u8{'\xff'},
    //     .ticket_supported = true,
    //     .session_ticket = "session_ticket",
    //     .psk_binders = &[_][]const u8{ "hi", "there" },
    // };
    // defer msg.deinit(allocator);

    // var data = try msg.marshal(allocator);
    // msg.deinit(allocator);

    // msg.random = &[_]u8{1} ** 32;
    // data = try msg.marshal(allocator);
    // std.debug.print("data=0x{x}\n", .{fmt.fmtSliceHexLower(data)});
}

test "writeLengthPrefixed" {
    const Foo = struct {
        const Self = @This();
        foo: []const u8,
        bar: []const u8,

        fn writeTo(self: *const Self, writer: anytype) !void {
            try writer.writeAll(self.foo);
            try writer.writeAll(self.bar);
        }
    };

    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const foo = Foo{ .foo = "hello, ", .bar = "world" };
    try writeLengthPrefixed(u8, *const Foo, Foo.writeTo, &foo, fbs.writer());
    try testing.expectEqualSlices(u8, "\x0chello, world", fbs.getWritten());
}
