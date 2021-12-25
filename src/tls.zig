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

    fn writeTo(self: ProtocolVersion, writer: anytype) !void {
        try writer.writeIntBig(u16, @enumToInt(self));
    }
};

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
const CipherSuite = enum(u16) {
    // TLS 1.3 cipher suites.
    TLS_AES_128_GCM_SHA256 = 0x1301,

    fn writeTo(self: CipherSuite, writer: anytype) !void {
        try writer.writeIntBig(u16, @enumToInt(self));
    }
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

    fn writeTo(self: MsgType, writer: anytype) !void {
        try writer.writeByte(@enumToInt(self));
    }
};

const random_length = 32;

const ClientHelloMsg = struct {
    raw: ?[]const u8 = null,
    vers: ProtocolVersion = undefined,
    random: []u8 = undefined,
    session_id: []u8 = undefined,
    cipher_suites: []const CipherSuite = undefined,
    compression_methods: []const u8 = undefined,
    server_name: ?[]const u8 = null,
    ocsp_stapling: bool = undefined,
    supported_curves: []const CurveId = &[_]CurveId{},
    supported_points: []const u8 = &[_]u8{},
    ticket_supported: bool = false,
    session_ticket: []const u8 = undefined,
    supported_signature_algorithms: []const SignatureScheme = &[_]SignatureScheme{},
    supported_signature_algorithms_cert: []const SignatureScheme = &[_]SignatureScheme{},
    secure_renegotiation_supported: bool = false,
    secure_renegotiation: []const u8 = undefined,
    alpn_protocols: [][]const u8 = undefined,
    scts: bool = false,
    supported_versions: []const ProtocolVersion = undefined,
    cookie: []const u8 = undefined,
    key_shares: []const KeyShare = undefined,
    early_data: bool = false,
    psk_modes: []const PskMode = undefined,
    psk_identities: []const PskIdentity = undefined,
    psk_binders: [][]const u8 = undefined,

    fn deinit(self: *ClientHelloMsg, allocator: mem.Allocator) void {
        if (self.raw) |raw| {
            allocator.free(raw);
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
        try MsgType.ClientHello.writeTo(writer);
        try writeLengthPrefixed(u24, *const ClientHelloMsg, writeContentWithoutLen, self, writer);
    }

    fn writeContentWithoutLen(self: *const ClientHelloMsg, writer: anytype) !void {
        try self.vers.writeTo(writer);
        assert(self.random.len == random_length);
        try writeBytes(self.random, writer);
        try writeU8LenAndBytes(self.session_id, writer);
        try writeLengthPrefixed(
            u16,
            []const CipherSuite,
            writeCipherSuites,
            self.cipher_suites,
            writer,
        );
        try writeU8LenAndBytes(self.compression_methods, writer);

        const ext_len: usize = try countLength(*const ClientHelloMsg, writeExtensions, self);
        if (ext_len > 0) {
            try writeLength(u16, @intCast(u16, ext_len), writer);
            try self.writeExtensions(writer);
        }
    }

    fn writeExtensions(self: *const ClientHelloMsg, writer: anytype) !void {
        if (self.server_name) |server_name| {
            // RFC 6066, Section 3
            try ExtensionType.ServerName.writeTo(writer);
            try writeLengthPrefixed(
                u16,
                []const u8,
                writeU16LenNameTypeAndServerName,
                server_name,
                writer,
            );
        }
        if (self.ocsp_stapling) {
            // RFC 4366, Section 3.6
            try ExtensionType.StatusRequest.writeTo(writer);
            try writeBytes("\x00\x05" ++ // u16 length
                "\x01" ++ // status_type = ocsp
                "\x00\x00" ++ // empty responder_id_list
                "\x00\x00", // empty request_extensions
                writer);
        }
        if (self.supported_curves.len > 0) {
            // RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
            try ExtensionType.SupportedCurves.writeTo(writer);
            try writeLengthPrefixed(
                u16,
                []const CurveId,
                writeU16LenAndCurveIds,
                self.supported_curves,
                writer,
            );
        }
        if (self.supported_points.len > 0) {
            // RFC 4492, Section 5.1.2
            try ExtensionType.SupportedPoints.writeTo(writer);
            try writeLengthPrefixed(
                u16,
                []const u8,
                writeU8LenAndBytes,
                self.supported_points,
                writer,
            );
        }
        if (self.ticket_supported) {
            // RFC 5077, Section 3.2
            try ExtensionType.SessionTicket.writeTo(writer);
            try writeLengthPrefixed(u16, []const u8, writeBytes, self.session_ticket, writer);
        }
        if (self.supported_signature_algorithms.len > 0) {
            // RFC 5246, Section 7.4.1.4.1
            try ExtensionType.SignatureAlgorithms.writeTo(writer);
            try writeLengthPrefixed(
                u16,
                []const SignatureScheme,
                writeU16LenAndSignatureSchemes,
                self.supported_signature_algorithms,
                writer,
            );
        }
        if (self.supported_signature_algorithms_cert.len > 0) {
            // RFC 8446, Section 4.2.3
            try ExtensionType.SignatureAlgorithmsCert.writeTo(writer);
            try writeLengthPrefixed(
                u16,
                []const SignatureScheme,
                writeU16LenAndSignatureSchemes,
                self.supported_signature_algorithms_cert,
                writer,
            );
        }
    }
};

fn writeCipherSuites(cipher_suites: []const CipherSuite, writer: anytype) !void {
    for (cipher_suites) |suite| {
        try suite.writeTo(writer);
    }
}

fn writeU16LenNameTypeAndServerName(server_name: []const u8, writer: anytype) !void {
    try writeLengthPrefixed(u16, []const u8, writeNameTypeAndServerName, server_name, writer);
}

fn writeNameTypeAndServerName(server_name: []const u8, writer: anytype) !void {
    try writer.writeByte(0); // name_type = host_name
    try writeLengthPrefixed(u16, []const u8, writeBytes, server_name, writer);
}

fn writeU16LenAndCurveIds(curves: []const CurveId, writer: anytype) !void {
    try writeLengthPrefixed(u16, []const CurveId, writeCurveIds, curves, writer);
}

fn writeCurveIds(curves: []const CurveId, writer: anytype) !void {
    try writeEnumSlice(u16, CurveId, curves, writer);
}

fn writeU16LenAndSignatureSchemes(schemes: []const SignatureScheme, writer: anytype) !void {
    try writeLengthPrefixed(u16, []const SignatureScheme, writeSignatureSchemes, schemes, writer);
}

fn writeSignatureSchemes(schemes: []const SignatureScheme, writer: anytype) !void {
    try writeEnumSlice(u16, SignatureScheme, schemes, writer);
}

fn writeEnumSlice(
    comptime T: type,
    comptime EnumType: type,
    values: []const EnumType,
    writer: anytype,
) !void {
    for (values) |value| {
        try writer.writeIntBig(T, @enumToInt(value));
    }
}

fn writeLenAndIntSlice(
    comptime LenType: type,
    comptime IntType: type,
    comptime ElemType: type,
    values: []const ElemType,
    writer: anytype,
) !void {

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

fn writeInt(comptime T: type, val: anytype, writer: anytype) !void {
    try writer.writeIntBig(T, toInt(T, val));
}

fn toInt(comptime T: type, val: anytype) T {
    return switch (@typeInfo(@TypeOf(val))) {
        .ComptimeInt, .Int => @intCast(T, val),
        .Enum => @intCast(T, @enumToInt(val)),
        else => @panic("invalid type for writeIntBig"),
    };
}

test "writeIntBig" {
    var buf = [_]u8{0} ** 64;
    var fbs = io.fixedBufferStream(&buf);

    try writeIntSlice(u16, u16, &[_]u16{ 0, 1 }, fbs.writer());
    // try writeInt(u16, 0x0102, fbs.writer());
    // // try writeIntBig(u16, SignatureScheme.Pkcs1WithSha256, fbs.writer());
    std.debug.print("data=0x{x}\n", .{fmt.fmtSliceHexLower(fbs.getWritten())});
}

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
    PSKModes = 45,
    CertificateAuthorities = 47,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
    RenegotiationInfo = 0xff01,

    fn writeTo(self: ExtensionType, writer: anytype) !void {
        try writer.writeIntBig(u16, @enumToInt(self));
    }
};

fn writeLengthPrefixed(
    comptime LenType: type,
    comptime Context: type,
    comptime writeToFn: fn (context: Context, writer: anytype) anyerror!void,
    context: Context,
    writer: anytype,
) !void {
    const len = try countLength(Context, writeToFn, context);
    try writeLength(LenType, @intCast(LenType, len), writer);
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

fn writeLength(comptime T: type, length: T, writer: anytype) !void {
    try writer.writeIntBig(T, length);
}

fn writeU8LenAndBytes(bytes: []const u8, writer: anytype) !void {
    try writeLengthPrefixed(u8, []const u8, writeBytes, bytes, writer);
}

fn writeBytes(bytes: []const u8, writer: anytype) !void {
    try writer.writeAll(bytes);
}

const testing = std.testing;

test "ClientHelloMsg" {
    const allocator = testing.allocator;

    var client_random = [_]u8{0} ** 32;
    var session_id = [_]u8{0} ** 32;
    var msg = ClientHelloMsg{
        .vers = .v1_3,
        .random = &client_random,
        .session_id = &session_id,
        .cipher_suites = &[_]CipherSuite{.TLS_AES_128_GCM_SHA256},
        .compression_methods = &[_]u8{0},
        // .server_name = "example.com",
        .supported_curves = &[_]CurveId{.x25519},
        .supported_points = &[_]u8{'\xff'},
        .ticket_supported = true,
        .session_ticket = "session_ticket",
    };
    defer msg.deinit(allocator);

    const data = try msg.marshal(allocator);
    std.debug.print("data=0x{x}\n", .{fmt.fmtSliceHexLower(data)});
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
