const std = @import("std");
const builtin = std.builtin;
const assert = std.debug.assert;
const fifo = std.fifo;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;

const BytesView = @import("../BytesView.zig");

pub const ProtocolVersion = enum(u16) {
    v1_3 = 0x0304,
    v1_2 = 0x0303,
    v1_0 = 0x0301,
};

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
pub const CipherSuite = enum(u16) {
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

pub const HandshakeMsg = union(MsgType) {
    HelloRequest: HelloRequestMsg,
    ClientHello: ClientHelloMsg,
    ServerHello: ServerHelloMsg,
    NewSessionTicket: NewSessionTicketMsg,
    EndOfEarlyData: EndOfEarlyDataMsg,
    EncryptedExtensions: EncryptedExtensionsMsg,
    Certificate: CertificateMsg,
    ServerKeyExchange: ServerKeyExchangeMsg,
    CertificateRequest: CertificateRequestMsg,
    ServerHelloDone: ServerHelloDoneMsg,
    CertificateVerify: CertificateVerifyMsg,
    ClientKeyExchange: ClientKeyExchangeMsg,
    Finished: FinishedMsg,
    CertificateStatus: CertificateStatusMsg,
    KeyUpdate: KeyUpdateMsg,
    NextProtocol: NextProtocolMsg,
    MessageHash: MessageHashMsg,

    pub fn unmarshal(allocator: mem.Allocator, data: []const u8) !HandshakeMsg {
        if (data.len < intTypeLen(u8) + intTypeLen(u24)) {
            return error.EndOfStream;
        }

        var bv = BytesView.init(data);
        const msg_type = @intToEnum(MsgType, try bv.readByte());
        const msg_len = try bv.readIntBig(u24);
        if (bv.restLen() < msg_len) {
            return error.EndOfStream;
        }

        switch (msg_type) {
            .ClientHello => HandshakeMsg{
                .ClientHello = try ClientHelloMsg.unmarshal(allocator, data),
            },
            else => @panic("not implemented yet"),
        }
    }
};

const HelloRequestMsg = void;
const ServerHelloMsg = void;
const NewSessionTicketMsg = void;
const EndOfEarlyDataMsg = void;
const EncryptedExtensionsMsg = void;
const CertificateMsg = void;
const ServerKeyExchangeMsg = void;
const CertificateRequestMsg = void;
const ServerHelloDoneMsg = void;
const CertificateVerifyMsg = void;
const ClientKeyExchangeMsg = void;
const FinishedMsg = void;
const CertificateStatusMsg = void;
const KeyUpdateMsg = void;
const NextProtocolMsg = void;
const MessageHashMsg = void;

pub const ClientHelloMsg = struct {
    raw: ?[]const u8 = null,
    vers: ProtocolVersion = undefined,
    random: []const u8 = undefined,
    session_id: []const u8 = undefined,
    cipher_suites: []const CipherSuite = undefined,
    compression_methods: []const CompressionMethod = &[_]CompressionMethod{.none},
    server_name: ?[]const u8 = null,
    ocsp_stapling: bool = undefined,
    supported_curves: []const CurveId = &[_]CurveId{},
    supported_points: []const EcPointFormat = &[_]EcPointFormat{},
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

    pub fn deinit(self: *ClientHelloMsg, allocator: mem.Allocator) void {
        if (self.raw) |raw| {
            allocator.free(raw);
            self.raw = null;
        }
    }

    pub fn deinitForUnmarshal(self: *ClientHelloMsg, allocator: mem.Allocator) void {
        allocator.free(self.cipher_suites);
        allocator.free(self.compression_methods);
    }

    fn unmarshal(allocator: mem.Allocator, data: []const u8) !ClientHelloMsg {
        var bv = BytesView.init(data);
        bv.advance(intTypeLen(u8) + intTypeLen(u24));
        const vers = @intToEnum(ProtocolVersion, try bv.readIntBig(u16));
        const random = try bv.sliceBytesNoEof(random_length);
        const session_id = try readLenAndSliceBytes(u8, &bv);
        const cipher_suites = try readLenAndEnumSlice(u16, CipherSuite, allocator, &bv);
        const compression_methods = try readLenAndEnumSlice(u8, CompressionMethod, allocator, &bv);

        return ClientHelloMsg{
            .raw = data[0..bv.pos],
            .vers = vers,
            .random = random,
            .session_id = session_id,
            .cipher_suites = cipher_suites,
            .compression_methods = compression_methods,
        };
    }

    pub fn marshal(self: *ClientHelloMsg, allocator: mem.Allocator) ![]const u8 {
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
            try writeLenLenAndIntSlice(u16, u8, u8, EcPointFormat, self.supported_points, writer);
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
        if (self.supported_versions.len > 0) {
            // RFC 8446, Section 4.2.1
            try writeInt(u16, ExtensionType.SupportedVersions, writer);
            try writeLenLenAndIntSlice(
                u16,
                u8,
                u16,
                ProtocolVersion,
                self.supported_versions,
                writer,
            );
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
pub const SignatureScheme = enum(u16) {
    // RSASSA-PKCS1-v1_5 algorithms.
    Pkcs1WithSha256 = 0x0401,
};

pub const CurveId = enum(u16) {
    x25519 = 29,
};

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
pub const EcPointFormat = enum(u8) {
    uncompressed = 0,
};

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
pub const KeyShare = struct {
    group: CurveId,
    data: []const u8,
};

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
pub const PskMode = enum(u8) {
    plain = 0,
    dhe = 1,
};

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
pub const PskIdentity = struct {
    label: []const u8,
    obfuscated_ticket_age: u32,
};

// TLS compression types.
pub const CompressionMethod = enum(u8) {
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

fn readLenAndSliceBytes(comptime LenType: type, bv: *BytesView) ![]const u8 {
    const len = try bv.readIntBig(LenType);
    return try bv.sliceBytesNoEof(len);
}

fn readLenAndEnumSlice(comptime LenType: type, comptime Enum: type, allocator: mem.Allocator, bv: *BytesView) ![]Enum {
    const enum_len = enumTypeLen(Enum);
    assert(enum_len > 0);

    const len = try bv.readIntBig(LenType);
    try bv.ensureLen(len);

    if (len % enum_len != 0) return error.BadPrefixLength;

    const count = len / enum_len;
    var values = try allocator.alloc(Enum, count);
    errdefer allocator.free(values);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        values[i] = try readEnum(Enum, bv);
    }
    return values;
}

test "readLenAndEnumSlice" {
    const allocator = testing.allocator;
    var bv = BytesView.init("\x00\x04\x03\x04\x03\x03");
    const got = try readLenAndEnumSlice(u16, ProtocolVersion, allocator, &bv);
    defer allocator.free(got);

    try testing.expectEqualSlices(ProtocolVersion, &[_]ProtocolVersion{ .v1_3, .v1_2 }, got);
}

fn readEnum(comptime Enum: type, bv: *BytesView) !Enum {
    return try bv.readEnum(Enum, std.builtin.Endian.Big);
}

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

fn writeLenAndBytes(comptime LenType: type, bytes: []const u8, writer: anytype) !void {
    try writeInt(LenType, bytes.len, writer);
    try writeBytes(bytes, writer);
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

fn enumTypeLen(comptime EnumType: type) usize {
    return intTypeLen(@typeInfo(EnumType).Enum.tag_type);
}

test "enumTypeLen" {
    try testing.expectEqual(@as(usize, 2), enumTypeLen(ProtocolVersion));
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

const testing = std.testing;

test "ClientHelloMsg.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: ClientHelloMsg, want: []const u8) !void {
            var copy = msg;
            const got = try copy.marshal(allocator);
            defer copy.deinit(allocator);

            try testing.expectEqualSlices(u8, want, got);
            const got2 = try copy.marshal(allocator);
            try testing.expectEqual(got, got2);
        }
    };

    try TestCase.run(
        ClientHelloMsg{
            .vers = .v1_3,
            .random = &[_]u8{0} ** 32,
            .session_id = &[_]u8{0} ** 32,
            .cipher_suites = &[_]CipherSuite{.TLS_AES_128_GCM_SHA256},
            .compression_methods = &[_]CompressionMethod{.none},
        },
        "\x01" ++ // ClientHello
            "\x00\x00\x49" ++ // u24 len
            "\x03\x04" ++ // TLS v1.3
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte random
            "\x20" ++ // u8 len 32
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte session id
            "\x00\x02" ++ // u16 len 2
            "\x13\x01" ++ // CipherSuite.TLS_AES_128_GCM_SHA256
            "\x01" ++ // u8 len 1
            "\x00", // CompressionMethod.none
    );

    try TestCase.run(
        ClientHelloMsg{
            .vers = .v1_3,
            .random = &[_]u8{0} ** 32,
            .session_id = &[_]u8{0} ** 32,
            .cipher_suites = &[_]CipherSuite{.TLS_AES_128_GCM_SHA256},
            .compression_methods = &[_]CompressionMethod{.none},
            .server_name = "example.com",
            .ocsp_stapling = true,
            .supported_curves = &[_]CurveId{.x25519},
            .supported_points = &[_]EcPointFormat{.uncompressed},
            .ticket_supported = true,
            .session_ticket = "\x12\x34\x56\x78",
            .supported_signature_algorithms = &[_]SignatureScheme{.Pkcs1WithSha256},
            .supported_signature_algorithms_cert = &[_]SignatureScheme{.Pkcs1WithSha256},
            .secure_renegotiation_supported = true,
            .secure_renegotiation = "",
            .alpn_protocols = &[_][]const u8{ "http/1.1", "spdy/1" },
            .scts = true,
            .supported_versions = &[_]ProtocolVersion{ .v1_3, .v1_2 },
            .cookie = "my cookie",
            .key_shares = &[_]KeyShare{.{ .group = .x25519, .data = "public key here" }},
            .early_data = true,
            .psk_modes = &[_]PskMode{ .plain, .dhe },
            .psk_identities = &[_]PskIdentity{.{ .label = "my id 1", .obfuscated_ticket_age = 0x778899aa }},
            .psk_binders = &[_][]const u8{ "binder1", "binder2" },
        },
        "\x01" ++ // ClientHello
            "\x00\x01\x0e" ++ // u24 len
            "\x03\x04" ++ // TLS v1.3
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte random
            "\x20" ++ // u8 len 32
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte session id
            "\x00\x02" ++ // u16 len 2
            "\x13\x01" ++ // CipherSuite.TLS_AES_128_GCM_SHA256
            "\x01" ++ // u8 len 1
            "\x00" ++ // CompressionMethod.none
            "\x00\xc3" ++ // u16 extensions len
            "\x00\x00" ++ // ExtensionType.ServerName
            "\x00\x12" ++ // u16 len
            "\x00\x10" ++ // u16 len
            "\x00" ++ // name_type = host_name
            "\x00\x0b" ++ // u16 len
            "\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d" ++ // server_name
            "\x00\x05" ++ // ExtensionType.StatusRequest
            "\x00\x05" ++ // u16 len
            "\x01" ++ // status_type = ocsp
            "\x00\x00" ++ // empty responder_id_list
            "\x00\x00" ++ // empty request_extensions
            "\x00\x0a" ++ // ExtensionType.SupportedCurves
            "\x00\x04" ++ // u16 len
            "\x00\x02" ++ // u16 len
            "\x00\x1d" ++ // CurveId.x25519
            "\x00\x0b" ++ // ExtensionType.SupportedPoints
            "\x00\x02" ++ // u16 len
            "\x01" ++ // u8 len
            "\x00" ++ // EcPointFormat.uncompressed
            "\x00\x23" ++ // ExtensionType.SessionTicket
            "\x00\x04" ++ // u16 len
            "\x12\x34\x56\x78" ++ // session_ticket
            "\x00\x0d" ++ // ExtensionType.SignatureAlgorithms
            "\x00\x04" ++ // u16 len
            "\x00\x02" ++ // u16 len
            "\x04\x01" ++ // SignatureScheme.Pkcs1WithSha256
            "\x00\x32" ++ // ExtensionType.SignatureAlgorithmsCert
            "\x00\x04" ++ // u16 len
            "\x00\x02" ++ // u16 len
            "\x04\x01" ++ // SignatureScheme.Pkcs1WithSha256
            "\xff\x01" ++ // ExtensionType.RenegotiationInfo
            "\x00\x01" ++ // u16 len
            "\x00" ++ // u8 len
            "\x00\x10" ++ // ExtensionType.Alpn
            "\x00\x12" ++ // u16 len
            "\x00\x10" ++ // u16 len
            "\x08" ++ // u8 len
            "\x68\x74\x74\x70\x2f\x31\x2e\x31" ++ //"http/1.1"
            "\x06" ++ // u8 len
            "\x73\x70\x64\x79\x2f\x31" ++ // "spdy/1"
            "\x00\x12" ++ // ExtensionType.Sct
            "\x00\x00" ++ // empty extension_data
            "\x00\x2b" ++ // ExtensionType.SupportedVersions
            "\x00\x05" ++ // u16 len
            "\x04" ++ // u8 len
            "\x03\x04" ++ // ProtocolVersion.v1_3
            "\x03\x03" ++ // ProtocolVersion.v1_2
            "\x00\x2c" ++ // ExtensionType.Cookie
            "\x00\x0b" ++ // u16 len
            "\x00\x09" ++ // u16 len
            "\x6d\x79\x20\x63\x6f\x6f\x6b\x69\x65" ++ // "my cookie"
            "\x00\x33" ++ // ExtensionType.KeyShare
            "\x00\x15" ++ // u16 len
            "\x00\x13" ++ // u16 len
            "\x00\x1d" ++ // CurveId.x25519
            "\x00\x0f" ++ // u16 len
            "\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x68\x65\x72\x65" ++ // "public key here"
            "\x00\x2a" ++ // ExtensionType.EarlyData
            "\x00\x00" ++ // empty extension_data
            "\x00\x2d" ++ // ExtensionType.PskModes
            "\x00\x03" ++ // u16 len
            "\x02" ++ // u8 len
            "\x00" ++ // PskMode.plain
            "\x01" ++ // PskMode.dhe
            "\x00\x29" ++ // ExtensionType.PreSharedKey
            "\x00\x1f" ++ // u16 len
            "\x00\x0d" ++ // u16 len
            "\x00\x07" ++ // u16 len
            "\x6d\x79\x20\x69\x64\x20\x31" ++ // label "my id 1"
            "\x77\x88\x99\xaa" ++ // obfuscated_ticket_age 0x778899aa
            "\x00\x10" ++ // u16 len
            "\x07" ++ // u8 len
            "\x62\x69\x6e\x64\x65\x72\x31" ++ // "binder1"
            "\x07" ++ // u8 len
            "\x62\x69\x6e\x64\x65\x72\x32", // "binder2"
    );
}

test "ClientHelloMsg.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: ClientHelloMsg) !void {
            _ = want;
            var got = try ClientHelloMsg.unmarshal(allocator, data);
            defer got.deinitForUnmarshal(allocator);

            std.log.debug("got={}", .{got});
        }
    };

    try TestCase.run(
        "\x01" ++ // ClientHello
            "\x00\x00\x49" ++ // u24 len
            "\x03\x04" ++ // TLS v1.3
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte random
            "\x20" ++ // u8 len 32
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte session id
            "\x00\x02" ++ // u16 len 2
            "\x13\x01" ++ // CipherSuite.TLS_AES_128_GCM_SHA256
            "\x01" ++ // u8 len 1
            "\x00", // CompressionMethod.none
        ClientHelloMsg{
            .vers = .v1_3,
            .random = &[_]u8{0} ** 32,
            .session_id = &[_]u8{0} ** 32,
            .cipher_suites = &[_]CipherSuite{.TLS_AES_128_GCM_SHA256},
            .compression_methods = &[_]CompressionMethod{.none},
        },
    );
}
