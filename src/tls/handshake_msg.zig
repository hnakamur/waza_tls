const std = @import("std");
const assert = std.debug.assert;
const builtin = std.builtin;
const crypto = std.crypto;
const fifo = std.fifo;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;

const BytesView = @import("../BytesView.zig");
const asn1 = @import("asn1.zig");

pub const ProtocolVersion = enum(u16) {
    v1_3 = 0x0304,
    v1_2 = 0x0303,
    v1_1 = 0x0302,
    v1_0 = 0x0301,
};

// A list of cipher suite IDs that are, or have been, implemented by this
// package.
//
// See https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
pub const CipherSuiteId = enum(u16) {
    // TLS 1.3 cipher suites.
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,

    // TLS 1.0 - 1.2 cipher suites.
    tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = 0xc02b,
    tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = 0xc02c,
    tls_ecdhe_rsa_with_aes_128_gcm_sha256 = 0xc02f,
    tls_ecdhe_rsa_with_aes_256_gcm_sha384 = 0xc030,
    tls_ecdhe_rsa_with_chacha20_poly1305_sha256 = 0xcca8,
    tls_ecdhe_ecdsa_with_chacha20_poly1305_sha256 = 0xcca9,

    // TLS signaling cipher suite values
    scsv_renegotiation = 0x00ff,

    // tls_fallback_scsv isn't a standard cipher suite but an indicator
    // that the client is doing version fallback. See RFC 7507.
    tls_fallback_scsv = 0x5600,

    _,
};

pub const MsgType = enum(u8) {
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
    _,
};

pub const random_length = 32;

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

    pub fn deinit(self: *HandshakeMsg, allocator: mem.Allocator) void {
        switch (self.*) {
            .ClientHello => |*msg| msg.deinit(allocator),
            .ServerHello => |*msg| msg.deinit(allocator),
            .Certificate => |*msg| msg.deinit(allocator),
            .ServerKeyExchange => |*msg| msg.deinit(allocator),
            .ServerHelloDone => |*msg| msg.deinit(allocator),
            .ClientKeyExchange => |*msg| msg.deinit(allocator),
            .Finished => |*msg| msg.deinit(allocator),
            else => @panic("not implemented yet"),
        }
    }

    pub fn unmarshal(allocator: mem.Allocator, data: []const u8) !HandshakeMsg {
        if (data.len < handshake_msg_header_len) {
            return error.ShortInput;
        }
        const body_len = mem.readIntBig(u24, data[1..4]);
        const msg_len = handshake_msg_header_len + @as(usize, body_len);
        if (data.len < msg_len) {
            return error.ShortInput;
        }
        const msg_data = data[0..msg_len];
        const msg_type = @intToEnum(MsgType, data[0]);
        switch (msg_type) {
            .ClientHello => return HandshakeMsg{
                .ClientHello = try ClientHelloMsg.unmarshal(allocator, msg_data),
            },
            .ServerHello => return HandshakeMsg{
                .ServerHello = try ServerHelloMsg.unmarshal(allocator, msg_data),
            },
            .Certificate => return HandshakeMsg{
                .Certificate = try CertificateMsg.unmarshal(allocator, msg_data),
            },
            .ServerKeyExchange => return HandshakeMsg{
                .ServerKeyExchange = try ServerKeyExchangeMsg.unmarshal(allocator, msg_data),
            },
            .ServerHelloDone => return HandshakeMsg{
                .ServerHelloDone = try ServerHelloDoneMsg.unmarshal(allocator, msg_data),
            },
            .ClientKeyExchange => return HandshakeMsg{
                .ClientKeyExchange = try ClientKeyExchangeMsg.unmarshal(allocator, msg_data),
            },
            .Finished => return HandshakeMsg{
                .Finished = try FinishedMsg.unmarshal(allocator, msg_data),
            },
            else => @panic("not implemented yet"),
        }
    }
};

pub const handshake_msg_header_len = enumTypeLen(MsgType) + intTypeLen(u24);

const HelloRequestMsg = void;
const NewSessionTicketMsg = void;
const EndOfEarlyDataMsg = void;
const EncryptedExtensionsMsg = void;
const CertificateRequestMsg = void;
const CertificateVerifyMsg = void;
const CertificateStatusMsg = void;
const KeyUpdateMsg = void;
const NextProtocolMsg = void;
const MessageHashMsg = void;

pub const ClientHelloMsg = struct {
    raw: ?[]const u8 = null,
    vers: ProtocolVersion = undefined,
    random: []const u8 = undefined,
    session_id: []const u8 = undefined,
    cipher_suites: []const CipherSuiteId,
    compression_methods: []const CompressionMethod,
    server_name: ?[]const u8 = null,
    ocsp_stapling: bool = undefined,
    supported_curves: []const CurveId = &[_]CurveId{},
    supported_points: []const EcPointFormat = &[_]EcPointFormat{},
    ticket_supported: bool = false,
    session_ticket: []const u8 = "",
    supported_signature_algorithms: ?[]const SignatureScheme = null,
    supported_signature_algorithms_cert: ?[]const SignatureScheme = null,
    secure_renegotiation_supported: bool = false,
    secure_renegotiation: []const u8 = "",
    alpn_protocols: []const []const u8 = &[_][]u8{},
    scts: bool = false,
    supported_versions: ?[]const ProtocolVersion = null,
    cookie: []const u8 = "",
    key_shares: ?[]const KeyShare = null,
    early_data: bool = false,
    psk_modes: ?[]const PskMode = null,
    psk_identities: ?[]const PskIdentity = null,
    psk_binders: ?[]const []const u8 = null,

    pub fn deinit(self: *ClientHelloMsg, allocator: mem.Allocator) void {
        allocator.free(self.random);
        allocator.free(self.session_id);
        allocator.free(self.cipher_suites);
        allocator.free(self.compression_methods);
        if (self.supported_curves.len > 0) allocator.free(self.supported_curves);
        if (self.supported_points.len > 0) allocator.free(self.supported_points);
        if (self.alpn_protocols.len > 0) allocator.free(self.alpn_protocols);
        freeOptionalField(self, allocator, "supported_signature_algorithms");
        freeOptionalField(self, allocator, "supported_signature_algorithms_cert");
        freeOptionalField(self, allocator, "supported_versions");
        freeOptionalField(self, allocator, "key_shares");
        freeOptionalField(self, allocator, "psk_modes");
        freeOptionalField(self, allocator, "psk_identities");
        freeOptionalField(self, allocator, "psk_binders");
        freeOptionalField(self, allocator, "raw");
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !ClientHelloMsg {
        var bv: BytesView = undefined;
        var msg: ClientHelloMsg = undefined;
        {
            const raw = try allocator.dupe(u8, msg_data);
            errdefer allocator.free(raw);
            bv = BytesView.init(raw);
            bv.skip(handshake_msg_header_len);
            const vers = try readEnum(ProtocolVersion, &bv);
            const random = try allocator.dupe(u8, try bv.sliceBytesNoEof(random_length));
            const session_id = try allocator.dupe(u8, try readString(u8, &bv));

            const cipher_suites = try readEnumList(u16, CipherSuiteId, allocator, &bv);
            errdefer allocator.free(cipher_suites);
            const idx = mem.indexOfScalar(CipherSuiteId, cipher_suites, .scsv_renegotiation);
            const secure_renegotiation_supported = idx != null;

            const compression_methods = try readEnumList(u8, CompressionMethod, allocator, &bv);
            errdefer allocator.free(compression_methods);

            msg = ClientHelloMsg{
                .raw = raw,
                .vers = vers,
                .random = random,
                .session_id = session_id,
                .cipher_suites = cipher_suites,
                .secure_renegotiation_supported = secure_renegotiation_supported,
                .compression_methods = compression_methods,
            };
        }
        errdefer msg.deinit(allocator);

        if (bv.restLen() == 0) {
            return msg;
        }

        try msg.unmarshalExtensions(allocator, &bv);
        return msg;
    }

    pub fn marshal(self: *ClientHelloMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw) |raw| {
            return raw;
        }

        const msg_len: usize = try countLength(*const ClientHelloMsg, writeTo, self);
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);
        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try self.writeTo(writer);
        self.raw = raw;
        return raw;
    }

    fn unmarshalExtensions(self: *ClientHelloMsg, allocator: mem.Allocator, bv: *BytesView) !void {
        const extensions_len = try bv.readIntBig(u16);
        try bv.ensureRestLen(extensions_len);
        const extensions_end_pos = bv.pos + extensions_len;
        while (bv.pos < extensions_end_pos) {
            const ext_type = try readEnum(ExtensionType, bv);
            const ext_len = try bv.readIntBig(u16);
            try bv.ensureRestLen(ext_len);
            switch (ext_type) {
                .ServerName => {
                    // RFC 6066, Section 3
                    const server_names_len = try bv.readIntBig(u16);
                    try bv.ensureRestLen(server_names_len);
                    const server_names_end_pos = bv.pos + server_names_len;
                    while (bv.pos < server_names_end_pos) {
                        const name_type = try bv.readByte();
                        const server_name = try readString(u16, bv);
                        if (name_type != 0) {
                            continue;
                        }
                        if (self.server_name) |_| {
                            // Multiple names of the same name_type are prohibited.
                            return error.MultipleSameNameTypeServerName;
                        }
                        // An SNI value may not include a trailing dot.
                        if (mem.endsWith(u8, server_name, ".")) {
                            return error.SniWithTrailingDot;
                        }
                        self.server_name = server_name;
                    }
                },
                .StatusRequest => {
                    // RFC 4366, Section 3.6
                    const status_type = try readEnum(CertificateStatusType, bv);
                    // ignore responder_id_list and request_extensions
                    bv.skip(intTypeLen(u16) * 2);
                    self.ocsp_stapling = status_type == .ocsp;
                },
                .SupportedCurves => {
                    // RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
                    self.supported_curves = try readEnumList(u16, CurveId, allocator, bv);
                },
                .SupportedPoints => {
                    // RFC 4492, Section 5.1.2
                    self.supported_points = try readEnumList(
                        u8,
                        EcPointFormat,
                        allocator,
                        bv,
                    );
                    if (self.supported_points.len == 0) {
                        return error.EmptySupportedPoints;
                    }
                },
                .SessionTicket => {
                    // RFC 5077, Section 3.2
                    self.ticket_supported = true;
                    self.session_ticket = try bv.sliceBytesNoEof(ext_len);
                },
                .SignatureAlgorithms => {
                    // RFC 5246, Section 7.4.1.4.1
                    self.supported_signature_algorithms = try readEnumList(u16, SignatureScheme, allocator, bv);
                },
                .SignatureAlgorithmsCert => {
                    // RFC 8446, Section 4.2.3
                    self.supported_signature_algorithms_cert = try readEnumList(
                        u16,
                        SignatureScheme,
                        allocator,
                        bv,
                    );
                },
                .RenegotiationInfo => {
                    // RFC 5746, Section 3.2
                    self.secure_renegotiation = try readString(u8, bv);
                    self.secure_renegotiation_supported = true;
                },
                .Alpn => {
                    // RFC 7301, Section 3.1
                    self.alpn_protocols = try readStringList(u16, u8, allocator, bv);
                },
                .Sct => {
                    // RFC 6962, Section 3.3.1
                    self.scts = true;
                },
                .SupportedVersions => {
                    // RFC 8446, Section 4.2.1
                    self.supported_versions = try readEnumList(u8, ProtocolVersion, allocator, bv);
                },
                .Cookie => {
                    // RFC 8446, Section 4.2.2
                    const cookie = try readString(u16, bv);
                    if (cookie.len == 0) {
                        return error.EmptyCookie;
                    }
                    self.cookie = cookie;
                },
                .KeyShare => {
                    // RFC 8446, Section 4.2.
                    self.key_shares = try readKeyShareList(allocator, bv);
                },
                .EarlyData => {
                    // RFC 8446, Section 4.2.10
                    self.early_data = true;
                },
                .PskModes => {
                    // RFC 8446, Section 4.2.9
                    self.psk_modes = try readEnumList(u8, PskMode, allocator, bv);
                },
                .PreSharedKey => {
                    // RFC 8446, Section 4.2.11
                    self.psk_identities = try readPskIdentityList(allocator, bv);
                    self.psk_binders = try readNonEmptyStringList(u16, u8, allocator, bv);
                },
                else => bv.skip(ext_len),
            }
        }
    }

    fn writeTo(self: *const ClientHelloMsg, writer: anytype) !void {
        try writeInt(u8, MsgType.ClientHello, writer);
        try writeLengthPrefixed(u24, *const ClientHelloMsg, writeBody, self, writer);
    }

    fn writeBody(self: *const ClientHelloMsg, writer: anytype) !void {
        try writeInt(u16, self.vers, writer);
        assert(self.random.len == random_length);
        try writeBytes(self.random, writer);
        try writeLenAndBytes(u8, self.session_id, writer);
        try writeLenAndIntSlice(u16, u16, CipherSuiteId, self.cipher_suites, writer);
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
            const len2 = intTypeLen(u8) + intTypeLen(u16) + server_name.len;
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
            try writeLenLenAndIntSlice(u16, u16, u16, CurveId, self.supported_curves, writer);
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
        if (self.supported_signature_algorithms) |sig_and_algs| {
            // RFC 5246, Section 7.4.1.4.1
            try writeInt(u16, ExtensionType.SignatureAlgorithms, writer);
            try writeLenLenAndIntSlice(u16, u16, u16, SignatureScheme, sig_and_algs, writer);
        }
        if (self.supported_signature_algorithms_cert) |sig_and_algs| {
            // RFC 8446, Section 4.2.3
            try writeInt(u16, ExtensionType.SignatureAlgorithmsCert, writer);
            try writeLenLenAndIntSlice(u16, u16, u16, SignatureScheme, sig_and_algs, writer);
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
        if (self.supported_versions) |versions| {
            // RFC 8446, Section 4.2.1
            try writeInt(u16, ExtensionType.SupportedVersions, writer);
            try writeLenLenAndIntSlice(u16, u8, u16, ProtocolVersion, versions, writer);
        }
        if (self.cookie.len > 0) {
            // RFC 8446, Section 4.2.2
            try writeInt(u16, ExtensionType.Cookie, writer);
            try writeLenLenAndBytes(u16, u16, self.cookie, writer);
        }
        if (self.key_shares) |key_shares| {
            // RFC 8446, Section 4.2.8
            try writeInt(u16, ExtensionType.KeyShare, writer);
            var len2: usize = 0;
            for (key_shares) |*ks| {
                len2 += intTypeLen(u16) * 2 + ks.data.len;
            }
            const len1 = intTypeLen(u16) + len2;
            try writeInt(u16, len1, writer);
            try writeInt(u16, len2, writer);
            for (key_shares) |*ks| {
                try writeInt(u16, ks.group, writer);
                try writeLenAndBytes(u16, ks.data, writer);
            }
        }
        if (self.early_data) {
            // RFC 8446, Section 4.2.10
            try writeInt(u16, ExtensionType.EarlyData, writer);
            try writeInt(u16, 0, writer); // empty extension_data
        }
        if (self.psk_modes) |psk_modes| {
            // RFC 8446, Section 4.2.9
            try writeInt(u16, ExtensionType.PskModes, writer);
            try writeLenLenAndIntSlice(u16, u8, u8, PskMode, psk_modes, writer);
        }
        if (self.psk_identities) |identities| { // pre_shared_key must be the last extension
            // RFC 8446, Section 4.2.11
            try writeInt(u16, ExtensionType.PreSharedKey, writer);
            var len2i: usize = 0;
            for (identities) |*psk| {
                len2i += intTypeLen(u16) + psk.label.len + intTypeLen(u32);
            }
            var len2b: usize = 0;
            if (self.psk_binders) |binders| {
                for (binders) |binder| {
                    len2b += intTypeLen(u8) + binder.len;
                }
            }
            const len1 = intTypeLen(u16) * 2 + len2i + len2b;
            try writeInt(u16, len1, writer);
            try writeInt(u16, len2i, writer);
            for (identities) |*psk| {
                try writeLenAndBytes(u16, psk.label, writer);
                try writeInt(u32, psk.obfuscated_ticket_age, writer);
            }
            try writeInt(u16, len2b, writer);
            if (self.psk_binders) |binders| {
                for (binders) |binder| {
                    try writeLenAndBytes(u8, binder, writer);
                }
            }
        }
    }
};

pub const ServerHelloMsg = struct {
    raw: ?[]const u8 = null,
    vers: ProtocolVersion = undefined,
    random: []const u8 = undefined,
    session_id: []const u8 = undefined,
    cipher_suite: CipherSuiteId,
    compression_method: CompressionMethod,
    ocsp_stapling: bool = undefined,
    ticket_supported: bool = false,
    secure_renegotiation_supported: bool = false,
    secure_renegotiation: []const u8 = "",
    alpn_protocol: ?[]const u8 = null,
    scts: ?[]const []const u8 = null,
    supported_version: ?ProtocolVersion = null,
    server_share: ?KeyShare = null,
    selected_identity: ?u16 = null,
    supported_points: ?[]const EcPointFormat = null,

    // HelloRetryRequest extensions
    cookie: ?[]const u8 = null,
    selected_group: ?CurveId = null,

    pub fn deinit(self: *ServerHelloMsg, allocator: mem.Allocator) void {
        allocator.free(self.random);
        freeOptionalField(self, allocator, "supported_points");
        freeOptionalField(self, allocator, "scts");
        freeOptionalField(self, allocator, "raw");
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !ServerHelloMsg {
        var bv: BytesView = undefined;
        var msg: ServerHelloMsg = undefined;
        {
            const raw = try allocator.dupe(u8, msg_data);
            errdefer allocator.free(raw);
            bv = BytesView.init(raw);
            bv.skip(handshake_msg_header_len);
            const vers = try readEnum(ProtocolVersion, &bv);
            const random = try allocator.dupe(u8, try bv.sliceBytesNoEof(random_length));
            errdefer allocator.free(random);
            const session_id = try readString(u8, &bv);

            const cipher_suite = try readEnum(CipherSuiteId, &bv);
            const compression_method = try readEnum(CompressionMethod, &bv);

            msg = ServerHelloMsg{
                .raw = raw,
                .vers = vers,
                .random = random,
                .session_id = session_id,
                .cipher_suite = cipher_suite,
                .compression_method = compression_method,
            };
        }
        errdefer msg.deinit(allocator);

        if (bv.restLen() == 0) {
            return msg;
        }

        try msg.unmarshalExtensions(allocator, &bv);
        return msg;
    }

    pub fn marshal(self: *ServerHelloMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw) |raw| {
            return raw;
        }

        const msg_len: usize = try countLength(*const ServerHelloMsg, writeTo, self);
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);
        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try self.writeTo(writer);
        self.raw = raw;
        return raw;
    }

    fn unmarshalExtensions(self: *ServerHelloMsg, allocator: mem.Allocator, bv: *BytesView) !void {
        std.log.debug("unmarshalExtensions start bytes={}", .{fmtx.fmtSliceHexColonLower(bv.rest())});
        const extensions_len = try bv.readIntBig(u16);
        try bv.ensureRestLen(extensions_len);
        const extensions_end_pos = bv.pos + extensions_len;
        while (bv.pos < extensions_end_pos) {
            const ext_type = try readEnum(ExtensionType, bv);
            const ext_len = try bv.readIntBig(u16);
            try bv.ensureRestLen(ext_len);
            std.log.debug("unmarshalExtensions ext_type={}, ext_len={}, bytes={}", .{ ext_type, ext_len, fmtx.fmtSliceHexColonLower(bv.rest()) });
            switch (ext_type) {
                .StatusRequest => self.ocsp_stapling = true,
                .SessionTicket => self.ticket_supported = true,
                .RenegotiationInfo => {
                    self.secure_renegotiation = try readString(u8, bv);
                    self.secure_renegotiation_supported = true;
                },
                .Alpn => {
                    const protos_len = try bv.readIntBig(u16);
                    const protos_end_pos = bv.pos + protos_len;
                    self.alpn_protocol = try readString(u8, bv);
                    if (bv.pos < protos_end_pos) {
                        return error.TooManyProtocols;
                    }
                },
                .Sct => self.scts = try readNonEmptyStringList(u16, u16, allocator, bv),
                .SupportedVersions => self.supported_version = try readEnum(ProtocolVersion, bv),
                .Cookie => {
                    const cookie = try readString(u16, bv);
                    if (cookie.len == 0) {
                        return error.EmptyCookie;
                    }
                    self.cookie = cookie;
                },
                .KeyShare => {
                    // This extension has different formats in SH and HRR, accept either
                    // and let the handshake logic decide. See RFC 8446, Section 4.2.8.
                    if (ext_len == 2) {
                        self.selected_group = try readEnum(CurveId, bv);
                    } else {
                        const group = try readEnum(CurveId, bv);
                        const data = try readString(u16, bv);
                        self.server_share = .{ .group = group, .data = data };
                    }
                },
                .PreSharedKey => self.selected_identity = try bv.readIntBig(u16),
                .SupportedPoints => {
                    std.log.debug("SupportedPoints bytes={}", .{fmtx.fmtSliceHexColonLower(bv.rest())});
                    // RFC 4492, Section 5.1.2
                    self.supported_points = try readEnumList(
                        u8,
                        EcPointFormat,
                        allocator,
                        bv,
                    );
                    if (self.supported_points) |points| {
                        if (points.len == 0) {
                            return error.EmptySupportedPoints;
                        }
                    }
                },
                else => {
                    // Ignore unknown extensions.
                    bv.skip(ext_len);
                },
            }
        }
    }

    fn writeTo(self: *const ServerHelloMsg, writer: anytype) !void {
        try writeInt(u8, MsgType.ServerHello, writer);
        try writeLengthPrefixed(u24, *const ServerHelloMsg, writeBody, self, writer);
    }

    fn writeBody(self: *const ServerHelloMsg, writer: anytype) !void {
        try writeInt(u16, self.vers, writer);
        assert(self.random.len == random_length);
        try writeBytes(self.random, writer);
        try writeLenAndBytes(u8, self.session_id, writer);
        try writeInt(u16, self.cipher_suite, writer);
        try writeInt(u8, self.compression_method, writer);

        const ext_len: usize = try countLength(*const ServerHelloMsg, writeExtensions, self);
        if (ext_len > 0) {
            try writeInt(u16, ext_len, writer);
            try self.writeExtensions(writer);
        }
    }

    fn writeExtensions(self: *const ServerHelloMsg, writer: anytype) !void {
        if (self.ocsp_stapling) {
            try writeInt(u16, ExtensionType.StatusRequest, writer);
            const ext_len = 0;
            try writeInt(u16, ext_len, writer); // empty extension_data
        }
        if (self.ticket_supported) {
            try writeInt(u16, ExtensionType.SessionTicket, writer);
            const ext_len = 0;
            try writeInt(u16, ext_len, writer); // empty extension_data
        }
        if (self.secure_renegotiation_supported) {
            try writeInt(u16, ExtensionType.RenegotiationInfo, writer);
            try writeLenLenAndBytes(u16, u8, self.secure_renegotiation, writer);
        }
        if (self.alpn_protocol) |protocol| {
            try writeInt(u16, ExtensionType.Alpn, writer);
            const ext_len = intTypeLen(u16) + intTypeLen(u8) + protocol.len;
            try writeInt(u16, ext_len, writer);
            try writeLenLenAndBytes(u16, u8, protocol, writer);
        }
        if (self.scts) |scts| {
            try writeInt(u16, ExtensionType.Sct, writer);
            var scts_len: usize = 0;
            for (scts) |sct| {
                scts_len += intTypeLen(u16) + sct.len;
            }
            const ext_len = intTypeLen(u16) + scts_len;
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, scts_len, writer);
            for (scts) |sct| {
                try writeLenAndBytes(u16, sct, writer);
            }
        }
        if (self.supported_version) |version| {
            try writeInt(u16, ExtensionType.SupportedVersions, writer);
            const ext_len = intTypeLen(u16);
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, version, writer);
        }
        if (self.server_share) |key_share| {
            try writeInt(u16, ExtensionType.KeyShare, writer);
            const ext_len = intTypeLen(u16) * 2 + key_share.data.len;
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, key_share.group, writer);
            try writeLenAndBytes(u16, key_share.data, writer);
        }
        if (self.selected_identity) |selected_identity| {
            try writeInt(u16, ExtensionType.PreSharedKey, writer);
            const ext_len = intTypeLen(u16);
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, selected_identity, writer);
        }
        if (self.cookie) |cookie| {
            try writeInt(u16, ExtensionType.Cookie, writer);
            const ext_len = intTypeLen(u16) + cookie.len;
            try writeInt(u16, ext_len, writer);
            try writeLenAndBytes(u16, cookie, writer);
        }
        if (self.selected_group) |curve| {
            try writeInt(u16, ExtensionType.KeyShare, writer);
            const ext_len = intTypeLen(u16);
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, curve, writer);
        }
        if (self.supported_points) |points| {
            try writeInt(u16, ExtensionType.SupportedPoints, writer);
            const ext_len = intTypeLen(u8) + points.len;
            try writeInt(u16, ext_len, writer);
            try writeLenAndIntSlice(u8, u8, EcPointFormat, points, writer);
        }
    }
};

pub const CertificateMsg = struct {
    raw: ?[]const u8 = null,
    certificates: []const []const u8 = undefined,

    pub fn deinit(self: *CertificateMsg, allocator: mem.Allocator) void {
        allocator.free(self.certificates);
        freeOptionalField(self, allocator, "raw");
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !CertificateMsg {
        const raw = try allocator.dupe(u8, msg_data);
        errdefer allocator.free(raw);
        var bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);
        const certificates = try readStringList(u24, u24, allocator, &bv);
        errdefer allocator.free(certificates);

        return CertificateMsg{
            .raw = raw,
            .certificates = certificates,
        };
    }

    pub fn marshal(self: *CertificateMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw) |raw| {
            return raw;
        }

        var certs_len: usize = 0;
        for (self.certificates) |cert| {
            certs_len += intTypeLen(u24) + cert.len;
        }
        const msg_len = intTypeLen(u24) + certs_len;
        const raw_len = enumTypeLen(MsgType) + intTypeLen(u24) + msg_len;

        var raw = try allocator.alloc(u8, raw_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.Certificate, writer);
        try writeInt(u24, msg_len, writer);
        try writeInt(u24, certs_len, writer);
        for (self.certificates) |cert| {
            try writeLenAndBytes(u24, cert, writer);
        }
        self.raw = raw;
        return raw;
    }
};

pub const ServerKeyExchangeMsg = struct {
    raw: ?[]const u8 = null,
    key: []const u8,

    pub fn deinit(self: *ServerKeyExchangeMsg, allocator: mem.Allocator) void {
        allocator.free(self.key);
        freeOptionalField(self, allocator, "raw");
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !ServerKeyExchangeMsg {
        const raw = try allocator.dupe(u8, msg_data);
        var bv = BytesView.init(raw);
        bv.skip(enumTypeLen(MsgType));
        const key = try allocator.dupe(u8, try readString(u24, &bv));

        return ServerKeyExchangeMsg{
            .raw = raw,
            .key = key,
        };
    }

    pub fn marshal(self: *ServerKeyExchangeMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw) |raw| {
            return raw;
        }

        const body_len = self.key.len;
        const msg_len = handshake_msg_header_len + body_len;
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.ServerKeyExchange, writer);
        try writeLenAndBytes(u24, self.key, writer);
        self.raw = raw;
        return raw;
    }
};

pub const ServerHelloDoneMsg = struct {
    raw: ?[]const u8 = null,

    pub fn deinit(self: *ServerHelloDoneMsg, allocator: mem.Allocator) void {
        freeOptionalField(self, allocator, "raw");
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !ServerHelloDoneMsg {
        const raw = try allocator.dupe(u8, msg_data);
        errdefer allocator.free(raw);

        var bv = BytesView.init(raw);
        bv.skip(enumTypeLen(MsgType));
        const body_len = try bv.readIntBig(u24);
        try bv.ensureRestLen(body_len);

        return ServerHelloDoneMsg{
            .raw = raw,
        };
    }

    pub fn marshal(self: *ServerHelloDoneMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw) |raw| {
            return raw;
        }

        const raw_len = handshake_msg_header_len;
        var raw = try allocator.alloc(u8, raw_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.ServerHelloDone, writer);
        try writeInt(u24, 0, writer);
        self.raw = raw;
        return raw;
    }
};

pub const ClientKeyExchangeMsg = struct {
    raw: ?[]const u8 = null,
    ciphertext: []const u8 = undefined,

    pub fn deinit(self: *ClientKeyExchangeMsg, allocator: mem.Allocator) void {
        allocator.free(self.ciphertext);
        freeOptionalField(self, allocator, "raw");
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !ClientKeyExchangeMsg {
        const raw = try allocator.dupe(u8, msg_data);
        var bv = BytesView.init(raw);
        bv.skip(enumTypeLen(MsgType));
        const ciphertext = try allocator.dupe(u8, try readString(u24, &bv));

        return ClientKeyExchangeMsg{
            .raw = raw,
            .ciphertext = ciphertext,
        };
    }

    pub fn marshal(self: *ClientKeyExchangeMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw) |raw| {
            return raw;
        }

        const body_len = self.ciphertext.len;
        const msg_len = handshake_msg_header_len + body_len;
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.ClientKeyExchange, writer);
        try writeLenAndBytes(u24, self.ciphertext, writer);
        self.raw = raw;
        return raw;
    }
};

pub const FinishedMsg = struct {
    raw: ?[]const u8 = null,
    verify_data: []const u8 = undefined,

    pub fn deinit(self: *FinishedMsg, allocator: mem.Allocator) void {
        freeOptionalField(self, allocator, "raw");
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !FinishedMsg {
        const raw = try allocator.dupe(u8, msg_data);
        var bv = BytesView.init(raw);
        bv.skip(enumTypeLen(MsgType));
        const verify_data = try readString(u24, &bv);

        return FinishedMsg{
            .raw = raw,
            .verify_data = verify_data,
        };
    }

    pub fn marshal(self: *FinishedMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw) |raw| {
            return raw;
        }

        const body_len = self.verify_data.len;
        const msg_len = handshake_msg_header_len + body_len;
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.Finished, writer);
        try writeLenAndBytes(u24, self.verify_data, writer);
        self.raw = raw;
        return raw;
    }
};

pub fn freeOptionalField(
    lhs: anytype,
    allocator: mem.Allocator,
    comptime field_name: []const u8,
) void {
    if (@field(lhs, field_name)) |f| {
        allocator.free(f);
        @field(lhs, field_name) = null;
    }
}

const CertificateStatusType = enum(u8) {
    ocsp = 1,
    _,
};

// SignatureScheme identifies a signature algorithm supported by TLS. See
// RFC 8446, Section 4.2.3.
pub const SignatureScheme = enum(u16) {
    // RSASSA-PKCS1-v1_5 algorithms.
    pkcs1_with_sha256 = 0x0401,
    pkcs1_with_sha384 = 0x0501,
    pkcs1_with_sha512 = 0x0601,

    // RSASSA-PSS algorithms with public key OID rsaEncryption.
    pss_with_sha256 = 0x0804,
    pss_with_sha384 = 0x0805,
    pss_with_sha512 = 0x0806,

    // ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
    ecdsa_with_p256_and_sha256 = 0x0403,
    ecdsa_with_p384_and_sha384 = 0x0503,
    ecdsa_with_p521_and_sha512 = 0x0603,

    // EdDSA algorithms.
    ed25519 = 0x0807,

    // Legacy signature and hash algorithms for TLS 1.2.
    pkcs1_with_sha1 = 0x0201,
    ecdsa_with_sha1 = 0x0203,
};

pub const CurveId = enum(u16) {
    // RFC 5480, 2.1.1.1. Named Curve
    //
    // secp224r1 OBJECT IDENTIFIER ::= {
    //   iso(1) identified-organization(3) certicom(132) curve(0) 33 }
    //
    // secp256r1 OBJECT IDENTIFIER ::= {
    //   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
    //   prime(1) 7 }
    //
    // secp384r1 OBJECT IDENTIFIER ::= {
    //   iso(1) identified-organization(3) certicom(132) curve(0) 34 }
    //
    // secp521r1 OBJECT IDENTIFIER ::= {
    //   iso(1) identified-organization(3) certicom(132) curve(0) 35 }
    //
    // NB: secp256r1 is equivalent to prime256v1
    const oid_named_curve_p256 = asn1.ObjectIdentifier.initConst(&.{ 1, 2, 840, 10045, 3, 1, 7 });
    const oid_named_curve_p384 = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 132, 0, 34 });
    const oid_named_curve_p521 = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 132, 0, 35 });

    secp256r1 = 23,
    secp384r1 = 24,
    secp521r1 = 25,
    x25519 = 29,

    pub fn fromOid(oid: asn1.ObjectIdentifier) ?CurveId {
        if (oid.eql(oid_named_curve_p256)) {
            return CurveId.secp256r1;
        } else if (oid.eql(oid_named_curve_p384)) {
            return CurveId.secp384r1;
        } else if (oid.eql(oid_named_curve_p521)) {
            return CurveId.secp521r1;
        }
        return null;
    }
};

// TLS Elliptic Curve Point Formats
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
pub const EcPointFormat = enum(u8) {
    uncompressed = 0,
    _,
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

fn readStringList(
    comptime LenType1: type,
    comptime LenType2: type,
    allocator: mem.Allocator,
    bv: *BytesView,
) ![]const []const u8 {
    const len1 = try bv.readIntBig(LenType1);
    try bv.ensureRestLen(len1);

    const start_pos = bv.pos;
    const end_pos = start_pos + len1;
    var n: usize = 0;
    while (bv.pos < end_pos) {
        const len2 = try bv.readIntBig(LenType2);
        try bv.ensureRestLen(len2);
        bv.skip(len2);
        n += 1;
    }
    bv.pos = start_pos;

    var list = try allocator.alloc([]const u8, n);
    errdefer allocator.free(list);
    n = 0;
    while (bv.pos < end_pos) {
        list[n] = try readString(LenType2, bv);
        n += 1;
    }
    return list;
}

fn readNonEmptyStringList(
    comptime LenType1: type,
    comptime LenType2: type,
    allocator: mem.Allocator,
    bv: *BytesView,
) ![]const []const u8 {
    const len1 = try bv.readIntBig(LenType1);
    try bv.ensureRestLen(len1);

    const start_pos = bv.pos;
    const end_pos = start_pos + len1;
    var n: usize = 0;
    while (bv.pos < end_pos) {
        const len2 = try bv.readIntBig(LenType2);
        if (len2 == 0) {
            return error.EmptyString;
        }
        try bv.ensureRestLen(len2);
        bv.skip(len2);
        n += 1;
    }
    bv.pos = start_pos;

    var list = try allocator.alloc([]const u8, n);
    errdefer allocator.free(list);
    n = 0;
    while (bv.pos < end_pos) {
        list[n] = try readString(LenType2, bv);
        n += 1;
    }
    return list;
}

fn readString(comptime LenType: type, bv: *BytesView) ![]const u8 {
    const len = try bv.readIntBig(LenType);
    return try bv.sliceBytesNoEof(len);
}

test "readString empty" {
    var bv = BytesView.init("\x00");
    try testing.expectEqualStrings("", try readString(u8, &bv));
}

fn readKeyShareList(allocator: mem.Allocator, bv: *BytesView) ![]const KeyShare {
    const list_len = try bv.readIntBig(u16);
    try bv.ensureRestLen(list_len);

    const start_pos = bv.pos;
    const end_pos = start_pos + list_len;
    var n: usize = 0;
    while (bv.pos < end_pos) {
        bv.skip(enumTypeLen(CurveId));
        const data_len = try bv.readIntBig(u16);
        if (data_len == 0) {
            return error.EmptyKeyShareData;
        }
        try bv.ensureRestLen(data_len);
        bv.skip(data_len);
        n += 1;
    }
    bv.pos = start_pos;

    var values = try allocator.alloc(KeyShare, n);
    errdefer allocator.free(values);

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const group = try bv.readEnum(CurveId, .Big);
        const data = try readString(u16, bv);
        values[i] = .{ .group = group, .data = data };
    }
    return values;
}

fn readPskIdentityList(allocator: mem.Allocator, bv: *BytesView) ![]const PskIdentity {
    const list_len = try bv.readIntBig(u16);
    try bv.ensureRestLen(list_len);

    const start_pos = bv.pos;
    const end_pos = start_pos + list_len;
    var n: usize = 0;
    while (bv.pos < end_pos) {
        const label_len = try bv.readIntBig(u16);
        if (label_len == 0) {
            return error.EmptyPskIdentityLabel;
        }
        try bv.ensureRestLen(label_len);
        bv.skip(label_len);
        bv.skip(intTypeLen(u32));
        n += 1;
    }
    bv.pos = start_pos;

    var values = try allocator.alloc(PskIdentity, n);
    errdefer allocator.free(values);

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const label = try readString(u16, bv);
        const age = try bv.readIntBig(u32);
        values[i] = PskIdentity{ .label = label, .obfuscated_ticket_age = age };
    }
    return values;
}

fn readIntList(comptime Len: type, comptime Int: type, allocator: mem.Allocator, bv: *BytesView) ![]const Int {
    const int_len = intTypeLen(Int);
    assert(int_len > 0);

    const len = try bv.readIntBig(Len);
    try bv.ensureRestLen(len);

    if (len % int_len != 0) return error.BadPrefixLength;

    const count = len / int_len;
    var values = try allocator.alloc(Int, count);
    errdefer allocator.free(values);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        values[i] = try bv.readIntBig(Int);
    }
    return values;
}

fn readEnumList(comptime Len: type, comptime Enum: type, allocator: mem.Allocator, bv: *BytesView) ![]const Enum {
    const enum_len = enumTypeLen(Enum);
    assert(enum_len > 0);

    const len = try bv.readIntBig(Len);
    try bv.ensureRestLen(len);

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

test "readEnumList" {
    const allocator = testing.allocator;
    var bv = BytesView.init("\x00\x04\x03\x04\x03\x03");
    const got = try readEnumList(u16, ProtocolVersion, allocator, &bv);
    defer allocator.free(got);

    try testing.expectEqualSlices(ProtocolVersion, &[_]ProtocolVersion{ .v1_3, .v1_2 }, got);
}

fn readEnum(comptime Enum: type, bv: *BytesView) !Enum {
    return try bv.readEnum(Enum, .Big);
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
    return @divExact(@typeInfo(IntType).Int.bits, 8);
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

pub fn generateRandom(
    allocator: mem.Allocator,
    random: std.rand.Random,
) !*[random_length]u8 {
    var random_bytes = try allocator.alloc(u8, random_length);
    fillRandomBytes(random, random_bytes[0..random_length]);
    return random_bytes[0..random_length];
}

pub fn fillRandomBytes(random: std.rand.Random, out: *[random_length]u8) void {
    random.bytes(out[0..random_length]);
}

const testing = std.testing;

test "ClientHelloMsg.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: *ClientHelloMsg, want: []const u8) !void {
            const got = try msg.marshal(allocator);

            try testing.expectEqualSlices(u8, want, got);
            const got2 = try msg.marshal(allocator);
            try testing.expectEqual(got, got2);
        }
    };

    {
        var msg = try testCreateClientHelloMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_client_hello_msg);
    }

    {
        var msg = try testCreateClientHelloMsgWithExtensions(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_client_hello_msg_with_extensions);
    }
}

fn testingExpectPrintEqual(
    allocator: mem.Allocator,
    comptime template: []const u8,
    expected: anytype,
    actual: @TypeOf(expected),
) !void {
    const expected_str = try std.fmt.allocPrint(allocator, template, .{expected});
    defer allocator.free(expected_str);
    const actual_str = try std.fmt.allocPrint(allocator, template, .{actual});
    defer allocator.free(actual_str);
    try testing.expectEqualStrings(expected_str, actual_str);
}

test "ClientHelloMsg.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ClientHelloMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data);
            defer msg.deinit(allocator);

            var got = msg.ClientHello;
            try testing.expectEqualSlices(u8, data, got.raw.?);
            got.raw = null;

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = try testCreateClientHelloMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_client_hello_msg, &msg);
    }

    {
        var msg = try testCreateClientHelloMsgWithExtensions(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_client_hello_msg_with_extensions, &msg);
    }
}

fn testCreateClientHelloMsg(allocator: mem.Allocator) !ClientHelloMsg {
    const random = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(random);
    const session_id = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(session_id);
    const cipher_suites = try allocator.dupe(
        CipherSuiteId,
        &[_]CipherSuiteId{.tls_aes_128_gcm_sha256},
    );
    errdefer allocator.free(cipher_suites);
    const compression_methods = try allocator.dupe(
        CompressionMethod,
        &[_]CompressionMethod{.none},
    );
    errdefer allocator.free(compression_methods);
    return ClientHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
    };
}

const test_marshaled_client_hello_msg = "\x01" ++ // ClientHello
    "\x00\x00\x49" ++ // u24 len
    "\x03\x04" ++ // TLS v1.3
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte random
    "\x20" ++ // u8 len 32
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte session id
    "\x00\x02" ++ // u16 len 2
    "\x13\x01" ++ // CipherSuiteId.tls_aes_128_gcm_sha256
    "\x01" ++ // u8 len 1
    "\x00"; // CompressionMethod.none

fn testCreateClientHelloMsgWithExtensions(allocator: mem.Allocator) !ClientHelloMsg {
    const random = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(random);
    const session_id = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(session_id);
    const cipher_suites = try allocator.dupe(
        CipherSuiteId,
        &[_]CipherSuiteId{.tls_aes_128_gcm_sha256},
    );
    errdefer allocator.free(cipher_suites);
    const compression_methods = try allocator.dupe(
        CompressionMethod,
        &[_]CompressionMethod{.none},
    );
    errdefer allocator.free(compression_methods);
    const supported_curves = try allocator.dupe(CurveId, &[_]CurveId{.x25519});
    errdefer allocator.free(supported_curves);
    const supported_points = try allocator.dupe(
        EcPointFormat,
        &[_]EcPointFormat{.uncompressed},
    );
    errdefer allocator.free(supported_points);
    const supported_signature_algorithms = try allocator.dupe(
        SignatureScheme,
        &[_]SignatureScheme{.pkcs1_with_sha256},
    );
    errdefer allocator.free(supported_signature_algorithms);
    const supported_signature_algorithms_cert = try allocator.dupe(
        SignatureScheme,
        &[_]SignatureScheme{.pkcs1_with_sha256},
    );
    errdefer allocator.free(supported_signature_algorithms_cert);
    const alpn_protocols = try allocator.dupe(
        []const u8,
        &[_][]const u8{ "http/1.1", "spdy/1" },
    );
    errdefer allocator.free(alpn_protocols);
    const supported_versions = try allocator.dupe(
        ProtocolVersion,
        &[_]ProtocolVersion{ .v1_3, .v1_2 },
    );
    errdefer allocator.free(supported_versions);
    const key_shares = try allocator.dupe(
        KeyShare,
        &[_]KeyShare{.{ .group = .x25519, .data = "public key here" }},
    );
    errdefer allocator.free(key_shares);
    const psk_modes = try allocator.dupe(
        PskMode,
        &[_]PskMode{ .plain, .dhe },
    );
    errdefer allocator.free(psk_modes);
    const psk_identities = try allocator.dupe(
        PskIdentity,
        &[_]PskIdentity{.{ .label = "my id 1", .obfuscated_ticket_age = 0x778899aa }},
    );
    errdefer allocator.free(psk_identities);
    const psk_binders = try allocator.dupe(
        []const u8,
        &[_][]const u8{ "binder1", "binder2" },
    );
    errdefer allocator.free(psk_binders);
    return ClientHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
        .server_name = "example.com",
        .ocsp_stapling = true,
        .supported_curves = supported_curves,
        .supported_points = supported_points,
        .ticket_supported = true,
        .session_ticket = "\x12\x34\x56\x78",
        .supported_signature_algorithms = supported_signature_algorithms,
        .supported_signature_algorithms_cert = supported_signature_algorithms_cert,
        .secure_renegotiation_supported = true,
        .secure_renegotiation = "",
        .alpn_protocols = alpn_protocols,
        .scts = true,
        .supported_versions = supported_versions,
        .cookie = "my cookie",
        .key_shares = key_shares,
        .early_data = true,
        .psk_modes = psk_modes,
        .psk_identities = psk_identities,
        .psk_binders = psk_binders,
    };
}

const test_marshaled_client_hello_msg_with_extensions = "\x01" ++ // ClientHello
    "\x00\x01\x0e" ++ // u24 len
    "\x03\x04" ++ // TLS v1.3
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte random
    "\x20" ++ // u8 len 32
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++ // 32 byte session id
    "\x00\x02" ++ // u16 len 2
    "\x13\x01" ++ // CipherSuiteId.tls_aes_128_gcm_sha256
    "\x01" ++ // u8 len 1
    "\x00" ++ // CompressionMethod.none
    "\x00\xc3" ++ // u16 extensions len
    "\x00\x00" ++ // ExtensionType.ServerName
    "\x00\x10" ++ // u16 len
    "\x00\x0e" ++ // u16 len
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
    "\x00\x21" ++ // u16 len
    "\x00\x0d" ++ // u16 len
    "\x00\x07" ++ // u16 len
    "\x6d\x79\x20\x69\x64\x20\x31" ++ // label "my id 1"
    "\x77\x88\x99\xaa" ++ // obfuscated_ticket_age 0x778899aa
    "\x00\x10" ++ // u16 len
    "\x07" ++ // u8 len
    "\x62\x69\x6e\x64\x65\x72\x31" ++ // "binder1"
    "\x07" ++ // u8 len
    "\x62\x69\x6e\x64\x65\x72\x32"; // "binder2"

const fmtx = @import("../fmtx.zig");

test "ServerHelloMsg.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: *ServerHelloMsg, want: []const u8) !void {
            const got = try msg.marshal(allocator);
            if (!mem.eql(u8, got, want)) {
                std.log.warn("\n got={},\nwant={}\n", .{
                    fmtx.fmtSliceHexEscapeLower(got),
                    fmtx.fmtSliceHexEscapeLower(want),
                });
            }
            try testing.expectEqualSlices(u8, want, got);
            const got2 = try msg.marshal(allocator);
            try testing.expectEqual(got, got2);
        }
    };

    {
        var msg = try testCreateServerHelloMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_server_hello_msg);
    }

    {
        var msg = try testCreateServerHelloMsgWithExtensions(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_server_hello_msg_with_extensions);
    }
}

test "ServerHelloMsg.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ServerHelloMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data);
            defer msg.deinit(allocator);

            var got = msg.ServerHello;
            try testing.expectEqualSlices(u8, data, got.raw.?);
            got.raw = null;

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = try testCreateServerHelloMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_server_hello_msg, &msg);
    }

    {
        var msg = try testCreateServerHelloMsgWithExtensions(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_server_hello_msg_with_extensions, &msg);
    }

    {
        var msg = try testCreateServerHelloMsgWithExtensions2(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_server_hello_msg_with_extensions2, &msg);
    }
}

fn testCreateServerHelloMsg(allocator: mem.Allocator) !ServerHelloMsg {
    const random = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(random);
    return ServerHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = &[_]u8{0} ** 32,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .compression_method = .none,
        .ocsp_stapling = false,
    };
}

const test_marshaled_server_hello_msg = "\x02" ++ // ServerHello
    "\x00\x00\x46" ++ // u24 len
    "\x03\x04" ++ // TLS v1.3
    "\x00" ** 32 ++ // 32 byte random
    "\x20" ++ // u8 len 32
    "\x00" ** 32 ++ // 32 byte session id
    "\x13\x01" ++ // CipherSuiteId.tls_aes_128_gcm_sha256
    "\x00"; // CompressionMethod.none

fn testCreateServerHelloMsgWithExtensions(allocator: mem.Allocator) !ServerHelloMsg {
    const random = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(random);
    const scts = try allocator.dupe(
        []const u8,
        &[_][]const u8{ "sct1", "sct2" },
    );
    errdefer allocator.free(scts);
    const supported_points = try allocator.dupe(
        EcPointFormat,
        &[_]EcPointFormat{.uncompressed},
    );
    errdefer allocator.free(supported_points);
    return ServerHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = &[_]u8{0} ** 32,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .compression_method = .none,
        .ocsp_stapling = true,
        .ticket_supported = true,
        .secure_renegotiation_supported = true,
        .secure_renegotiation = "renegoation",
        .alpn_protocol = "http/1.1",
        .scts = scts,
        .supported_version = .v1_3,
        .server_share = .{ .group = .x25519, .data = "public key here" },
        .selected_identity = 0x4321,
        .supported_points = supported_points,
    };
}

const test_marshaled_server_hello_msg_with_extensions = "\x02" ++ // ServerHello
    "\x00\x00\xaa" ++ // u24 len
    "\x03\x04" ++ // TLS v1.3
    "\x00" ** 32 ++ // 32 byte random
    "\x20" ++ // u8 len 32
    "\x00" ** 32 ++ // 32 byte session id
    "\x13\x01" ++ // CipherSuiteId.tls_aes_128_gcm_sha256
    "\x00" ++ // CompressionMethod.none
    "\x00\x62" ++ // u16 extensions_len
    "\x00\x05" ++ // ExtensionType.StatusRequest
    "\x00\x00" ++ // u16 ext_len = 0 (empty)
    "\x00\x23" ++ // ExtensionType.SessionTicket
    "\x00\x00" ++ // u16 ext_len = 0 (empty)
    "\xff\x01" ++ // ExtensionType.RenegotiationInfo
    "\x00\x0c" ++ // u16 ext_len
    "\x0b" ++ // u8 len
    "\x72\x65\x6e\x65\x67\x6f\x61\x74\x69\x6f\x6e" ++ // "renegoation"
    "\x00\x10" ++ // ExtensionType.Alpn
    "\x00\x0b" ++ // u16 ext_len
    "\x00\x09" ++ // u16 protocols len
    "\x08" ++ // u8 protocol len
    "\x68\x74\x74\x70\x2f\x31\x2e\x31" ++ // "http/1.1"
    "\x00\x12" ++ // ExtensionType.Sct
    "\x00\x0e" ++ // u16 ext_len
    "\x00\x0c" ++ // u16 scts len
    "\x00\x04" ++ // u16 sct len
    "\x73\x63\x74\x31" ++ // "sct1"
    "\x00\x04" ++ // u16 sct len
    "\x73\x63\x74\x32" ++ // "sct2"
    "\x00\x2b" ++ // ExtensionType.SupportedVersions
    "\x00\x02" ++ // u16 ext_len
    "\x03\x04" ++ // TLS v1.3
    "\x00\x33" ++ // ExtensionType.KeyShare
    "\x00\x13" ++ // u16 ext_len
    "\x00\x1d" ++ // u16 server_share.group = CurveId.x25519
    "\x00\x0f" ++ // u16 server_share.data.len
    "\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x68\x65\x72\x65" ++ // "public key here"
    "\x00\x29" ++ // ExtensionType.PreSharedKey
    "\x00\x02" ++ // u16 ext_len
    "\x43\x21" ++ // u16 selected_identity = 0x4321
    "\x00\x0b" ++ // ExtensionType.SupportedPoints
    "\x00\x02" ++ // u16 ext_len
    "\x01" ++ // u8 len
    "\x00"; // EcPointFormat.uncompressed

fn testCreateServerHelloMsgWithExtensions2(allocator: mem.Allocator) !ServerHelloMsg {
    const random = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(random);
    const scts = try allocator.dupe(
        []const u8,
        &[_][]const u8{ "sct1", "sct2" },
    );
    errdefer allocator.free(scts);
    const supported_points = try allocator.dupe(
        EcPointFormat,
        &[_]EcPointFormat{.uncompressed},
    );
    errdefer allocator.free(supported_points);
    return ServerHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = &[_]u8{0} ** 32,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .compression_method = .none,
        .ocsp_stapling = true,
        .ticket_supported = true,
        .secure_renegotiation_supported = true,
        .secure_renegotiation = "",
        .alpn_protocol = "http/1.1",
        .scts = scts,
        .supported_version = .v1_3,
        .server_share = .{ .group = .x25519, .data = "public key here" },
        .selected_identity = 0x4321,
        .supported_points = supported_points,
    };
}

const test_marshaled_server_hello_msg_with_extensions2 = "\x02" ++ // ServerHello
    "\x00\x00\x9f" ++ // u24 len
    "\x03\x04" ++ // TLS v1.3
    "\x00" ** 32 ++ // 32 byte random
    "\x20" ++ // u8 len 32
    "\x00" ** 32 ++ // 32 byte session id
    "\x13\x01" ++ // CipherSuiteId.tls_aes_128_gcm_sha256
    "\x00" ++ // CompressionMethod.none
    "\x00\x57" ++ // u16 extensions_len
    "\x00\x05" ++ // ExtensionType.StatusRequest
    "\x00\x00" ++ // u16 ext_len = 0 (empty)
    "\x00\x23" ++ // ExtensionType.SessionTicket
    "\x00\x00" ++ // u16 ext_len = 0 (empty)
    "\xff\x01" ++ // ExtensionType.RenegotiationInfo
    "\x00\x01" ++ // u16 ext_len
    "\x00" ++ // u8 len
    "\x00\x10" ++ // ExtensionType.Alpn
    "\x00\x0b" ++ // u16 ext_len
    "\x00\x09" ++ // u16 protocols len
    "\x08" ++ // u8 protocol len
    "\x68\x74\x74\x70\x2f\x31\x2e\x31" ++ // "http/1.1"
    "\x00\x12" ++ // ExtensionType.Sct
    "\x00\x0e" ++ // u16 ext_len
    "\x00\x0c" ++ // u16 scts len
    "\x00\x04" ++ // u16 sct len
    "\x73\x63\x74\x31" ++ // "sct1"
    "\x00\x04" ++ // u16 sct len
    "\x73\x63\x74\x32" ++ // "sct2"
    "\x00\x2b" ++ // ExtensionType.SupportedVersions
    "\x00\x02" ++ // u16 ext_len
    "\x03\x04" ++ // TLS v1.3
    "\x00\x33" ++ // ExtensionType.KeyShare
    "\x00\x13" ++ // u16 ext_len
    "\x00\x1d" ++ // u16 server_share.group = CurveId.x25519
    "\x00\x0f" ++ // u16 server_share.data.len
    "\x70\x75\x62\x6c\x69\x63\x20\x6b\x65\x79\x20\x68\x65\x72\x65" ++ // "public key here"
    "\x00\x29" ++ // ExtensionType.PreSharedKey
    "\x00\x02" ++ // u16 ext_len
    "\x43\x21" ++ // u16 selected_identity = 0x4321
    "\x00\x0b" ++ // ExtensionType.SupportedPoints
    "\x00\x02" ++ // u16 ext_len
    "\x01" ++ // u8 len
    "\x00"; // EcPointFormat.uncompressed

test "CertificateMsg.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: *CertificateMsg, want: []const u8) !void {
            const got = try msg.marshal(allocator);
            if (!mem.eql(u8, got, want)) {
                std.log.warn("\n got={},\nwant={}\n", .{
                    fmtx.fmtSliceHexEscapeLower(got),
                    fmtx.fmtSliceHexEscapeLower(want),
                });
            }
            try testing.expectEqualSlices(u8, want, got);
            const got2 = try msg.marshal(allocator);
            try testing.expectEqual(got, got2);
        }
    };

    {
        var msg = try testCreateCertificateMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_certificate_msg);
    }
}

test "CertificateMsg.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *CertificateMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data);
            defer msg.deinit(allocator);

            var got = msg.Certificate;
            try testing.expectEqualSlices(u8, data, got.raw.?);
            got.raw = null;

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = try testCreateCertificateMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_certificate_msg, &msg);
    }
}

fn testCreateCertificateMsg(allocator: mem.Allocator) !CertificateMsg {
    const certificates = try allocator.dupe(
        []const u8,
        &[_][]const u8{ "cert1", "cert2" },
    );
    return CertificateMsg{
        .certificates = certificates,
    };
}

const test_marshaled_certificate_msg = "\x0b" ++ // MsgType.Certificate
    "\x00\x00\x13" ++ // u24 msg_len
    "\x00\x00\x10" ++ // u24 certificates_len
    "\x00\x00\x05" ++ // u24 certificate len
    "\x63\x65\x72\x74\x31" ++ // "cert1"
    "\x00\x00\x05" ++ // u24 certificate len
    "\x63\x65\x72\x74\x32"; // "cert2"

test "ServerKeyExchangeMsg.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: *ServerKeyExchangeMsg, want: []const u8) !void {
            const got = try msg.marshal(allocator);
            if (!mem.eql(u8, got, want)) {
                std.log.warn("\n got={},\nwant={}\n", .{
                    fmtx.fmtSliceHexEscapeLower(got),
                    fmtx.fmtSliceHexEscapeLower(want),
                });
            }
            try testing.expectEqualSlices(u8, want, got);
            const got2 = try msg.marshal(allocator);
            try testing.expectEqual(got, got2);
        }
    };

    {
        var msg = try testCreateServerKeyExchangeMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_server_key_exchange_msg);
    }
}

test "ServerKeyExchangeMsg.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ServerKeyExchangeMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data);
            defer msg.deinit(allocator);

            var got = msg.ServerKeyExchange;
            try testing.expectEqualSlices(u8, data, got.raw.?);
            got.raw = null;

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = try testCreateServerKeyExchangeMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_server_key_exchange_msg, &msg);
    }
}

fn testCreateServerKeyExchangeMsg(allocator: mem.Allocator) !ServerKeyExchangeMsg {
    const key = try allocator.dupe(u8, "server key");
    return ServerKeyExchangeMsg{
        .key = key,
    };
}

const test_marshaled_server_key_exchange_msg = "\x0c" ++ // MsgType.ServerKeyExchange
    "\x00\x00\x0a" ++ // u24 msg_len
    "\x73\x65\x72\x76\x65\x72\x20\x6b\x65\x79"; // "server key"

test "ServerHelloDoneMsg.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: *ServerHelloDoneMsg, want: []const u8) !void {
            const got = try msg.marshal(allocator);
            if (!mem.eql(u8, got, want)) {
                std.log.warn("\n got={},\nwant={}\n", .{
                    fmtx.fmtSliceHexEscapeLower(got),
                    fmtx.fmtSliceHexEscapeLower(want),
                });
            }
            try testing.expectEqualSlices(u8, want, got);
            const got2 = try msg.marshal(allocator);
            try testing.expectEqual(got, got2);
        }
    };

    {
        var msg = testCreateServerHelloDoneMsg();
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_server_hello_done_msg);
    }
}

test "ServerHelloDoneMsg.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ServerHelloDoneMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data);
            defer msg.deinit(allocator);

            var got = msg.ServerHelloDone;
            try testing.expectEqualSlices(u8, data, got.raw.?);
            got.raw = null;

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = testCreateServerHelloDoneMsg();
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_server_hello_done_msg, &msg);
    }
}

fn testCreateServerHelloDoneMsg() ServerHelloDoneMsg {
    return ServerHelloDoneMsg{};
}

const test_marshaled_server_hello_done_msg = "\x0e" ++ // MsgType.ServerHelloDone
    "\x00\x00\x00"; // u24 msg_len = 0

test "ClientKeyExchangeMsg.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: *ClientKeyExchangeMsg, want: []const u8) !void {
            const got = try msg.marshal(allocator);
            if (!mem.eql(u8, got, want)) {
                std.log.warn("\n got={},\nwant={}\n", .{
                    fmtx.fmtSliceHexEscapeLower(got),
                    fmtx.fmtSliceHexEscapeLower(want),
                });
            }
            try testing.expectEqualSlices(u8, want, got);
            const got2 = try msg.marshal(allocator);
            try testing.expectEqual(got, got2);
        }
    };

    {
        var msg = try testCreateClientKeyExchangeMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_client_key_exchange_msg);
    }
}

test "ClientKeyExchangeMsg.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ClientKeyExchangeMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data);
            defer msg.deinit(allocator);

            var got = msg.ClientKeyExchange;
            try testing.expectEqualSlices(u8, data, got.raw.?);
            got.raw = null;

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = try testCreateClientKeyExchangeMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_client_key_exchange_msg, &msg);
    }
}

fn testCreateClientKeyExchangeMsg(allocator: mem.Allocator) !ClientKeyExchangeMsg {
    return ClientKeyExchangeMsg{
        .ciphertext = try allocator.dupe(u8, "cipher text"),
    };
}

const test_marshaled_client_key_exchange_msg = "\x10" ++ // MsgType.ClientKeyExchange
    "\x00\x00\x0b" ++ // u24 msg_len
    "\x63\x69\x70\x68\x65\x72\x20\x74\x65\x78\x74"; // "cipher text"

test "FinishedMsg.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: *FinishedMsg, want: []const u8) !void {
            const got = try msg.marshal(allocator);
            if (!mem.eql(u8, got, want)) {
                std.log.warn("\n got={},\nwant={}\n", .{
                    fmtx.fmtSliceHexEscapeLower(got),
                    fmtx.fmtSliceHexEscapeLower(want),
                });
            }
            try testing.expectEqualSlices(u8, want, got);
            const got2 = try msg.marshal(allocator);
            try testing.expectEqual(got, got2);
        }
    };

    {
        var msg = testCreateFinishedMsg();
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_finished_msg);
    }
}

test "FinishedMsg.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *FinishedMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data);
            defer msg.deinit(allocator);

            var got = msg.Finished;
            try testing.expectEqualSlices(u8, data, got.raw.?);
            got.raw = null;

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = testCreateFinishedMsg();
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_finished_msg, &msg);
    }
}

fn testCreateFinishedMsg() FinishedMsg {
    return FinishedMsg{
        .verify_data = "verify data",
    };
}

const test_marshaled_finished_msg = "\x14" ++ // MsgType.Finished
    "\x00\x00\x0b" ++ // u24 msg_len
    "\x76\x65\x72\x69\x66\x79\x20\x64\x61\x74\x61"; // "verify data"
