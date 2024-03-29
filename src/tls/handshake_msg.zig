const std = @import("std");
const assert = std.debug.assert;
const builtin = std.builtin;
const crypto = std.crypto;
const fifo = std.fifo;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;

const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const BytesView = @import("../BytesView.zig");
const memx = @import("../memx.zig");
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
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,
    certificate_status = 22,
    key_update = 24,
    next_protocol = 67, // Not IANA assigned
    message_hash = 254, // synthetic message
    _,
};

pub const random_length = 32;

pub const HandshakeMsg = union(MsgType) {
    hello_request: HelloRequestMsg,
    client_hello: ClientHelloMsg,
    server_hello: ServerHelloMsg,
    new_session_ticket: NewSessionTicketMsg,
    end_of_early_data: EndOfEarlyDataMsg,
    encrypted_extensions: EncryptedExtensionsMsg,
    certificate: CertificateMsg,
    server_key_exchange: ServerKeyExchangeMsg,
    certificate_request: CertificateRequestMsg,
    server_hello_done: ServerHelloDoneMsg,
    certificate_verify: CertificateVerifyMsg,
    client_key_exchange: ClientKeyExchangeMsg,
    finished: FinishedMsg,
    certificate_status: CertificateStatusMsg,
    key_update: KeyUpdateMsg,
    next_protocol: NextProtocolMsg,
    message_hash: MessageHashMsg,

    pub fn deinit(self: *HandshakeMsg, allocator: mem.Allocator) void {
        switch (self.*) {
            .hello_request => |*msg| msg.deinit(allocator),
            .client_hello => |*msg| msg.deinit(allocator),
            .server_hello => |*msg| msg.deinit(allocator),
            .new_session_ticket => |*msg| msg.deinit(allocator),
            .certificate => |*msg| msg.deinit(allocator),
            .server_key_exchange => |*msg| msg.deinit(allocator),
            .server_hello_done => |*msg| msg.deinit(allocator),
            .certificate_verify => |*msg| msg.deinit(allocator),
            .client_key_exchange => |*msg| msg.deinit(allocator),
            .finished => |*msg| msg.deinit(allocator),
            .key_update => |*msg| msg.deinit(allocator),
            else => @panic("not implemented yet"),
        }
    }

    pub fn marshal(self: *HandshakeMsg, allocator: mem.Allocator) ![]const u8 {
        return try switch (self.*) {
            .hello_request => |*msg| msg.marshal(allocator),
            .client_hello => |*msg| msg.marshal(allocator),
            .server_hello => |*msg| msg.marshal(allocator),
            .new_session_ticket => |*msg| msg.marshal(allocator),
            .certificate => |*msg| msg.marshal(allocator),
            .server_key_exchange => |*msg| msg.marshal(allocator),
            .server_hello_done => |*msg| msg.marshal(allocator),
            .certificate_verify => |*msg| msg.marshal(allocator),
            .client_key_exchange => |*msg| msg.marshal(allocator),
            .finished => |*msg| msg.marshal(allocator),
            .key_update => |*msg| msg.marshal(allocator),
            else => @panic("not implemented yet"),
        };
    }

    pub fn unmarshal(
        allocator: mem.Allocator,
        data: []const u8,
        ver: ?ProtocolVersion,
    ) !HandshakeMsg {
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
        std.log.debug("HandshakeMsg.unmarshal msg_type={}", .{msg_type});
        switch (msg_type) {
            .hello_request => return HandshakeMsg{
                .hello_request = try HelloRequestMsg.unmarshal(allocator, msg_data),
            },
            .client_hello => return HandshakeMsg{
                .client_hello = try ClientHelloMsg.unmarshal(allocator, msg_data),
            },
            .server_hello => return HandshakeMsg{
                .server_hello = try ServerHelloMsg.unmarshal(allocator, msg_data),
            },
            .new_session_ticket => return HandshakeMsg{
                .new_session_ticket = try NewSessionTicketMsg.unmarshal(allocator, msg_data, ver.?),
            },
            .encrypted_extensions => return HandshakeMsg{
                .encrypted_extensions = try EncryptedExtensionsMsg.unmarshal(allocator, msg_data),
            },
            .certificate => return HandshakeMsg{
                .certificate = try CertificateMsg.unmarshal(allocator, msg_data, ver.?),
            },
            .certificate_request => return HandshakeMsg{
                .certificate_request = try CertificateRequestMsg.unmarshal(allocator, msg_data, ver.?),
            },
            .server_key_exchange => return HandshakeMsg{
                .server_key_exchange = try ServerKeyExchangeMsg.unmarshal(allocator, msg_data),
            },
            .server_hello_done => return HandshakeMsg{
                .server_hello_done = try ServerHelloDoneMsg.unmarshal(allocator, msg_data),
            },
            .certificate_verify => return HandshakeMsg{
                .certificate_verify = try CertificateVerifyMsg.unmarshal(allocator, msg_data),
            },
            .client_key_exchange => return HandshakeMsg{
                .client_key_exchange = try ClientKeyExchangeMsg.unmarshal(allocator, msg_data),
            },
            .finished => return HandshakeMsg{
                .finished = try FinishedMsg.unmarshal(allocator, msg_data),
            },
            .key_update => return HandshakeMsg{
                .key_update = try KeyUpdateMsg.unmarshal(allocator, msg_data),
            },
            else => @panic("not implemented yet"),
        }
    }
};

pub const handshake_msg_header_len = enumTypeLen(MsgType) + intTypeLen(u24);

const EndOfEarlyDataMsg = void;
const NextProtocolMsg = void;
const MessageHashMsg = void;

pub const ClientHelloMsg = struct {
    raw: []const u8 = "",
    vers: ProtocolVersion = undefined,
    random: []const u8 = undefined,
    session_id: []const u8 = undefined,
    cipher_suites: []const CipherSuiteId,
    compression_methods: []const CompressionMethod,
    server_name: []const u8 = "",
    ocsp_stapling: bool = undefined,
    supported_curves: []const CurveId = &.{},
    supported_points: []const EcPointFormat = &.{},
    ticket_supported: bool = false,
    session_ticket: []const u8 = "",
    supported_signature_algorithms: []const SignatureScheme = &.{},
    supported_signature_algorithms_cert: []const SignatureScheme = &.{},
    secure_renegotiation_supported: bool = false,
    secure_renegotiation: []const u8 = "",
    alpn_protocols: []const []const u8 = &.{},
    scts: bool = false,
    supported_versions: []const ProtocolVersion = &.{},
    cookie: []const u8 = "",
    key_shares: []KeyShare = &.{},
    early_data: bool = false,
    psk_modes: []const PskMode = &.{},
    psk_identities: []PskIdentity = &.{},
    psk_binders: []const []const u8 = &.{},

    pub fn deinit(self: *ClientHelloMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.random);
        allocator.free(self.session_id);
        allocator.free(self.cipher_suites);
        allocator.free(self.compression_methods);
        allocator.free(self.server_name);
        allocator.free(self.supported_curves);
        allocator.free(self.session_ticket);
        allocator.free(self.supported_points);
        allocator.free(self.secure_renegotiation);

        for (self.alpn_protocols) |protocol| allocator.free(protocol);
        allocator.free(self.alpn_protocols);

        allocator.free(self.supported_signature_algorithms);
        allocator.free(self.supported_signature_algorithms_cert);
        allocator.free(self.secure_renegotiation);
        allocator.free(self.supported_versions);
        allocator.free(self.cookie);

        for (self.key_shares) |*key_share| key_share.deinit(allocator);
        allocator.free(self.key_shares);

        allocator.free(self.psk_modes);

        for (self.psk_identities) |*identity| identity.deinit(allocator);
        allocator.free(self.psk_identities);

        for (self.psk_binders) |psk_binder| allocator.free(psk_binder);
        allocator.free(self.psk_binders);
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
        if (self.raw.len > 0) {
            return self.raw;
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

    // marshalWithoutBinders returns the ClientHello through the
    // PreSharedKeyExtension.identities field, according to RFC 8446, Section
    // 4.2.11.2. Note that m.pskBinders must be set to slices of the correct length.
    //
    // The caller must not free the returned memory.
    pub fn marshalWithoutBinders(self: *ClientHelloMsg, allocator: mem.Allocator) ![]const u8 {
        var binders_len: usize = u16_size;
        for (self.psk_binders) |binder| {
            binders_len += u8_size + binder.len;
        }

        const full_message = try self.marshal(allocator);
        return full_message[0 .. full_message.len - binders_len];
    }

    // self takes ownership of psk_binders.
    pub fn updateBinders(
        self: *ClientHelloMsg,
        allocator: mem.Allocator,
        psk_binders: [][]const u8,
    ) !void {
        if (psk_binders.len != self.psk_binders.len) {
            @panic("tls: internal error: pskBinders length mismatch");
        }
        for (self.psk_binders) |self_binder, i| {
            if (psk_binders[i].len != self_binder.len) {
                @panic("tls: internal error: pskBinders length mismatch");
            }
        }
        memx.freeElemsAndFreeSlice([]const u8, self.psk_binders, allocator);
        self.psk_binders = psk_binders;
        allocator.free(self.raw);
        self.raw = "";
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
                .server_name => {
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
                        if (self.server_name.len > 0) {
                            // Multiple names of the same name_type are prohibited.
                            return error.MultipleSameNameTypeServerName;
                        }
                        // An SNI value may not include a trailing dot.
                        if (mem.endsWith(u8, server_name, ".")) {
                            return error.SniWithTrailingDot;
                        }
                        self.server_name = try allocator.dupe(u8, server_name);
                    }
                },
                .status_request => {
                    // RFC 4366, Section 3.6
                    const status_type = try readEnum(CertificateStatusType, bv);
                    // ignore responder_id_list and request_extensions
                    bv.skip(intTypeLen(u16) * 2);
                    self.ocsp_stapling = status_type == .ocsp;
                },
                .supported_curves => {
                    // RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
                    self.supported_curves = try readEnumList(u16, CurveId, allocator, bv);
                },
                .supported_points => {
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
                .session_ticket => {
                    // RFC 5077, Section 3.2
                    self.ticket_supported = true;
                    self.session_ticket = try allocator.dupe(u8, try bv.sliceBytesNoEof(ext_len));
                },
                .signature_algorithms => {
                    // RFC 5246, Section 7.4.1.4.1
                    self.supported_signature_algorithms = try readEnumList(
                        u16,
                        SignatureScheme,
                        allocator,
                        bv,
                    );
                },
                .signature_algorithms_cert => {
                    // RFC 8446, Section 4.2.3
                    self.supported_signature_algorithms_cert = try readEnumList(
                        u16,
                        SignatureScheme,
                        allocator,
                        bv,
                    );
                },
                .renegotiation_info => {
                    // RFC 5746, Section 3.2
                    self.secure_renegotiation = try allocator.dupe(u8, try readString(u8, bv));
                    self.secure_renegotiation_supported = true;
                },
                .alpn => {
                    // RFC 7301, Section 3.1
                    self.alpn_protocols = try readStringList(u16, u8, allocator, bv);
                },
                .sct => {
                    // RFC 6962, Section 3.3.1
                    self.scts = true;
                },
                .supported_versions => {
                    // RFC 8446, Section 4.2.1
                    self.supported_versions = try readEnumList(u8, ProtocolVersion, allocator, bv);
                },
                .cookie => {
                    // RFC 8446, Section 4.2.2
                    const cookie = try readString(u16, bv);
                    if (cookie.len == 0) {
                        return error.EmptyCookie;
                    }
                    self.cookie = try allocator.dupe(u8, cookie);
                },
                .key_share => {
                    // RFC 8446, Section 4.2.
                    self.key_shares = try readKeyShareList(allocator, bv);
                },
                .early_data => {
                    // RFC 8446, Section 4.2.10
                    self.early_data = true;
                },
                .psk_modes => {
                    // RFC 8446, Section 4.2.9
                    self.psk_modes = try readEnumList(u8, PskMode, allocator, bv);
                },
                .pre_shared_key => {
                    // RFC 8446, Section 4.2.11
                    self.psk_identities = try readPskIdentityList(allocator, bv);
                    self.psk_binders = try readNonEmptyStringList(u16, u8, allocator, bv);
                },
                else => bv.skip(ext_len),
            }
        }
    }

    fn writeTo(self: *const ClientHelloMsg, writer: anytype) !void {
        try writeInt(u8, MsgType.client_hello, writer);
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
        if (self.server_name.len > 0) {
            // RFC 6066, Section 3
            try writeInt(u16, ExtensionType.server_name, writer);
            const len2 = intTypeLen(u8) + intTypeLen(u16) + self.server_name.len;
            const len1 = intTypeLen(u16) + len2;
            try writeInt(u16, len1, writer);
            try writeInt(u16, len2, writer);
            try writeInt(u8, 0, writer); // name_type = host_name;
            try writeLenAndBytes(u16, self.server_name, writer);
        }
        if (self.ocsp_stapling) {
            // RFC 4366, Section 3.6
            try writeInt(u16, ExtensionType.status_request, writer);
            try writeBytes("\x00\x05" ++ // u16 length
                "\x01" ++ // status_type = ocsp
                "\x00\x00" ++ // empty responder_id_list
                "\x00\x00", // empty request_extensions
                writer);
        }
        if (self.supported_curves.len > 0) {
            // RFC 4492, sections 5.1.1 and RFC 8446, Section 4.2.7
            try writeInt(u16, ExtensionType.supported_curves, writer);
            try writeLenLenAndIntSlice(u16, u16, u16, CurveId, self.supported_curves, writer);
        }
        if (self.supported_points.len > 0) {
            // RFC 4492, Section 5.1.2
            try writeInt(u16, ExtensionType.supported_points, writer);
            try writeLenLenAndIntSlice(u16, u8, u8, EcPointFormat, self.supported_points, writer);
        }
        if (self.ticket_supported) {
            // RFC 5077, Section 3.2
            try writeInt(u16, ExtensionType.session_ticket, writer);
            try writeLenAndBytes(u16, self.session_ticket, writer);
        }
        if (self.supported_signature_algorithms.len > 0) {
            // RFC 5246, Section 7.4.1.4.1
            try writeInt(u16, ExtensionType.signature_algorithms, writer);
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
            try writeInt(u16, ExtensionType.signature_algorithms_cert, writer);
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
            try writeInt(u16, ExtensionType.renegotiation_info, writer);
            try writeLenLenAndBytes(u16, u8, self.secure_renegotiation, writer);
        }
        if (self.alpn_protocols.len > 0) {
            // RFC 7301, Section 3.1
            try writeInt(u16, ExtensionType.alpn, writer);
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
            try writeInt(u16, ExtensionType.sct, writer);
            try writeInt(u16, 0, writer); // empty extension_data
        }
        if (self.supported_versions.len > 0) {
            // RFC 8446, Section 4.2.1
            try writeInt(u16, ExtensionType.supported_versions, writer);
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
            try writeInt(u16, ExtensionType.cookie, writer);
            try writeLenLenAndBytes(u16, u16, self.cookie, writer);
        }
        if (self.key_shares.len > 0) {
            // RFC 8446, Section 4.2.8
            try writeInt(u16, ExtensionType.key_share, writer);
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
            try writeInt(u16, ExtensionType.early_data, writer);
            try writeInt(u16, 0, writer); // empty extension_data
        }
        if (self.psk_modes.len > 0) {
            // RFC 8446, Section 4.2.9
            try writeInt(u16, ExtensionType.psk_modes, writer);
            try writeLenLenAndIntSlice(u16, u8, u8, PskMode, self.psk_modes, writer);
        }
        if (self.psk_identities.len > 0) { // pre_shared_key must be the last extension
            // RFC 8446, Section 4.2.11
            try writeInt(u16, ExtensionType.pre_shared_key, writer);
            var len2i: usize = 0;
            for (self.psk_identities) |*psk| {
                len2i += intTypeLen(u16) + psk.label.len + intTypeLen(u32);
            }
            var len2b: usize = 0;
            if (self.psk_binders.len > 0) {
                for (self.psk_binders) |binder| {
                    len2b += intTypeLen(u8) + binder.len;
                }
            }
            const len1 = intTypeLen(u16) * 2 + len2i + len2b;
            try writeInt(u16, len1, writer);
            try writeInt(u16, len2i, writer);
            for (self.psk_identities) |*psk| {
                try writeLenAndBytes(u16, psk.label, writer);
                try writeInt(u32, psk.obfuscated_ticket_age, writer);
            }
            try writeInt(u16, len2b, writer);
            if (self.psk_binders.len > 0) {
                for (self.psk_binders) |binder| {
                    try writeLenAndBytes(u8, binder, writer);
                }
            }
        }
    }
};

pub const ServerHelloMsg = struct {
    raw: []const u8 = "",
    vers: ProtocolVersion = undefined,
    random: []const u8 = "",
    session_id: []const u8 = "",
    cipher_suite: ?CipherSuiteId = null,
    compression_method: CompressionMethod,
    ocsp_stapling: bool = undefined,
    ticket_supported: bool = false,
    secure_renegotiation_supported: bool = false,
    secure_renegotiation: []const u8 = "",
    alpn_protocol: []const u8 = "",
    scts: []const []const u8 = &.{},
    supported_version: ?ProtocolVersion = null,
    server_share: ?KeyShare = null,
    selected_identity: ?u16 = null,
    supported_points: []const EcPointFormat = &.{},

    // HelloRetryRequest extensions
    cookie: []const u8 = "",
    selected_group: ?CurveId = null,

    pub fn deinit(self: *ServerHelloMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.random);
        allocator.free(self.session_id);
        allocator.free(self.secure_renegotiation);
        allocator.free(self.alpn_protocol);

        for (self.scts) |sct| allocator.free(sct);
        allocator.free(self.scts);

        if (self.server_share) |*server_share| server_share.deinit(allocator);
        allocator.free(self.supported_points);
        allocator.free(self.cookie);
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !ServerHelloMsg {
        var bv: BytesView = undefined;
        var msg: ServerHelloMsg = blk: {
            const raw = try allocator.dupe(u8, msg_data);
            errdefer allocator.free(raw);
            bv = BytesView.init(raw);
            bv.skip(handshake_msg_header_len);
            const vers = try readEnum(ProtocolVersion, &bv);
            const random = try allocator.dupe(u8, try bv.sliceBytesNoEof(random_length));
            errdefer allocator.free(random);
            const session_id = try allocator.dupe(u8, try readString(u8, &bv));
            errdefer allocator.free(session_id);

            const cipher_suite = try readEnum(CipherSuiteId, &bv);
            const compression_method = try readEnum(CompressionMethod, &bv);

            break :blk ServerHelloMsg{
                .raw = raw,
                .vers = vers,
                .random = random,
                .session_id = session_id,
                .cipher_suite = cipher_suite,
                .compression_method = compression_method,
            };
        };
        errdefer msg.deinit(allocator);

        if (bv.restLen() == 0) {
            return msg;
        }

        try msg.unmarshalExtensions(allocator, &bv);
        return msg;
    }

    pub fn marshal(self: *ServerHelloMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
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
                .status_request => self.ocsp_stapling = true,
                .session_ticket => self.ticket_supported = true,
                .renegotiation_info => {
                    self.secure_renegotiation = try allocator.dupe(u8, try readString(u8, bv));
                    self.secure_renegotiation_supported = true;
                },
                .alpn => {
                    const protos_len = try bv.readIntBig(u16);
                    const protos_end_pos = bv.pos + protos_len;
                    self.alpn_protocol = try allocator.dupe(u8, try readString(u8, bv));
                    if (bv.pos < protos_end_pos) {
                        return error.TooManyProtocols;
                    }
                },
                .sct => self.scts = try readNonEmptyStringList(u16, u16, allocator, bv),
                .supported_versions => self.supported_version = try readEnum(ProtocolVersion, bv),
                .cookie => {
                    const cookie = try readString(u16, bv);
                    if (cookie.len == 0) {
                        return error.EmptyCookie;
                    }
                    self.cookie = try allocator.dupe(u8, cookie);
                },
                .key_share => {
                    // This extension has different formats in SH and HRR, accept either
                    // and let the handshake logic decide. See RFC 8446, Section 4.2.8.
                    if (ext_len == 2) {
                        self.selected_group = try readEnum(CurveId, bv);
                    } else {
                        const group = try readEnum(CurveId, bv);
                        const data = try allocator.dupe(u8, try readString(u16, bv));
                        self.server_share = .{ .group = group, .data = data };
                    }
                },
                .pre_shared_key => self.selected_identity = try bv.readIntBig(u16),
                .supported_points => {
                    std.log.debug("SupportedPoints bytes={}", .{fmtx.fmtSliceHexColonLower(bv.rest())});
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
                else => {
                    // Ignore unknown extensions.
                    bv.skip(ext_len);
                },
            }
        }
    }

    fn writeTo(self: *const ServerHelloMsg, writer: anytype) !void {
        try writeInt(u8, MsgType.server_hello, writer);
        try writeLengthPrefixed(u24, *const ServerHelloMsg, writeBody, self, writer);
    }

    fn writeBody(self: *const ServerHelloMsg, writer: anytype) !void {
        try writeInt(u16, self.vers, writer);
        assert(self.random.len == random_length);
        try writeBytes(self.random, writer);
        try writeLenAndBytes(u8, self.session_id, writer);
        try writeInt(u16, self.cipher_suite.?, writer);
        try writeInt(u8, self.compression_method, writer);

        const ext_len: usize = try countLength(*const ServerHelloMsg, writeExtensions, self);
        if (ext_len > 0) {
            try writeInt(u16, ext_len, writer);
            try self.writeExtensions(writer);
        }
    }

    fn writeExtensions(self: *const ServerHelloMsg, writer: anytype) !void {
        if (self.ocsp_stapling) {
            try writeInt(u16, ExtensionType.status_request, writer);
            const ext_len = 0;
            try writeInt(u16, ext_len, writer); // empty extension_data
        }
        if (self.ticket_supported) {
            try writeInt(u16, ExtensionType.session_ticket, writer);
            const ext_len = 0;
            try writeInt(u16, ext_len, writer); // empty extension_data
        }
        if (self.secure_renegotiation_supported) {
            try writeInt(u16, ExtensionType.renegotiation_info, writer);
            try writeLenLenAndBytes(u16, u8, self.secure_renegotiation, writer);
        }
        if (self.alpn_protocol.len > 0) {
            try writeInt(u16, ExtensionType.alpn, writer);
            const ext_len = intTypeLen(u16) + intTypeLen(u8) + self.alpn_protocol.len;
            try writeInt(u16, ext_len, writer);
            try writeLenLenAndBytes(u16, u8, self.alpn_protocol, writer);
        }
        if (self.scts.len > 0) {
            try writeInt(u16, ExtensionType.sct, writer);
            var scts_len: usize = 0;
            for (self.scts) |sct| {
                scts_len += intTypeLen(u16) + sct.len;
            }
            const ext_len = intTypeLen(u16) + scts_len;
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, scts_len, writer);
            for (self.scts) |sct| {
                try writeLenAndBytes(u16, sct, writer);
            }
        }
        if (self.supported_version) |version| {
            try writeInt(u16, ExtensionType.supported_versions, writer);
            const ext_len = intTypeLen(u16);
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, version, writer);
        }
        if (self.server_share) |key_share| {
            try writeInt(u16, ExtensionType.key_share, writer);
            const ext_len = intTypeLen(u16) * 2 + key_share.data.len;
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, key_share.group, writer);
            try writeLenAndBytes(u16, key_share.data, writer);
        }
        if (self.selected_identity) |selected_identity| {
            try writeInt(u16, ExtensionType.pre_shared_key, writer);
            const ext_len = intTypeLen(u16);
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, selected_identity, writer);
        }
        if (self.cookie.len > 0) {
            try writeInt(u16, ExtensionType.cookie, writer);
            const ext_len = intTypeLen(u16) + self.cookie.len;
            try writeInt(u16, ext_len, writer);
            try writeLenAndBytes(u16, self.cookie, writer);
        }
        if (self.selected_group) |curve| {
            try writeInt(u16, ExtensionType.key_share, writer);
            const ext_len = intTypeLen(u16);
            try writeInt(u16, ext_len, writer);
            try writeInt(u16, curve, writer);
        }
        if (self.supported_points.len > 0) {
            try writeInt(u16, ExtensionType.supported_points, writer);
            const ext_len = intTypeLen(u8) + self.supported_points.len;
            try writeInt(u16, ext_len, writer);
            try writeLenAndIntSlice(u8, u8, EcPointFormat, self.supported_points, writer);
        }
    }
};

pub const CertificateMsg = union(ProtocolVersion) {
    v1_3: CertificateMsgTls13,
    v1_2: CertificateMsgTls12,
    v1_1: void,
    v1_0: void,

    pub fn deinit(self: *CertificateMsg, allocator: mem.Allocator) void {
        switch (self.*) {
            .v1_3 => |*m| m.deinit(allocator),
            .v1_2 => |*m| m.deinit(allocator),
            else => {},
        }
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
        ver: ProtocolVersion,
    ) !CertificateMsg {
        return switch (ver) {
            .v1_3 => CertificateMsg{
                .v1_3 = try CertificateMsgTls13.unmarshal(allocator, msg_data),
            },
            .v1_2 => CertificateMsg{
                .v1_2 = try CertificateMsgTls12.unmarshal(allocator, msg_data),
            },
            else => @panic("unsupported TLS version"),
        };
    }

    pub fn marshal(self: *CertificateMsg, allocator: mem.Allocator) ![]const u8 {
        return switch (self.*) {
            .v1_3 => |*m| try m.marshal(allocator),
            .v1_2 => |*m| try m.marshal(allocator),
            else => @panic("unsupported TLS version"),
        };
    }
};

pub const CertificateMsgTls12 = struct {
    raw: []const u8 = "",
    certificates: []const []const u8 = &.{},

    pub fn deinit(self: *CertificateMsgTls12, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        for (self.certificates) |certificate| allocator.free(certificate);
        allocator.free(self.certificates);
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !CertificateMsgTls12 {
        const raw = try allocator.dupe(u8, msg_data);
        errdefer allocator.free(raw);
        var bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);
        const certificates = try readStringList(u24, u24, allocator, &bv);
        errdefer allocator.free(certificates);

        return CertificateMsgTls12{
            .raw = raw,
            .certificates = certificates,
        };
    }

    pub fn marshal(self: *CertificateMsgTls12, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
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
        try writeInt(u8, MsgType.certificate, writer);
        try writeInt(u24, msg_len, writer);
        try writeInt(u24, certs_len, writer);
        for (self.certificates) |cert| {
            try writeLenAndBytes(u24, cert, writer);
        }
        self.raw = raw;
        return raw;
    }
};

// TLS CertificateStatusType (RFC 3546)
pub const status_type_ocsp: u8 = 1;

pub const CertificateMsgTls13 = struct {
    raw: []const u8 = "",
    cert_chain: CertificateChain,
    ocsp_stapling: bool = false,
    scts: bool = false,

    pub fn deinit(self: *CertificateMsgTls13, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        self.cert_chain.deinit(allocator);
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !CertificateMsgTls13 {
        var bv: BytesView = undefined;
        const raw = try allocator.dupe(u8, msg_data);
        errdefer allocator.free(raw);
        bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);

        const context = try bv.readByte();
        if (context != 0) {
            return error.InvalidCertificateMsgTls12;
        }

        const cert_chain = try CertificateChain.unmarshal(allocator, bv.rest());

        return CertificateMsgTls13{
            .cert_chain = cert_chain,
            .ocsp_stapling = cert_chain.ocsp_staple.len > 0,
            .scts = cert_chain.signed_certificate_timestamps.len != 0,
            .raw = raw,
        };
    }

    pub fn marshal(self: *CertificateMsgTls13, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        const cert_chain = CertificateChain{
            .certificate_chain = self.cert_chain.certificate_chain,
            .ocsp_staple = if (self.ocsp_stapling) self.cert_chain.ocsp_staple else "",
            .signed_certificate_timestamps = if (self.scts)
                self.cert_chain.signed_certificate_timestamps
            else
                &.{},
        };

        var msg_len: usize = u8_size + u24_size + u8_size + cert_chain.marshaledLen();

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var rest_len = msg_len;
        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.certificate, writer);
        rest_len -= u8_size + u24_size;
        try writeInt(u24, rest_len, writer);
        try writeInt(u8, 0, writer); // certificate_request_context
        try cert_chain.writeTo(writer);

        self.raw = raw;
        return raw;
    }
};

pub const CertificateRequestMsg = union(ProtocolVersion) {
    v1_3: CertificateRequestMsgTls13,
    v1_2: CertificateRequestMsgTls12,
    v1_1: void,
    v1_0: void,

    pub fn deinit(self: *CertificateRequestMsg, allocator: mem.Allocator) void {
        switch (self.*) {
            .v1_3 => |*m| m.deinit(allocator),
            .v1_2 => |*m| m.deinit(allocator),
            else => {},
        }
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
        ver: ProtocolVersion,
    ) !CertificateRequestMsg {
        return switch (ver) {
            .v1_3 => CertificateRequestMsg{
                .v1_3 = try CertificateRequestMsgTls13.unmarshal(allocator, msg_data),
            },
            .v1_2 => CertificateRequestMsg{
                .v1_2 = try CertificateRequestMsgTls12.unmarshal(allocator, msg_data),
            },
            else => @panic("unsupported TLS version"),
        };
    }

    pub fn marshal(self: *CertificateRequestMsg, allocator: mem.Allocator) ![]const u8 {
        return switch (self.*) {
            .v1_3 => |*m| try m.marshal(allocator),
            .v1_2 => |*m| try m.marshal(allocator),
            else => @panic("unsupported TLS version"),
        };
    }
};

pub const CertificateRequestMsgTls12 = struct {
    pub const CertificateType = enum(u8) {
        rsa_sign = 1,
        ecdsa_sign = 2,
    };

    raw: []const u8 = "",
    certificate_types: []const CertificateType = &.{},
    supported_signature_algorithms: []const SignatureScheme = &.{},
    certificate_authorities: []const []const u8 = &.{},

    pub fn deinit(self: *CertificateRequestMsgTls12, allocator: mem.Allocator) void {
        allocator.free(self.raw);

        allocator.free(self.certificate_types);
        allocator.free(self.supported_signature_algorithms);

        for (self.certificate_authorities) |auth| allocator.free(auth);
        allocator.free(self.certificate_authorities);
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !CertificateRequestMsgTls12 {
        const raw = try allocator.dupe(u8, msg_data);
        errdefer allocator.free(raw);
        var bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);

        const cert_types = try readEnumList(u8, CertificateType, allocator, &bv);
        errdefer allocator.free(cert_types);

        // CertificateRequestMsgTls12 has always signature algorithms
        const sig_and_algs = try readEnumList(u16, SignatureScheme, allocator, &bv);
        errdefer allocator.free(sig_and_algs);

        var authorities = try readStringList(u16, u16, allocator, &bv);
        errdefer memx.freeElemsAndFreeSlice([]const u8, authorities, allocator);

        if (!bv.empty()) {
            return error.InvalidCertificateRequestMsgTls12;
        }

        return CertificateRequestMsgTls12{
            .raw = raw,
            .certificate_types = cert_types,
            .supported_signature_algorithms = sig_and_algs,
            .certificate_authorities = authorities,
        };
    }

    pub fn marshal(self: *CertificateRequestMsgTls12, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        var msg_len: usize = u8_size + u24_size + u8_size + self.certificate_types.len;
        if (self.supported_signature_algorithms.len > 0) {
            msg_len += u16_size + u16_size * self.supported_signature_algorithms.len;
        }
        var authorities_len: usize = 0;
        if (self.certificate_authorities.len > 0) {
            for (self.certificate_authorities) |auth| {
                authorities_len += u16_size + auth.len;
            }
            msg_len += u16_size + authorities_len;
        }

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var rest_len = msg_len;
        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.certificate_request, writer);
        rest_len -= u8_size + u24_size;
        try writeInt(u24, rest_len, writer);
        // try writeLenAndBytes(u8, self.certificate_types, writer);
        try writeLenAndIntSlice(
            u8,
            u8,
            CertificateType,
            self.certificate_types,
            writer,
        );
        try writeLenAndIntSlice(
            u16,
            u16,
            SignatureScheme,
            self.supported_signature_algorithms,
            writer,
        );
        try writeInt(u16, authorities_len, writer);
        for (self.certificate_authorities) |auth| {
            try writeLenAndBytes(u16, auth, writer);
        }

        self.raw = raw;
        return raw;
    }
};

test "CertificateRequestMsgTls12" {
    const allocator = testing.allocator;

    const msg_data = "\x0d" ++ // index: 0
        "\x00\x00\x25" ++ // index: 1
        "\x02\x01\x02" ++ // index: 4
        "\x00\x06" ++ // index: 7
        "\x08\x04" ++ // index: 9
        "\x04\x03" ++ // index: 11
        "\x08\x07" ++ // index: 13
        "\x00\x18" ++ // index: 15
        "\x00\x0a" ++ // index: 17
        "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x31" ++ // index: 19
        "\x00\x0a" ++ // index: 29
        "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x32"; // index: 31
    var msg = try CertificateRequestMsgTls12.unmarshal(allocator, msg_data);
    defer msg.deinit(allocator);

    const want_certificate_types = &[_]CertificateRequestMsgTls12.CertificateType{
        .rsa_sign, .ecdsa_sign,
    };
    try testing.expectEqualSlices(
        CertificateRequestMsgTls12.CertificateType,
        want_certificate_types,
        msg.certificate_types,
    );
    const want_supported_signature_algorithms = &[_]SignatureScheme{
        .pss_with_sha256,
        .ecdsa_with_p256_and_sha256,
        .ed25519,
    };
    try testing.expectEqual(
        want_supported_signature_algorithms.len,
        msg.supported_signature_algorithms.len,
    );
    for (msg.supported_signature_algorithms) |alg, i| {
        try testing.expectEqual(want_supported_signature_algorithms[i], alg);
    }

    const want_certificate_authorities = &[_][]const u8{
        "authority1",
        "authority2",
    };
    try testing.expectEqual(
        want_certificate_authorities.len,
        msg.certificate_authorities.len,
    );
    for (msg.certificate_authorities) |auth, i| {
        try testing.expectEqualSlices(u8, want_certificate_authorities[i], auth);
    }

    allocator.free(msg.raw);
    msg.raw = "";

    const msg_data2 = try msg.marshal(allocator);
    try testing.expectEqualSlices(u8, msg_data, msg_data2);
}

pub const CertificateRequestMsgTls13 = struct {
    raw: []const u8 = "",
    ocsp_stapling: bool = false,
    scts: bool = false,
    supported_signature_algorithms: []SignatureScheme = &.{},
    supported_signature_algorithms_cert: []SignatureScheme = &.{},
    certificate_authorities: []const []const u8 = &.{},

    pub fn deinit(self: *CertificateRequestMsgTls13, allocator: mem.Allocator) void {
        allocator.free(self.raw);

        allocator.free(self.supported_signature_algorithms);
        allocator.free(self.supported_signature_algorithms_cert);

        for (self.certificate_authorities) |auth| allocator.free(auth);
        allocator.free(self.certificate_authorities);
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !CertificateRequestMsgTls13 {
        var extensions: BytesView = undefined;
        var msg: CertificateRequestMsgTls13 = blk: {
            const raw = try allocator.dupe(u8, msg_data);
            errdefer allocator.free(raw);
            var bv = BytesView.init(raw);
            bv.skip(handshake_msg_header_len);

            const context_len = try bv.readByte();
            if (context_len != 0) {
                return error.InvalidCertificateRequestMsgTls13;
            }

            extensions = BytesView.init(try bv.readLenPrefixedBytes(u16, .Big));
            if (!bv.empty()) {
                return error.InvalidCertificateRequestMsgTls13;
            }

            break :blk CertificateRequestMsgTls13{
                .raw = raw,
            };
        };
        errdefer msg.deinit(allocator);

        while (!extensions.empty()) {
            const ext_type = try extensions.readEnum(ExtensionType, .Big);
            var ext_data = BytesView.init(try extensions.readLenPrefixedBytes(u16, .Big));
            switch (ext_type) {
                .status_request => msg.ocsp_stapling = true,
                .sct => msg.scts = true,
                .signature_algorithms => {
                    var sig_and_algs = BytesView.init(try ext_data.readLenPrefixedBytes(u16, .Big));
                    if (sig_and_algs.empty()) {
                        return error.InvalidCertificateRequestMsgTls13;
                    }
                    const count = sig_and_algs.restLen() / enumTypeLen(SignatureScheme);
                    msg.supported_signature_algorithms = try allocator.alloc(
                        SignatureScheme,
                        count,
                    );
                    var i: usize = 0;
                    while (!sig_and_algs.empty()) : (i += 1) {
                        msg.supported_signature_algorithms[i] =
                            try sig_and_algs.readEnum(SignatureScheme, .Big);
                    }
                },
                .signature_algorithms_cert => {
                    var sig_and_algs = BytesView.init(try ext_data.readLenPrefixedBytes(u16, .Big));
                    if (sig_and_algs.empty()) {
                        return error.InvalidCertificateRequestMsgTls13;
                    }
                    const count = sig_and_algs.restLen() / enumTypeLen(SignatureScheme);
                    msg.supported_signature_algorithms_cert = try allocator.alloc(
                        SignatureScheme,
                        count,
                    );
                    var i: usize = 0;
                    while (!sig_and_algs.empty()) : (i += 1) {
                        msg.supported_signature_algorithms_cert[i] =
                            try sig_and_algs.readEnum(SignatureScheme, .Big);
                    }
                },
                .certificate_authorities => {
                    var auths = BytesView.init(try ext_data.readLenPrefixedBytes(u16, .Big));
                    if (auths.empty()) {
                        return error.InvalidCertificateRequestMsgTls13;
                    }

                    var count: usize = 0;
                    var auths_count = auths;
                    while (!auths_count.empty()) : (count += 1) {
                        const ca = try auths_count.readLenPrefixedBytes(u16, .Big);
                        if (ca.len == 0) {
                            return error.InvalidCertificateRequestMsgTls13;
                        }
                    }

                    var i: usize = 0;
                    var authorities = try allocator.alloc([]const u8, count);
                    errdefer {
                        var j: usize = 0;
                        while (j < i) : (j += 1) {
                            allocator.free(authorities[j]);
                        }
                        allocator.free(authorities);
                    }
                    while (!auths.empty()) : (i += 1) {
                        const ca = try auths.readLenPrefixedBytes(u16, .Big);
                        authorities[i] = try allocator.dupe(u8, ca);
                    }
                    msg.certificate_authorities = authorities;
                },
                else => {
                    // Ignore unknown extensions.
                    continue;
                },
            }

            if (!ext_data.empty()) {
                return error.InvalidCertificateRequestMsgTls13;
            }
        }

        return msg;
    }

    pub fn marshal(self: *CertificateRequestMsgTls13, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        var msg_len: usize = u8_size + u24_size + u8_size + u16_size;
        if (self.ocsp_stapling) {
            msg_len += u16_size * 2;
        }
        if (self.scts) {
            msg_len += u16_size * 2;
        }
        if (self.supported_signature_algorithms.len > 0) {
            msg_len += u16_size * 2 + u16_size + u16_size * self.supported_signature_algorithms.len;
        }
        if (self.supported_signature_algorithms_cert.len > 0) {
            msg_len += u16_size * 2 + u16_size + u16_size * self.supported_signature_algorithms_cert.len;
        }
        var authorities_len: usize = 0;
        if (self.certificate_authorities.len > 0) {
            authorities_len += u16_size * 3;
            for (self.certificate_authorities) |auth| {
                authorities_len += u16_size + auth.len;
            }
            msg_len += authorities_len;
        }

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var rest_len = msg_len;
        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.certificate_request, writer);
        rest_len -= u8_size + u24_size;
        try writeInt(u24, rest_len, writer);
        try writeInt(u8, 0, writer); // context_len
        rest_len -= u8_size + u16_size;
        try writeInt(u16, rest_len, writer); // extensions_len
        if (self.ocsp_stapling) {
            try writeInt(u16, ExtensionType.status_request, writer);
            try writeInt(u16, 0, writer);
        }
        if (self.scts) {
            try writeInt(u16, ExtensionType.sct, writer);
            try writeInt(u16, 0, writer);
        }
        if (self.supported_signature_algorithms.len > 0) {
            try writeInt(u16, ExtensionType.signature_algorithms, writer);
            try writeInt(u16, u16_size + u16_size * self.supported_signature_algorithms.len, writer);
            try writeInt(u16, u16_size * self.supported_signature_algorithms.len, writer);
            for (self.supported_signature_algorithms) |alg| {
                try writeInt(u16, alg, writer);
            }
        }
        if (self.supported_signature_algorithms_cert.len > 0) {
            try writeInt(u16, ExtensionType.signature_algorithms_cert, writer);
            try writeInt(u16, u16_size + u16_size * self.supported_signature_algorithms_cert.len, writer);
            try writeInt(u16, u16_size * self.supported_signature_algorithms_cert.len, writer);
            for (self.supported_signature_algorithms_cert) |alg| {
                try writeInt(u16, alg, writer);
            }
        }
        if (self.certificate_authorities.len > 0) {
            try writeInt(u16, ExtensionType.certificate_authorities, writer);
            authorities_len -= u16_size * 2;
            try writeInt(u16, authorities_len, writer);
            try writeInt(u16, authorities_len - u16_size, writer);
            for (self.certificate_authorities) |auth| {
                try writeInt(u16, auth.len, writer);
                try writeBytes(auth, writer);
            }
        }

        self.raw = raw;
        return raw;
    }
};

test "CertificateRequestMsgTls13" {
    const allocator = testing.allocator;

    const msg_data = "\x0d" ++ // index: 0
        "\x00\x00\x41" ++ // index: 1
        "\x00" ++ // index: 4
        "\x00\x3e" ++ // index: 5, extensions_len
        "\x00\x05" ++ // index: 7, ExtensionType.StatusRequest
        "\x00\x00" ++ // index: 9
        "\x00\x12" ++ // index: 11, ExtensionType.Sct
        "\x00\x00" ++ // index: 13
        "\x00\x0d" ++ // index: 15, ExtensionType.SignatureAlgorithms
        "\x00\x08" ++ // index: 17
        "\x00\x06" ++ // index: 19
        "\x08\x04" ++ // index: 21
        "\x04\x03" ++ // index: 23
        "\x08\x07" ++ // index: 25
        "\x00\x32" ++ // index: 27, ExtensionType.SignatureAlgorithmsCert
        "\x00\x08" ++ // index: 29
        "\x00\x06" ++ // index: 31
        "\x08\x04" ++ // index: 33
        "\x04\x03" ++ // index: 35
        "\x08\x07" ++ // index: 37
        "\x00\x2f" ++ // index: 39, ExtensionType: CertificateAuthorities
        "\x00\x1a" ++ // index: 41
        "\x00\x18" ++ // index: 43
        "\x00\x0a" ++ // index: 45
        "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x31" ++ // index: 47
        "\x00\x0a" ++ // index: 57
        "\x61\x75\x74\x68\x6f\x72\x69\x74\x79\x32"; // index: 59
    var msg = try CertificateRequestMsgTls13.unmarshal(allocator, msg_data);
    defer msg.deinit(allocator);

    try testing.expect(msg.ocsp_stapling);
    try testing.expect(msg.scts);
    const want_supported_signature_algorithms = &[_]SignatureScheme{
        .pss_with_sha256,
        .ecdsa_with_p256_and_sha256,
        .ed25519,
    };
    try testing.expectEqual(
        want_supported_signature_algorithms.len,
        msg.supported_signature_algorithms.len,
    );
    for (msg.supported_signature_algorithms) |alg, i| {
        try testing.expectEqual(want_supported_signature_algorithms[i], alg);
    }

    const want_supported_signature_algorithms_cert = &[_]SignatureScheme{
        .pss_with_sha256,
        .ecdsa_with_p256_and_sha256,
        .ed25519,
    };
    try testing.expectEqual(
        want_supported_signature_algorithms_cert.len,
        msg.supported_signature_algorithms_cert.len,
    );
    for (msg.supported_signature_algorithms_cert) |alg, i| {
        try testing.expectEqual(want_supported_signature_algorithms_cert[i], alg);
    }

    const want_certificate_authorities = &[_][]const u8{
        "authority1",
        "authority2",
    };
    try testing.expectEqual(
        want_certificate_authorities.len,
        msg.certificate_authorities.len,
    );
    for (msg.certificate_authorities) |auth, i| {
        try testing.expectEqualSlices(u8, want_certificate_authorities[i], auth);
    }

    allocator.free(msg.raw);
    msg.raw = "";

    const msg_data2 = try msg.marshal(allocator);
    try testing.expectEqualSlices(u8, msg_data, msg_data2);
}

pub const ServerKeyExchangeMsg = struct {
    raw: []const u8 = "",
    key: []const u8,

    pub fn deinit(self: *ServerKeyExchangeMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.key);
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
        if (self.raw.len > 0) {
            return self.raw;
        }

        const body_len = self.key.len;
        const msg_len = handshake_msg_header_len + body_len;
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.server_key_exchange, writer);
        try writeLenAndBytes(u24, self.key, writer);
        self.raw = raw;
        return raw;
    }
};

pub const CertificateStatusMsg = struct {
    raw: []const u8 = "",
    response: []const u8 = "",

    pub fn deinit(self: *CertificateStatusMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.response);
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
    ) !CertificateStatusMsg {
        const raw = try allocator.dupe(u8, msg_data);
        var bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);

        const status_type = try bv.readByte();
        if (status_type != status_type_ocsp) {
            return error.InvalidCertificateStatusMsg;
        }

        const response = try allocator.dupe(u8, try bv.readLenPrefixedBytes(u24, .Big));
        errdefer allocator.free(response);

        if (response.len == 0 or !bv.empty()) {
            return error.InvalidCertificateStatusMsg;
        }

        return CertificateStatusMsg{
            .raw = raw,
            .response = response,
        };
    }

    pub fn marshal(self: *CertificateStatusMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        const msg_len = u8_size + u24_size + u8_size + u24_size + self.response.len;

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();

        try writeInt(u8, MsgType.certificate_status, writer);
        var rest_len = msg_len - u8_size - u24_size;
        try writeInt(u24, rest_len, writer);
        try writeInt(u8, status_type_ocsp, writer);
        try writeLenAndBytes(u24, self.response, writer);

        self.raw = raw;
        return raw;
    }
};

test "CertificateStatusMsg.marshal" {
    const allocator = testing.allocator;

    var msg = CertificateStatusMsg{
        .response = "response",
    };

    const marshaled = try msg.marshal(allocator);
    defer allocator.free(marshaled);

    const want = "\x16\x00\x00\x0c\x01\x00\x00\x08\x72\x65\x73\x70\x6f\x6e\x73\x65";
    try testing.expectEqualSlices(u8, want, marshaled);

    var msg2 = try CertificateStatusMsg.unmarshal(allocator, marshaled);
    defer msg2.deinit(allocator);

    try testing.expectEqualSlices(u8, msg.response, msg2.response);
}

pub const ServerHelloDoneMsg = struct {
    raw: []const u8 = "",

    pub fn deinit(self: *ServerHelloDoneMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
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
        if (self.raw.len > 0) {
            return self.raw;
        }

        const raw_len = handshake_msg_header_len;
        var raw = try allocator.alloc(u8, raw_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.server_hello_done, writer);
        try writeInt(u24, 0, writer);
        self.raw = raw;
        return raw;
    }
};

pub const ClientKeyExchangeMsg = struct {
    raw: []const u8 = "",
    ciphertext: []const u8 = "",

    pub fn deinit(self: *ClientKeyExchangeMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.ciphertext);
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
        if (self.raw.len > 0) {
            return self.raw;
        }

        const body_len = self.ciphertext.len;
        const msg_len = handshake_msg_header_len + body_len;
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.client_key_exchange, writer);
        try writeLenAndBytes(u24, self.ciphertext, writer);
        self.raw = raw;
        return raw;
    }
};

pub const FinishedMsg = struct {
    raw: []const u8 = "",
    verify_data: []const u8 = "",

    pub fn deinit(self: *FinishedMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.verify_data);
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !FinishedMsg {
        const raw = try allocator.dupe(u8, msg_data);
        var bv = BytesView.init(raw);
        bv.skip(enumTypeLen(MsgType));
        const verify_data = try allocator.dupe(u8, try readString(u24, &bv));

        return FinishedMsg{
            .raw = raw,
            .verify_data = verify_data,
        };
    }

    pub fn marshal(self: *FinishedMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        const body_len = self.verify_data.len;
        const msg_len = handshake_msg_header_len + body_len;
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.finished, writer);
        try writeLenAndBytes(u24, self.verify_data, writer);
        self.raw = raw;
        return raw;
    }
};

pub const NewSessionTicketMsg = union(ProtocolVersion) {
    v1_3: NewSessionTicketMsgTls13,
    v1_2: NewSessionTicketMsgTls12,
    v1_1: void,
    v1_0: void,

    pub fn deinit(self: *NewSessionTicketMsg, allocator: mem.Allocator) void {
        switch (self.*) {
            .v1_3 => |*m| m.deinit(allocator),
            .v1_2 => |*m| m.deinit(allocator),
            else => {},
        }
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
        ver: ProtocolVersion,
    ) !NewSessionTicketMsg {
        return switch (ver) {
            .v1_3 => NewSessionTicketMsg{
                .v1_3 = try NewSessionTicketMsgTls13.unmarshal(allocator, msg_data),
            },
            .v1_2 => NewSessionTicketMsg{
                .v1_2 = try NewSessionTicketMsgTls12.unmarshal(allocator, msg_data),
            },
            else => @panic("unsupported TLS version"),
        };
    }

    pub fn marshal(self: *NewSessionTicketMsg, allocator: mem.Allocator) ![]const u8 {
        return switch (self.*) {
            .v1_3 => |*m| try m.marshal(allocator),
            .v1_2 => |*m| try m.marshal(allocator),
            else => @panic("unsupported TLS version"),
        };
    }
};

pub const NewSessionTicketMsgTls12 = struct {
    raw: []const u8 = "",
    ticket: []const u8 = "",

    pub fn deinit(self: *NewSessionTicketMsgTls12, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.ticket);
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
    ) !NewSessionTicketMsgTls12 {
        const raw = try allocator.dupe(u8, msg_data);
        var bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len + u32_size);

        const ticket = try allocator.dupe(u8, try bv.readLenPrefixedBytes(u16, .Big));
        errdefer allocator.free(ticket);

        return NewSessionTicketMsgTls12{
            .raw = raw,
            .ticket = ticket,
        };
    }

    pub fn marshal(self: *NewSessionTicketMsgTls12, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        const msg_len = u8_size + u24_size + u32_size + u16_size + self.ticket.len;

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();

        try writeInt(u8, MsgType.new_session_ticket, writer);
        var rest_len = msg_len - u8_size - u24_size;
        try writeInt(u24, rest_len, writer);
        try writeInt(u32, 0, writer); // ticket_lifetime_hint
        try writeLenAndBytes(u16, self.ticket, writer);

        self.raw = raw;
        return raw;
    }
};

test "NewSessionTicketMsgTls12.marshal" {
    const allocator = testing.allocator;

    var msg = NewSessionTicketMsgTls12{
        .ticket = "ticket",
    };

    const marshaled = try msg.marshal(allocator);
    defer allocator.free(marshaled);

    const want = "\x04\x00\x00\x0c\x00\x00\x00\x00\x00\x06\x74\x69\x63\x6b\x65\x74";
    try testing.expectEqualSlices(u8, want, marshaled);

    var msg2 = try NewSessionTicketMsgTls12.unmarshal(allocator, marshaled);
    defer msg2.deinit(allocator);

    try testing.expectEqualSlices(u8, msg.ticket, msg2.ticket);
}

pub const NewSessionTicketMsgTls13 = struct {
    raw: []const u8 = "",
    lifetime: u32 = 0,
    age_add: u32 = 0,
    nonce: []const u8 = "",
    label: []const u8 = "",
    max_early_data: u32 = 0,

    pub fn deinit(self: *NewSessionTicketMsgTls13, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.nonce);
        allocator.free(self.label);
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
    ) !NewSessionTicketMsgTls13 {
        const raw = try allocator.dupe(u8, msg_data);
        var bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);

        const lifetime = try bv.readIntBig(u32);
        const age_add = try bv.readIntBig(u32);
        const nonce = try allocator.dupe(u8, try bv.readLenPrefixedBytes(u8, .Big));
        errdefer allocator.free(nonce);
        const label = try allocator.dupe(u8, try bv.readLenPrefixedBytes(u16, .Big));
        errdefer allocator.free(label);
        var extensions = BytesView.init(try bv.readLenPrefixedBytes(u16, .Big));
        if (!bv.empty()) {
            return error.InvalidNewSessionTicketMsgTls13;
        }

        var max_early_data: u32 = 0;
        while (!extensions.empty()) {
            const ext_type = try extensions.readEnum(ExtensionType, .Big);
            var ext_data = BytesView.init(try extensions.readLenPrefixedBytes(u16, .Big));
            switch (ext_type) {
                .early_data => max_early_data = try ext_data.readIntBig(u32),
                else => continue,
            }

            if (!ext_data.empty()) {
                return error.InvalidNewSessionTicketMsgTls13;
            }
        }

        return NewSessionTicketMsgTls13{
            .raw = raw,
            .lifetime = lifetime,
            .age_add = age_add,
            .nonce = nonce,
            .label = label,
            .max_early_data = max_early_data,
        };
    }

    pub fn marshal(self: *NewSessionTicketMsgTls13, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        const early_data_len = if (self.max_early_data > 0)
            u16_size * 2 + u32_size
        else
            @as(usize, 0);
        const msg_len = u8_size + u24_size + u32_size * 2 + u8_size + self.nonce.len +
            u16_size + self.label.len +
            u16_size + early_data_len;

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();

        try writeInt(u8, MsgType.new_session_ticket, writer);
        var rest_len = msg_len - u8_size - u24_size;
        try writeInt(u24, rest_len, writer);
        try writeInt(u32, self.lifetime, writer);
        try writeInt(u32, self.age_add, writer);
        try writeLenAndBytes(u8, self.nonce, writer);
        try writeLenAndBytes(u16, self.label, writer);
        try writeInt(u16, early_data_len, writer);
        if (self.max_early_data > 0) {
            try writeInt(u16, ExtensionType.early_data, writer);
            try writeInt(u16, u32_size, writer);
            try writeInt(u32, self.max_early_data, writer);
        }

        self.raw = raw;
        return raw;
    }
};

test "NewSessionTicketMsgTls13.marshal" {
    const allocator = testing.allocator;

    var msg = NewSessionTicketMsgTls13{
        .lifetime = 0x12345678,
        .age_add = 0x33445566,
        .nonce = "nonce",
        .label = "label",
        .max_early_data = 0xffeeddcc,
    };

    const marshaled = try msg.marshal(allocator);
    defer allocator.free(marshaled);

    const want = "\x04\x00\x00\x1f\x12\x34\x56\x78\x33\x44\x55\x66\x05\x6e\x6f\x6e\x63\x65\x00\x05\x6c\x61\x62\x65\x6c\x00\x08\x00\x2a\x00\x04\xff\xee\xdd\xcc";
    try testing.expectEqualSlices(u8, want, marshaled);

    var msg2 = try NewSessionTicketMsgTls13.unmarshal(allocator, marshaled);
    defer msg2.deinit(allocator);

    try testing.expectEqual(msg.lifetime, msg2.lifetime);
    try testing.expectEqual(msg.age_add, msg2.age_add);
    try testing.expectEqualSlices(u8, msg.nonce, msg2.nonce);
    try testing.expectEqualSlices(u8, msg.label, msg2.label);
    try testing.expectEqual(msg.max_early_data, msg2.max_early_data);
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

    _,
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
    _,

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

    pub fn isSupported(id: CurveId) bool {
        return switch (id) {
            .secp256r1, .x25519 => true,
            .secp384r1, .secp521r1 => @panic("not implmented yet"),
            else => false,
        };
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
    data: []const u8 = "",

    pub fn deinit(self: *KeyShare, allocator: mem.Allocator) void {
        allocator.free(self.data);
    }
};

// TLS 1.3 PSK Key Exchange Modes. See RFC 8446, Section 4.2.9.
pub const PskMode = enum(u8) {
    plain = 0,
    dhe = 1,
};

// TLS 1.3 PSK Identity. Can be a Session Ticket, or a reference to a saved
// session. See RFC 8446, Section 4.2.11.
pub const PskIdentity = struct {
    label: []const u8 = "",
    obfuscated_ticket_age: u32,

    pub fn deinit(self: *PskIdentity, allocator: mem.Allocator) void {
        allocator.free(self.label);
    }
};

// TLS compression types.
pub const CompressionMethod = enum(u8) {
    none = 0,
};

// TLS extension numbers
pub const ExtensionType = enum(u16) {
    server_name = 0,
    status_request = 5,
    supported_curves = 10, // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
    supported_points = 11,
    signature_algorithms = 13,
    alpn = 16,
    sct = 18,
    session_ticket = 35,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_modes = 45,
    certificate_authorities = 47,
    signature_algorithms_cert = 50,
    key_share = 51,
    renegotiation_info = 0xff01,
    _,
};

pub fn readStringList(
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
    errdefer {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            allocator.free(list[i]);
        }
        allocator.free(list);
    }
    n = 0;
    while (bv.pos < end_pos) {
        list[n] = try allocator.dupe(u8, try readString(LenType2, bv));
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
    errdefer {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            allocator.free(list[i]);
        }
        allocator.free(list);
    }
    n = 0;
    while (bv.pos < end_pos) {
        list[n] = try allocator.dupe(u8, try readString(LenType2, bv));
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

fn readKeyShareList(allocator: mem.Allocator, bv: *BytesView) ![]KeyShare {
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
        const data = try allocator.dupe(u8, try readString(u16, bv));
        values[i] = .{ .group = group, .data = data };
    }
    return values;
}

fn readPskIdentityList(allocator: mem.Allocator, bv: *BytesView) ![]PskIdentity {
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
    var i: usize = 0;
    errdefer memx.deinitElemsAndFreeSliceInError(PskIdentity, values, allocator, i);
    while (i < n) : (i += 1) {
        const label = try allocator.dupe(u8, try readString(u16, bv));
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

pub fn writeLenAndBytes(comptime LenType: type, bytes: []const u8, writer: anytype) !void {
    try writeInt(LenType, bytes.len, writer);
    try writeBytes(bytes, writer);
}

pub fn writeBytes(bytes: []const u8, writer: anytype) !void {
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
    return @divExact(@typeInfo(IntType).Int.bits, @bitSizeOf(u8));
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

pub fn writeInt(comptime T: type, val: anytype, writer: anytype) !void {
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
    random.bytes(random_bytes[0..random_length]);
    return random_bytes[0..random_length];
}

pub const u8_size = @divExact(@typeInfo(u8).Int.bits, @bitSizeOf(u8));
pub const u16_size = @divExact(@typeInfo(u16).Int.bits, @bitSizeOf(u8));
pub const u24_size = @divExact(@typeInfo(u24).Int.bits, @bitSizeOf(u8));
pub const u32_size = @divExact(@typeInfo(u32).Int.bits, @bitSizeOf(u8));

pub const EncryptedExtensionsMsg = struct {
    raw: []const u8 = "",
    alpn_protocol: []const u8 = "",

    pub fn deinit(self: *EncryptedExtensionsMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.alpn_protocol);
    }

    fn unmarshal(allocator: mem.Allocator, msg_data: []const u8) !EncryptedExtensionsMsg {
        var bv: BytesView = undefined;
        const raw = try allocator.dupe(u8, msg_data);
        errdefer allocator.free(raw);
        bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);

        const extensions_len = try bv.readIntBig(u16);
        try bv.ensureRestLen(extensions_len);
        const extensions_end_pos = bv.pos + extensions_len;
        var alpn_protocol: []const u8 = "";
        errdefer if (alpn_protocol.len > 0) allocator.free(alpn_protocol);
        while (bv.pos < extensions_end_pos) {
            const ext_type = try readEnum(ExtensionType, &bv);
            const ext_len = try bv.readIntBig(u16);
            try bv.ensureRestLen(ext_len);
            switch (ext_type) {
                .alpn => {
                    const proto_list_len = try bv.readIntBig(u16);
                    try bv.ensureRestLen(proto_list_len);
                    if (bv.restLen() != proto_list_len) {
                        return error.InvalidEncryptedExtensionsMessage;
                    }
                    alpn_protocol = try allocator.dupe(u8, try readString(u8, &bv));
                },
                else => bv.skip(ext_len),
            }
        }

        return EncryptedExtensionsMsg{
            .raw = raw,
            .alpn_protocol = alpn_protocol,
        };
    }

    pub fn marshal(self: *EncryptedExtensionsMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        var msg_len: usize = u8_size + u24_size + u16_size;
        if (self.alpn_protocol.len > 0) {
            msg_len += u16_size * 3 + u8_size + self.alpn_protocol.len;
        }

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var rest_len = msg_len;
        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.encrypted_extensions, writer);
        rest_len -= u8_size + u24_size;
        try writeInt(u24, rest_len, writer);
        rest_len -= u16_size;
        try writeInt(u16, rest_len, writer);
        if (self.alpn_protocol.len > 0) {
            try writeInt(u16, ExtensionType.alpn, writer);
            rest_len -= u16_size * 2;
            try writeInt(u16, rest_len, writer);
            rest_len -= u16_size;
            try writeInt(u16, rest_len, writer);
            rest_len -= u8_size;
            try writeInt(u8, rest_len, writer);
            try writeBytes(self.alpn_protocol, writer);
        }

        self.raw = raw;
        return raw;
    }
};

pub const CertificateVerifyMsg = struct {
    raw: []const u8 = "",
    signature_algorithm: SignatureScheme = undefined,
    signature: []const u8 = "",

    pub fn deinit(self: *CertificateVerifyMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.signature);
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
    ) !CertificateVerifyMsg {
        var bv: BytesView = undefined;
        const raw = try allocator.dupe(u8, msg_data);
        errdefer allocator.free(raw);
        bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);

        const signature_algorithm = try readEnum(SignatureScheme, &bv);
        const signature = try allocator.dupe(u8, try readString(u16, &bv));

        return CertificateVerifyMsg{
            .signature_algorithm = signature_algorithm,
            .signature = signature,
            .raw = raw,
        };
    }

    pub fn marshal(self: *CertificateVerifyMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        var msg_len: usize = u8_size + u24_size + u16_size +
            u16_size + self.signature.len;

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var rest_len = msg_len;
        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.certificate_verify, writer);
        rest_len -= u8_size + u24_size;
        try writeInt(u24, rest_len, writer);
        try writeInt(u16, self.signature_algorithm, writer);
        try writeInt(u16, self.signature.len, writer);
        try writeBytes(self.signature, writer);

        self.raw = raw;
        return raw;
    }
};

pub const KeyUpdateMsg = struct {
    raw: []const u8 = "",
    update_requested: bool = false,

    pub fn deinit(self: *KeyUpdateMsg, allocator: mem.Allocator) void {
        allocator.free(self.raw);
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
    ) !KeyUpdateMsg {
        var bv: BytesView = undefined;
        const raw = try allocator.dupe(u8, msg_data);
        errdefer allocator.free(raw);
        bv = BytesView.init(raw);
        bv.skip(handshake_msg_header_len);

        const update_requested = try bv.readByte();
        if (!bv.empty() or (update_requested != 0 and update_requested != 1)) {
            return error.InvalidKeyUpdateMsg;
        }

        return KeyUpdateMsg{
            .raw = raw,
            .update_requested = (update_requested == 1),
        };
    }

    pub fn marshal(self: *KeyUpdateMsg, allocator: mem.Allocator) ![]const u8 {
        if (self.raw.len > 0) {
            return self.raw;
        }

        const msg_len: usize = u8_size + u24_size + u8_size;
        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);

        var fbs = io.fixedBufferStream(raw);
        var writer = fbs.writer();
        try writeInt(u8, MsgType.key_update, writer);
        try writeInt(u24, 1, writer);
        try writeInt(u8, @as(u8, if (self.update_requested) 1 else 0), writer);

        self.raw = raw;
        return raw;
    }
};

pub const HelloRequestMsg = struct {
    pub fn deinit(self: *HelloRequestMsg, allocator: mem.Allocator) void {
        _ = self;
        _ = allocator;
    }

    fn unmarshal(
        allocator: mem.Allocator,
        msg_data: []const u8,
    ) !HelloRequestMsg {
        _ = allocator;
        if (msg_data.len != handshake_msg_header_len) {
            return error.InvalidHelloRequestMsg;
        }
        return HelloRequestMsg{};
    }

    pub fn marshal(self: *KeyUpdateMsg, allocator: mem.Allocator) ![]const u8 {
        _ = self;
        _ = allocator;
        return &[_]u8{ MsgType.hello_request, 0, 0, 0 };
    }
};

const testing = std.testing;

test "KeyUpdateMsg.marshal" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    var msg = KeyUpdateMsg{ .update_requested = true };
    const got = try msg.marshal(allocator);
    defer allocator.free(got);

    const want = "\x18\x00\x00\x01\x01";
    try testing.expectEqualSlices(u8, want, got);

    var msg2 = try KeyUpdateMsg.unmarshal(allocator, want);
    defer msg2.deinit(allocator);

    try testing.expectEqual(msg.update_requested, msg2.update_requested);
}

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
    testing.log_level = .err;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ClientHelloMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data, null);
            defer msg.deinit(allocator);

            var got = msg.client_hello;
            try testing.expectEqualSlices(u8, data, got.raw);
            got.raw = "";

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
    const server_name = try allocator.dupe(u8, "example.com");
    errdefer allocator.free(server_name);
    const supported_curves = try allocator.dupe(CurveId, &[_]CurveId{.x25519});
    errdefer allocator.free(supported_curves);
    const supported_points = try allocator.dupe(
        EcPointFormat,
        &[_]EcPointFormat{.uncompressed},
    );
    errdefer allocator.free(supported_points);
    const session_ticket = try allocator.dupe(u8, "\x12\x34\x56\x78");
    errdefer allocator.free(session_ticket);
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
    const protocol1 = try allocator.dupe(u8, "http/1.1");
    errdefer allocator.free(protocol1);
    const protocol2 = try allocator.dupe(u8, "spdy/1");
    errdefer allocator.free(protocol2);
    const alpn_protocols = try allocator.dupe(
        []const u8,
        &[_][]const u8{ protocol1, protocol2 },
    );
    errdefer allocator.free(alpn_protocols);
    const supported_versions = try allocator.dupe(
        ProtocolVersion,
        &[_]ProtocolVersion{ .v1_3, .v1_2 },
    );
    errdefer allocator.free(supported_versions);
    const cookie = try allocator.dupe(u8, "my cookie");
    errdefer allocator.free(cookie);
    var key_share_data = try allocator.dupe(u8, "public key here");
    errdefer allocator.free(key_share_data);
    const key_shares = try allocator.dupe(
        KeyShare,
        &[_]KeyShare{.{ .group = .x25519, .data = key_share_data }},
    );
    errdefer allocator.free(key_shares);
    const psk_modes = try allocator.dupe(
        PskMode,
        &[_]PskMode{ .plain, .dhe },
    );
    errdefer allocator.free(psk_modes);

    const psk_identities = blk_identities: {
        const psk_identity_label = try allocator.dupe(u8, "my id 1");
        errdefer allocator.free(psk_identity_label);
        break :blk_identities try allocator.dupe(
            PskIdentity,
            &[_]PskIdentity{.{ .label = psk_identity_label, .obfuscated_ticket_age = 0x778899aa }},
        );
    };
    errdefer memx.deinitSliceAndElems(PskIdentity, psk_identities, allocator);

    const psk_binders = blk_binders: {
        const binder1 = try allocator.dupe(u8, "binder1");
        errdefer allocator.free(binder1);
        const binder2 = try allocator.dupe(u8, "binder2");
        errdefer allocator.free(binder2);
        break :blk_binders try allocator.dupe(
            []const u8,
            &[_][]const u8{ binder1, binder2 },
        );
    };
    errdefer memx.freeElemsAndFreeSlice([]const u8, psk_binders, allocator);

    return ClientHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = session_id,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
        .server_name = server_name,
        .ocsp_stapling = true,
        .supported_curves = supported_curves,
        .supported_points = supported_points,
        .ticket_supported = true,
        .session_ticket = session_ticket,
        .supported_signature_algorithms = supported_signature_algorithms,
        .supported_signature_algorithms_cert = supported_signature_algorithms_cert,
        .secure_renegotiation_supported = true,
        .secure_renegotiation = "",
        .alpn_protocols = alpn_protocols,
        .scts = true,
        .supported_versions = supported_versions,
        .cookie = cookie,
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
    testing.log_level = .err;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ServerHelloMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data, null);
            defer msg.deinit(allocator);

            var got = msg.server_hello;
            try testing.expectEqualSlices(u8, data, got.raw);
            got.raw = "";

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
    const session_id = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(session_id);
    return ServerHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = session_id,
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
    const session_id = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(session_id);
    const sct1 = try allocator.dupe(u8, "sct1");
    errdefer allocator.free(sct1);
    const sct2 = try allocator.dupe(u8, "sct2");
    errdefer allocator.free(sct2);
    const scts = try allocator.dupe(
        []const u8,
        &[_][]const u8{ sct1, sct2 },
    );
    errdefer allocator.free(scts);
    const supported_points = try allocator.dupe(
        EcPointFormat,
        &[_]EcPointFormat{.uncompressed},
    );
    errdefer allocator.free(supported_points);
    const secure_renegotiation = try allocator.dupe(u8, "renegoation");
    errdefer allocator.free(secure_renegotiation);
    const alpn_protocol = try allocator.dupe(u8, "http/1.1");
    errdefer allocator.free(alpn_protocol);
    const key_share_data = try allocator.dupe(u8, "public key here");
    errdefer allocator.free(key_share_data);
    return ServerHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = session_id,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .compression_method = .none,
        .ocsp_stapling = true,
        .ticket_supported = true,
        .secure_renegotiation_supported = true,
        .secure_renegotiation = secure_renegotiation,
        .alpn_protocol = alpn_protocol,
        .scts = scts,
        .supported_version = .v1_3,
        .server_share = .{ .group = .x25519, .data = key_share_data },
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
    const session_id = try allocator.dupe(u8, &[_]u8{0} ** 32);
    errdefer allocator.free(session_id);
    const sct1 = try allocator.dupe(u8, "sct1");
    errdefer allocator.free(sct1);
    const sct2 = try allocator.dupe(u8, "sct2");
    errdefer allocator.free(sct2);
    const scts = try allocator.dupe(
        []const u8,
        &[_][]const u8{ sct1, sct2 },
    );
    errdefer allocator.free(scts);
    const alpn_protocol = try allocator.dupe(u8, "http/1.1");
    errdefer allocator.free(alpn_protocol);
    const key_share_data = try allocator.dupe(u8, "public key here");
    errdefer allocator.free(key_share_data);
    const supported_points = try allocator.dupe(
        EcPointFormat,
        &[_]EcPointFormat{.uncompressed},
    );
    errdefer allocator.free(supported_points);
    return ServerHelloMsg{
        .vers = .v1_3,
        .random = random,
        .session_id = session_id,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .compression_method = .none,
        .ocsp_stapling = true,
        .ticket_supported = true,
        .secure_renegotiation_supported = true,
        .secure_renegotiation = "",
        .alpn_protocol = alpn_protocol,
        .scts = scts,
        .supported_version = .v1_3,
        .server_share = .{ .group = .x25519, .data = key_share_data },
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

test "CertificateMsgTls12.marshal" {
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(msg: *CertificateMsgTls12, want: []const u8) !void {
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
        var msg = try testCreateCertificateMsgTls12(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_certificate_msg);
    }
}

test "CertificateMsgTls12.unmarshal" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *CertificateMsgTls12) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data, .v1_2);
            defer msg.deinit(allocator);

            var got = msg.certificate.v1_2;
            try testing.expectEqualSlices(u8, data, got.raw);
            got.raw = "";

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = try testCreateCertificateMsgTls12(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_certificate_msg, &msg);
    }
}

fn testCreateCertificateMsgTls12(allocator: mem.Allocator) !CertificateMsgTls12 {
    const cert1 = try allocator.dupe(u8, "cert1");
    errdefer allocator.free(cert1);
    const cert2 = try allocator.dupe(u8, "cert2");
    errdefer allocator.free(cert2);
    const certificates = try allocator.dupe(
        []const u8,
        &[_][]const u8{ cert1, cert2 },
    );
    return CertificateMsgTls12{
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
    testing.log_level = .err;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ServerKeyExchangeMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data, null);
            defer msg.deinit(allocator);

            var got = msg.server_key_exchange;
            try testing.expectEqualSlices(u8, data, got.raw);
            got.raw = "";

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

const test_marshaled_server_key_exchange_msg = "\x0c" ++ // MsgType.server_key_exchange
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
    testing.log_level = .err;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ServerHelloDoneMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data, null);
            defer msg.deinit(allocator);

            var got = msg.server_hello_done;
            try testing.expectEqualSlices(u8, data, got.raw);
            got.raw = "";

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

const test_marshaled_server_hello_done_msg = "\x0e" ++ // MsgType.server_hello_done
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
    testing.log_level = .err;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *ClientKeyExchangeMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data, null);
            defer msg.deinit(allocator);

            var got = msg.client_key_exchange;
            try testing.expectEqualSlices(u8, data, got.raw);
            got.raw = "";

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

const test_marshaled_client_key_exchange_msg = "\x10" ++ // MsgType.client_key_exchange
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
        var msg = try testCreateFinishedMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(&msg, test_marshaled_finished_msg);
    }
}

test "FinishedMsg.unmarshal" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    const TestCase = struct {
        fn run(data: []const u8, want: *FinishedMsg) !void {
            var msg = try HandshakeMsg.unmarshal(allocator, data, null);
            defer msg.deinit(allocator);

            var got = msg.finished;
            try testing.expectEqualSlices(u8, data, got.raw);
            got.raw = "";

            try testingExpectPrintEqual(allocator, "{}", want, &got);
        }
    };

    {
        var msg = try testCreateFinishedMsg(allocator);
        defer msg.deinit(allocator);
        try TestCase.run(test_marshaled_finished_msg, &msg);
    }
}

fn testCreateFinishedMsg(allocator: mem.Allocator) !FinishedMsg {
    return FinishedMsg{
        .verify_data = try allocator.dupe(u8, "verify data"),
    };
}

const test_marshaled_finished_msg = "\x14" ++ // MsgType.Finished
    "\x00\x00\x0b" ++ // u24 msg_len
    "\x76\x65\x72\x69\x66\x79\x20\x64\x61\x74\x61"; // "verify data"

test "EncryptedExtensionsMsg.marshal" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    var msg = EncryptedExtensionsMsg{ .alpn_protocol = "h2" };
    const got = try msg.marshal(allocator);
    defer allocator.free(got);
    // std.log.debug("marshaled={}", .{std.fmt.fmtSliceHexLower(got)});

    const want = "\x08\x00\x00\x0b\x00\x09\x00\x10\x00\x05\x00\x03\x02\x68\x32";
    try testing.expectEqualSlices(u8, want, got);

    var msg2 = try EncryptedExtensionsMsg.unmarshal(allocator, want);
    defer msg2.deinit(allocator);

    try testing.expectEqualStrings(msg.alpn_protocol, msg2.alpn_protocol);
}

test "CertificateMsgTls13.marshal case1" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    var msg = CertificateMsgTls13{
        .cert_chain = CertificateChain{
            .certificate_chain = &[_][]const u8{
                "\x24\x0a\xde\xde\x3d\x3b\xa4\x35\xbc\x02\xf8\x87\x18\x0a\x61",
                "\x52\xbb\x1f\x7f\x74\x18\x31\x74\x96\x33\x91\xac\x1a\xa3\x29\xfd\xa7\xb7\x56\x02\x72\xbb\x16\xd9\xbe\xc7\x81\x73\xd4\x01\x80\x61\x18\x1a\x1e",
            },
            .ocsp_staple = "\x4d\xab\x72\x65\x6e\x8d",
            .signed_certificate_timestamps = &[_][]const u8{
                "\x49\x81\xed\x50\x1d\x4d\x4d\x0e\x04\x2d\xeb\xcb\xcf",
                "\x30\x9d\x61\xf4\xab\xeb\xb1\xf5\x7c",
            },
        },
        .ocsp_stapling = true,
        .scts = true,
    };

    const got = try msg.marshal(allocator);
    defer allocator.free(got);
    // std.log.debug("marshaled={}", .{std.fmt.fmtSliceHexLower(got)});

    const want = "\x0b\x00\x00\x6e\x00\x00\x00\x6a\x00\x00\x0f\x24\x0a\xde\xde\x3d\x3b\xa4\x35\xbc\x02\xf8\x87\x18\x0a\x61\x00\x2e\x00\x05\x00\x0a\x01\x00\x00\x06\x4d\xab\x72\x65\x6e\x8d\x00\x12\x00\x1c\x00\x1a\x00\x0d\x49\x81\xed\x50\x1d\x4d\x4d\x0e\x04\x2d\xeb\xcb\xcf\x00\x09\x30\x9d\x61\xf4\xab\xeb\xb1\xf5\x7c\x00\x00\x23\x52\xbb\x1f\x7f\x74\x18\x31\x74\x96\x33\x91\xac\x1a\xa3\x29\xfd\xa7\xb7\x56\x02\x72\xbb\x16\xd9\xbe\xc7\x81\x73\xd4\x01\x80\x61\x18\x1a\x1e\x00\x00";
    try testing.expectEqualSlices(u8, want, got);

    var msg2 = try CertificateMsgTls13.unmarshal(allocator, want);
    defer msg2.deinit(allocator);

    try testing.expectEqual(
        msg.cert_chain.certificate_chain.len,
        msg2.cert_chain.certificate_chain.len,
    );
    for (msg.cert_chain.certificate_chain) |cert, i| {
        try testing.expectEqualStrings(cert, msg2.cert_chain.certificate_chain[i]);
    }

    try testing.expectEqualStrings(msg.cert_chain.ocsp_staple, msg2.cert_chain.ocsp_staple);

    try testing.expectEqual(
        msg.cert_chain.signed_certificate_timestamps.len,
        msg2.cert_chain.signed_certificate_timestamps.len,
    );
    for (msg.cert_chain.signed_certificate_timestamps) |sct, i| {
        try testing.expectEqualStrings(sct, msg2.cert_chain.signed_certificate_timestamps[i]);
    }
}

test "CertificateMsgTls13.marshal case2" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    var msg = CertificateMsgTls13{
        .cert_chain = CertificateChain{
            .certificate_chain = &[_][]const u8{
                "\x24\x0a\xde\xde\x3d\x3b\xa4\x35\xbc\x02\xf8\x87\x18\x0a\x61",
                "\x52\xbb\x1f\x7f\x74\x18\x31\x74\x96\x33\x91\xac\x1a\xa3\x29\xfd\xa7\xb7\x56\x02\x72\xbb\x16\xd9\xbe\xc7\x81\x73\xd4\x01\x80\x61\x18\x1a\x1e",
            },
            .ocsp_staple = "\x4d\xab\x72\x65\x6e\x8d",
            .signed_certificate_timestamps = &[_][]const u8{
                "\x49\x81\xed\x50\x1d\x4d\x4d\x0e\x04\x2d\xeb\xcb\xcf",
                "\x30\x9d\x61\xf4\xab\xeb\xb1\xf5\x7c",
            },
        },
        .ocsp_stapling = true,
        .scts = true,
    };

    const got = try msg.marshal(allocator);
    defer allocator.free(got);
    // std.log.debug("marshaled={}", .{std.fmt.fmtSliceHexLower(got)});

    const want = "\x0b\x00\x00\x6e\x00\x00\x00\x6a\x00\x00\x0f\x24\x0a\xde\xde\x3d\x3b\xa4\x35\xbc\x02\xf8\x87\x18\x0a\x61\x00\x2e\x00\x05\x00\x0a\x01\x00\x00\x06\x4d\xab\x72\x65\x6e\x8d\x00\x12\x00\x1c\x00\x1a\x00\x0d\x49\x81\xed\x50\x1d\x4d\x4d\x0e\x04\x2d\xeb\xcb\xcf\x00\x09\x30\x9d\x61\xf4\xab\xeb\xb1\xf5\x7c\x00\x00\x23\x52\xbb\x1f\x7f\x74\x18\x31\x74\x96\x33\x91\xac\x1a\xa3\x29\xfd\xa7\xb7\x56\x02\x72\xbb\x16\xd9\xbe\xc7\x81\x73\xd4\x01\x80\x61\x18\x1a\x1e\x00\x00";
    try testing.expectEqualSlices(u8, want, got);

    var msg2 = try CertificateMsgTls13.unmarshal(allocator, want);
    defer msg2.deinit(allocator);

    try testing.expectEqual(
        msg.cert_chain.certificate_chain.len,
        msg2.cert_chain.certificate_chain.len,
    );
    for (msg.cert_chain.certificate_chain) |cert, i| {
        try testing.expectEqualStrings(cert, msg2.cert_chain.certificate_chain[i]);
    }

    try testing.expectEqualStrings(msg.cert_chain.ocsp_staple, msg2.cert_chain.ocsp_staple);

    try testing.expectEqual(
        msg.cert_chain.signed_certificate_timestamps.len,
        msg2.cert_chain.signed_certificate_timestamps.len,
    );
    for (msg.cert_chain.signed_certificate_timestamps) |sct, i| {
        try testing.expectEqualStrings(sct, msg2.cert_chain.signed_certificate_timestamps[i]);
    }
}

test "CertificateVerifyMsg.marshal" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    var msg = CertificateVerifyMsg{
        .signature_algorithm = .ecdsa_with_p256_and_sha256,
        .signature = "example signature",
    };

    const got = try msg.marshal(allocator);
    defer allocator.free(got);
    // std.log.debug("marshaled={}", .{std.fmt.fmtSliceHexLower(got)});

    const want = "\x0f\x00\x00\x15\x04\x03\x00\x11\x65\x78\x61\x6d\x70\x6c\x65\x20\x73\x69\x67\x6e\x61\x74\x75\x72\x65";
    try testing.expectEqualSlices(u8, want, got);

    var msg2 = try CertificateVerifyMsg.unmarshal(allocator, want);
    defer msg2.deinit(allocator);

    try testing.expectEqual(msg.signature_algorithm, msg2.signature_algorithm);
    try testing.expectEqualSlices(u8, msg.signature, msg2.signature);
}
