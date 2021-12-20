const std = @import("std");
const io = std.io;

const SecurityParameters = struct {
    entity: ConnectionEnd,
    prf_algorithm: PrfAlgorithm,
    bulk_cipher_algorithm: BulkCipherAlgorithm,
    cipher_type: CipherType,
    enc_key_length: u8,
    block_length: u8,
    fixed_iv_length: u8,
    record_iv_length: u8,
    mac_algorithm: MacAlgorithm,
    mac_length: u8,
    mac_key_length: u8,
    compression_algorithm: CompressionMethod,
    master_secret: [48]u8,
    client_random: [32]u8,
    server_random: [32]u8,
};

const ConnectionEnd = enum {
    server,
    client,
};

const PrfAlgorithm = enum {
    tls_prf_sha256,
};

const BulkCipherAlgorithm = enum {
    @"null",
    rc4,
    @"3des",
    aes,
};

const CipherType = enum {
    stream,
    block,
    aead,
};

const MacAlgorithm = enum {
    @"null",
    hmac_md5,
    hmac_sha1,
    hmac_sha256,
    hmac_sha384,
    hmac_sha512,
};

const CompressionMethod = enum(u8) {
    @"null" = 0,

    fn encode(self: CompressionMethod, writer: anytype) !void {
        try writer.writeByte(@enumToInt(self));
    }
};
fn encodeCompressionMethodList(methods: []const CompressionMethod, writer: anytype) !void {
    try writer.writeByte(@truncate(u8, methods.len * @sizeOf(CompressionMethod)));
    for (methods) |method| {
        try method.encode(writer);
    }
}

const HashAlgorithm = enum(u8) {
    none = 0,
    md5 = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,
    sha512 = 6,
};

const SignatureAlgorithm = enum(u8) {
    anonymous = 0,
    rsa = 1,
    dsa = 2,
    ecdsa = 3,
};

const SignatureAndHashAlgorithm = struct {
    hash: HashAlgorithm,
    signature: SignatureAlgorithm,
};

const ProtocolVersion = struct {
    major: u8,
    minor: u8,

    fn encode(self: *const ProtocolVersion, writer: anytype) !void {
        try writer.writeByte(self.major);
        try writer.writeByte(self.minor);
    }
};
const v1_2 = ProtocolVersion{ .major = 3, .minor = 3 };
const v1_0 = ProtocolVersion{ .major = 3, .minor = 1 };

const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

const TlsPlaintext = struct {
    content_type: ContentType,
    version: ProtocolVersion,
    length: u16,
    fragment: []u8,
};

// https://datatracker.ietf.org/doc/html/rfc6066#section-4
const tls_ciphertext_fragment_max_len: usize = 1 << (14 - 1);

const TlsCiphertext = struct {
    const Fragment = union(CipherType) {
        stream: GenericStreamCipher,
        block: GenericBlockCipher,
        aead: GenericAeadCipher,
    };

    content_type: ContentType,
    version: ProtocolVersion,
    length: u16,
    fragment: Fragment,
};

const GenericStreamCipher = struct {
    content: []u8,
    mac: []u8,
};

const GenericBlockCipher = struct {
    const BlockCiphered = struct {
        content: []u8,
        mac: []u8,
        padding: []u8,
        padding_length: u8,
    };

    iv: []u8,
    block_ciphered: BlockCiphered,
};

const GenericAeadCipher = struct {
    const AeadCiphered = struct {
        content: []u8,
    };

    nonce_explicit: []u8,
    aead_ciphered: AeadCiphered,
};

const HandshakeType = enum(u8) {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20,

    fn encode(self: HandshakeType, writer: anytype) !void {
        try writer.writeByte(@enumToInt(self));
    }
};

const Handshake = struct {
    const Body = union(HandshakeType) {
        hello_request: HelloRequest,
        client_hello: ClientHello,
        server_hello: ServerHello,
        certificate: Certificate,
        server_key_exchange: ServerKeyExchange,
        certificate_request: CertificateRequest,
        server_hello_done: ServerHelloDone,
        certificate_verify: CertificateVerify,
        client_key_exchange: ClientKeyExchange,
        finished: Finished,

        fn encode(self: *const Body, writer: anytype) !void {
            switch (self.*) {
                .client_hello => |*ch| try ch.encode(writer),
                else => {},
            }
        }
    };

    msg_type: HandshakeType,
    length: u24,
    body: Body,

    fn updateLength(self: *Handshake) !void {
        var writer = io.countingWriter(io.null_writer);
        try self.body.encode(writer.writer());
        self.length = @truncate(u24, writer.bytes_written);
    }

    fn encode(self: *const Handshake, writer: anytype) !void {
        try self.msg_type.encode(writer);
        try writer.writeIntBig(u24, self.length);
        try self.body.encode(writer);
    }
};

const ClientHello = struct {
    client_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suites: []CipherSuite,
    compression_methods: []const CompressionMethod,
    extensions: []const Extension,

    fn encode(self: *const ClientHello, writer: anytype) !void {
        try self.client_version.encode(writer);
        try writer.writeAll(&self.random);
        try encodeSessionId(self.session_id, writer);
        try encodeCipherSuiteList(self.cipher_suites, writer);
        try encodeCompressionMethodList(self.compression_methods, writer);
        try encodeExtensions(self.extensions, writer);
    }
};

const ServerHello = struct {
    server_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suite: CipherSuite,
    compression_method: []CompressionMethod,
    extensions: []Extension,
};

const Random = [32]u8;

const SessionId = []const u8;
const session_id_max_len = 32;

fn encodeSessionId(self: SessionId, writer: anytype) !void {
    try writer.writeByte(@truncate(u8, self.len));
    try writer.writeAll(self);
}

const CipherSuite = [2]u8;

fn encodeCipherSuiteList(cipher_suites: []const CipherSuite, writer: anytype) !void {
    try writer.writeIntBig(u16, @truncate(u16, cipher_suites.len) * @sizeOf(CipherSuite));
    for (cipher_suites) |*suite| {
        try writer.writeAll(suite);
    }
}

fn encodeExtensions(extensions: []const Extension, writer: anytype) !void {
    const len = try calcExtensionsContentsEncodedLen(extensions);
    try writer.writeIntBig(u16, @truncate(u16, len));
    try encodeExtensionsContents(extensions, writer);
}

fn calcExtensionsContentsEncodedLen(extensions: []const Extension) !u64 {
    var writer = io.countingWriter(io.null_writer);
    try encodeExtensionsContents(extensions, writer.writer());
    return writer.bytes_written;
}

fn encodeExtensionsContents(extensions: []const Extension, writer: anytype) !void {
    for (extensions) |*ext| {
        try ext.encode(writer);
    }
}

const Extension = struct {
    extension_type: ExtensionType,
    extension_data: ExtensionData,

    fn encode(self: *const Extension, writer: anytype) !void {
        try writer.writeIntBig(u16, @enumToInt(self.extension_type));
        try self.extension_data.encode(writer);
    }
};

// https://datatracker.ietf.org/doc/html/rfc6066#section-1.1
const ExtensionType = enum(u16) {
    server_name = 0,
    // max_fragment_length = 1,
    // client_certificate_url = 2,
    // trusted_ca_keys = 3,
    // truncated_hmac = 4,
    // status_request = 5,
    // signature_algorithms = 13,
};

const ExtensionData = union(ExtensionType) {
    server_name: ServerNameList,

    fn encode(self: *const ExtensionData, writer: anytype) !void {
        switch (self.*) {
            .server_name => |sn| try sn.encode(writer),
        }
    }
};

const asn1_cert_len = 1 << (24 - 1) - 1;
const Asn1Cert = [asn1_cert_len]u8;

const Certificate = struct {
    certificate_list: []Asn1Cert,
};

const KeyExchangeAlgorithm = enum {
    dhe_dss,
    dhe_rsa,
    dh_anon,
    rsa,
    dh_dss,
    dh_rsa,
    // may be extended, e.g., for ECDH -- see [TLSECC]
};

const ServerDHParams = struct {
    dh_p: []u8,
    dh_g: []u8,
    dh_Ys: []u8,
};

const ServerKeyExchange = union(KeyExchangeAlgorithm) {
    const SignedParams = struct {
        client_random: [32]u8,
        server_random: [32]u8,
        params: ServerDHParams,
    };
    const ParamsAndSigned = struct {
        params: ServerDHParams,
        signed_params: SignedParams,
    };

    dh_anon: ServerDHParams,
    dhe_dss: ParamsAndSigned,
    dhe_rsa: ParamsAndSigned,
    rsa: void,
    dh_dss: void,
    dh_rsa: void,
    // message is omitted for rsa, dh_dss, and dh_rsa
    // may be extended, e.g., for ECDH -- see [TLSECC]
};

const ClientCertificateType = enum(u8) {
    rsa_sign = 1,
    dss_sign = 2,
    rsa_fixed_dh = 3,
    dss_fixed_dh = 4,
    rsa_ephemeral_dh_RESERVED = 5,
    dss_ephemeral_dh_RESERVED = 6,
    fortezza_dms_RESERVED = 20,
};

const HelloRequest = struct {};

const DistinguishedName = []u8;

const CertificateRequest = struct {
    certificate_types: ClientCertificateType,
    supported_signature_algorithms: []SignatureAndHashAlgorithm,
    certificate_authorities: []DistinguishedName,
};

const ServerHelloDone = struct {};

const CertificateVerify = struct {
    handshake_messages: []u8,
};

const ClientKeyExchange = struct {
    const Keys = union(KeyExchangeAlgorithm) {
        rsa: EncryptedPreMasterSecret,
        dhe_dss: ClientDiffieHellmanPublic,
        dhe_rsa: ClientDiffieHellmanPublic,
        dh_dss: ClientDiffieHellmanPublic,
        dh_rsa: ClientDiffieHellmanPublic,
        dh_anon: ClientDiffieHellmanPublic,
    };

    exchange_keys: Keys,
};

const EncryptedPreMasterSecret = struct {
    pre_master_secret: PreMasterSecret, //  public-key-encrypted
};

const PreMasterSecret = struct {
    client_version: ProtocolVersion,
    random: [46]u8,
};

const PublicValueEncoding = enum { implicit, explicit };

const ClientDiffieHellmanPublic = struct {
    const DhPublic = union(PublicValueEncoding) {
        implicit: void,
        explicit: DhYc,
    };

    dh_public: DhPublic,
};

const DhYc = []u8;

const Finished = struct {
    verify_data: []u8,
};

const ServerNameList = struct {
    server_name_list: []const ServerName,

    fn encode(self: *const ServerNameList, writer: anytype) !void {
        const len = try calcServerNameListContentsEncodedLen(self.server_name_list);
        try writer.writeIntBig(u16, @truncate(u16, len));
        try encodeServerNameListContents(self.server_name_list, writer);
    }
};

fn calcServerNameListContentsEncodedLen(server_name_list: []const ServerName) !u64 {
    var writer = io.countingWriter(io.null_writer);
    try encodeServerNameListContents(server_name_list, writer.writer());
    return writer.bytes_written;
}

fn encodeServerNameListContents(server_name_list: []const ServerName, writer: anytype) !void {
    for (server_name_list) |server_name| {
        try server_name.encode(writer);
    }
}

const ServerName = union(NameType) {
    host_name: HostName,

    fn encode(self: *const ServerName, writer: anytype) !void {
        try writer.writeByte(@enumToInt(@as(NameType, self.*)));
        switch (self.*) {
            .host_name => |n| try encodeHostName(n, writer),
        }
    }
};

const NameType = enum(u8) {
    host_name = 0,
};

const HostName = []const u8;
fn encodeHostName(hostname: []const u8, writer: anytype) !void {
    try writer.writeIntBig(u16, @truncate(u16, hostname.len));
    try writer.writeAll(hostname);
}

const testing = std.testing;

test "ServerKeyExchange" {
    const xchg = ServerKeyExchange{ .rsa = {} };
    std.debug.print("xchg = {}\n", .{xchg});
}

test "ClientHello" {
    const client_hello = TlsPlaintext{
        .content_type = .handshake,
        .version = v1_0,
        .length = 0,
        .fragment = "",
    };

    std.debug.print("client_hello = {}\n", .{client_hello});
}

test "write_u24" {
    var buf = [_]u8{0} ** 3;
    var fbs = io.fixedBufferStream(&buf);

    const length: u24 = 0x123456;
    try fbs.writer().writeIntBig(u24, length);
    try testing.expectEqualSlices(u8, &[_]u8{ '\x12', '\x34', '\x56' }, &buf);
}

test "Handshake.encode" {
    var hs = Handshake{
        .msg_type = .client_hello,
        .length = 0,
        .body = .{
            .client_hello = ClientHello{
                .client_version = v1_2,
                .random = [_]u8{0} ** 32,
                .session_id = &[_]u8{0},
                .cipher_suites = &[_]CipherSuite{},
                .compression_methods = &[_]CompressionMethod{.@"null"},
                .extensions = &[_]Extension{
                    .{
                        .extension_type = .server_name,
                        .extension_data = .{
                            .server_name = ServerNameList{
                                .server_name_list = &[_]ServerName{
                                    .{
                                        .host_name = "example.com",
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    };

    const allocator = testing.allocator;
    const DynamicBytesBuf = std.fifo.LinearFifo(u8, .Dynamic);
    var buf = DynamicBytesBuf.init(allocator);
    defer buf.deinit();
    var writer = buf.writer();
    try hs.updateLength();
    try testing.expectEqual(@as(u24, 49 + "example.com".len), hs.length);
    try hs.encode(writer);
    const want = "\x01\x00\x00\x3c" ++ "\x03\x03" ++ "\x00" ** 32 ++ "\x01\x00" ++
        "\x00\x00" ++ "\x01\x00" ++
        "\x00\x12" ++
        "\x00\x00" ++
        "\x00\x0e" ++
        "\x00" ++
        "\x00\x0b" ++
        "example.com";
    try testing.expectEqualSlices(u8, want, buf.readableSlice(0));
}
