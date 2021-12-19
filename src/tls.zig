const std = @import("std");

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
};

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
    };

    msg_type: HandshakeType,
    length: u24,
    body: Body,
};

const ClientHello = struct {
    client_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suites: []CipherSuite,
    compression_methods: []CompressionMethod,
    extensions: []Extension,
};

const ServerHello = struct {
    server_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suite: CipherSuite,
    compression_method: []CompressionMethod,
    extensions: []Extension,
};

const Random = struct {
    gmt_unix_time: u32,
    random_bytes: [28]u8,
};

const SessionId = u8;
const session_id_max = 32;

const CipherSuite = [2]u8;

const Extension = struct {
    extension_type: ExtensionType,
    extension_data: []u8,
};

// https://datatracker.ietf.org/doc/html/rfc6066#section-1.1
const ExtensionType = enum(u16) {
    server_name = 0,
    max_fragment_length = 1,
    client_certificate_url = 2,
    trusted_ca_keys = 3,
    truncated_hmac = 4,
    status_request = 5,
    signature_algorithms = 13,
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
    server_name_list: []ServerName,
};

const ServerName = union(NameType) {
    host_name: HostName,
};

const NameType = enum(u8) {
    host_name = 0,
};

const HostName = []u8;

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
