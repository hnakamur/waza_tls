const std = @import("std");
const math = std.math;
const mem = std.mem;
const datetime = @import("datetime");
const CurveId = @import("handshake_msg.zig").CurveId;
const asn1 = @import("asn1.zig");
const pkix = @import("pkix.zig");
const crypto = @import("crypto.zig");
const rsa = @import("rsa.zig");
const bigint = @import("big_int.zig");
const makeStaticCharBitSet = @import("../parser/lex.zig").makeStaticCharBitSet;
const fmtx = @import("../fmtx.zig");
const memx = @import("../memx.zig");
const netx = @import("../netx.zig");
const Uri = @import("../urix.zig").Uri;
const ecdsa = @import("ecdsa.zig");
const elliptic = @import("elliptic.zig");
const CertPool = @import("cert_pool.zig").CertPool;
const domainToReverseLabels = @import("verify.zig").domainToReverseLabels;
const verifyEmailSan = @import("verify.zig").verifyEmailSan;
const verifyDnsSan = @import("verify.zig").verifyDnsSan;
const verifyUriSan = @import("verify.zig").verifyUriSan;
const verifyIpSan = @import("verify.zig").verifyIpSan;
const VerifyOptions = @import("verify.zig").VerifyOptions;
const VerifiedCertChains = @import("verify.zig").VerifiedCertChains;
const validHostnamePattern = @import("verify.zig").validHostnamePattern;
const validHostnameInput = @import("verify.zig").validHostnameInput;
const matchExactly = @import("verify.zig").matchExactly;
const matchHostnames = @import("verify.zig").matchHostnames;
const checkChainForKeyUsage = @import("verify.zig").checkChainForKeyUsage;
const Rfc2821Mailbox = @import("mailbox.zig").Rfc2821Mailbox;
const HashType = @import("auth.zig").HashType;

pub const SignatureAlgorithm = enum(u8) {
    unknown,
    md2_with_rsa, // Unsupported.
    md5_with_rsa, // Only supported for signing, not verification.
    sha1_with_rsa, // Only supported for signing, not verification.
    sha256_with_rsa,
    sha384_with_rsa,
    sha512_with_rsa,
    dsa_with_sha1, // Unsupported.
    dsa_with_sha256, // Unsupported.
    ecdsa_with_sha1, // Only supported for signing, not verification.
    ecdsa_with_sha256,
    ecdsa_with_sha384,
    ecdsa_with_sha512,
    sha256_with_rsa_pss,
    sha384_with_rsa_pss,
    sha512_with_rsa_pss,
    pure_ed25519,

    pub fn fromAlgorithmIdentifier(ai: *const pkix.AlgorithmIdentifier) !SignatureAlgorithm {
        if (ai.algorithm.eql(asn1.ObjectIdentifier.signature_ed25519)) {
            // RFC 8410, Section 3
            // > For all of the OIDs, the parameters MUST be absent.
            if (ai.parameters) |params| {
                if (params.full_bytes.len != 0) {
                    return error.UnknownSignatureAlgorithm;
                }
            }
        }

        if (!ai.algorithm.eql(asn1.ObjectIdentifier.signature_rsa_pss)) {
            for (signature_algorithm_details) |detail| {
                if (ai.algorithm.eql(detail.oid)) {
                    return detail.algo;
                }
            }
            return error.UnknownSignatureAlgorithm;
        }

        // RSA PSS is special because it encodes important parameters
        // in the Parameters.

        @panic("not implemented yet");
    }

    fn is_rsa_pss(self: SignatureAlgorithm) bool {
        return switch (self) {
            .sha256_with_rsa_pss, .sha384_with_rsa_pss, .sha512_with_rsa_pss => true,
            else => false,
        };
    }
};

// PssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
const PssParameters = struct {
    hash: pkix.AlgorithmIdentifier,
    mgf: pkix.AlgorithmIdentifier,
    salt_length: usize,
    trailer_field: usize = 1,

    pub fn parse(input: []const u8, allocator: mem.Allocator) !PssParameters {
        _ = input;
        _ = allocator;
        @panic("not implemented yet");
    }
};

test "fromAlgorithmIdentifier" {
    const ai = pkix.AlgorithmIdentifier{ .algorithm = oid_signature_ed25519 };
    var algo = try SignatureAlgorithm.fromAlgorithmIdentifier(&ai);
    std.log.debug("algo={}\n", .{algo});
    // try testing.expectEqual(oid_signature_ed25519, ObjectIdentifier{ .components = &[_]u32{ 1, 3, 101, 112 } });
}

pub const oid_signature_sha1_with_rsa = asn1.ObjectIdentifier{
    .components = &[_]u32{ 1, 2, 840, 113549, 1, 1, 5 },
};
pub const oid_signature_rsa_pss = asn1.ObjectIdentifier{
    .components = &[_]u32{ 1, 2, 840, 113549, 1, 1, 10 },
};
pub const oid_signature_ed25519 = asn1.ObjectIdentifier{ .components = &[_]u32{ 1, 3, 101, 112 } };

pub const SignatureAlgorithmDetail = struct {
    algo: SignatureAlgorithm,
    name: []const u8,
    oid: asn1.ObjectIdentifier,
    pub_key_algo: crypto.PublicKeyAlgorithm,
    hash_type: HashType,
};

const signature_algorithm_details = [_]SignatureAlgorithmDetail{
    // .{
    //     .algo = .md2_with_rsa,
    //     .name = "MD2-RSA",
    //     .oid = asn1.ObjectIdentifier.signature_md2_with_rsa,
    //     .pub_key_algo = .rsa,
    //     // .hash_type = null,
    // },
    // .{
    //     .algo = .md5_with_rsa,
    //     .name = "MD5-RSA",
    //     .oid = asn1.ObjectIdentifier.signature_md5_with_rsa,
    //     .pub_key_algo = .rsa,
    //     // .hash_type = .md5,
    // },
    .{
        .algo = .sha1_with_rsa,
        .name = "SHA1-RSA",
        .oid = asn1.ObjectIdentifier.signature_sha1_with_rsa,
        .pub_key_algo = .rsa,
        .hash_type = .sha1,
    },
    .{
        .algo = .sha1_with_rsa,
        .name = "SHA1-RSA",
        .oid = asn1.ObjectIdentifier.iso_signature_sha1_with_rsa,
        .pub_key_algo = .rsa,
        .hash_type = .sha1,
    },
    .{
        .algo = .sha256_with_rsa,
        .name = "SHA256-RSA",
        .oid = asn1.ObjectIdentifier.signature_sha256_with_rsa,
        .pub_key_algo = .rsa,
        .hash_type = .sha256,
    },
    .{
        .algo = .sha384_with_rsa,
        .name = "SHA384-RSA",
        .oid = asn1.ObjectIdentifier.signature_sha384_with_rsa,
        .pub_key_algo = .rsa,
        .hash_type = .sha384,
    },
    .{
        .algo = .sha512_with_rsa,
        .name = "SHA512-RSA",
        .oid = asn1.ObjectIdentifier.signature_sha512_with_rsa,
        .pub_key_algo = .rsa,
        .hash_type = .sha512,
    },
    .{
        .algo = .sha256_with_rsa_pss,
        .name = "SHA256-RSAPSS",
        .oid = asn1.ObjectIdentifier.signature_rsa_pss,
        .pub_key_algo = .rsa,
        .hash_type = .sha256,
    },
    .{
        .algo = .sha384_with_rsa_pss,
        .name = "SHA384-RSAPSS",
        .oid = asn1.ObjectIdentifier.signature_rsa_pss,
        .pub_key_algo = .rsa,
        .hash_type = .sha384,
    },
    .{
        .algo = .sha512_with_rsa_pss,
        .name = "SHA512-RSAPSS",
        .oid = asn1.ObjectIdentifier.signature_rsa_pss,
        .pub_key_algo = .rsa,
        .hash_type = .sha512,
    },
    .{
        .algo = .dsa_with_sha1,
        .name = "DSA-SHA1",
        .oid = asn1.ObjectIdentifier.signature_dsa_with_sha1,
        .pub_key_algo = .dsa,
        .hash_type = .sha1,
    },
    .{
        .algo = .dsa_with_sha256,
        .name = "DSA-SHA256",
        .oid = asn1.ObjectIdentifier.signature_dsa_with_sha256,
        .pub_key_algo = .dsa,
        .hash_type = .sha256,
    },
    .{
        .algo = .ecdsa_with_sha1,
        .name = "ECDSA-SHA1",
        .oid = asn1.ObjectIdentifier.signature_ecdsa_with_sha1,
        .pub_key_algo = .ecdsa,
        .hash_type = .sha1,
    },
    .{
        .algo = .ecdsa_with_sha256,
        .name = "ECDSA-SHA256",
        .oid = asn1.ObjectIdentifier.signature_ecdsa_with_sha256,
        .pub_key_algo = .ecdsa,
        .hash_type = .sha256,
    },
    .{
        .algo = .ecdsa_with_sha384,
        .name = "ECDSA-SHA384",
        .oid = asn1.ObjectIdentifier.signature_ecdsa_with_sha384,
        .pub_key_algo = .ecdsa,
        .hash_type = .sha384,
    },
    .{
        .algo = .ecdsa_with_sha512,
        .name = "ECDSA-SHA512",
        .oid = asn1.ObjectIdentifier.signature_ecdsa_with_sha512,
        .pub_key_algo = .ecdsa,
        .hash_type = .sha512,
    },
    .{
        .algo = .pure_ed25519,
        .name = "Ed25519",
        .oid = asn1.ObjectIdentifier.signature_ed25519,
        .pub_key_algo = .ed25519,
        .hash_type = .direct_signing,
    },
};

// fieldParameters is the parsed representation of tag string from a structure field.
const FieldParameters = struct {
    optional: bool, // true iff the field is OPTIONAL
    explicit: bool, // true iff an EXPLICIT tag is in use.
    application: bool, // true iff an APPLICATION tag is in use.
    private: bool, // true iff a PRIVATE tag is in use.
    default_value: ?i64 = null, // a default value for INTEGER typed fields (maybe nil).
    tag: ?asn1.TagAndClass = null, // the EXPLICIT or IMPLICIT tag (maybe nil).
    string_type: usize, // the string tag to use when marshaling.
    time_type: usize, // the time tag to use when marshaling.
    set: bool, // true iff this should be encoded as a SET
    omit_empty: bool, // true iff this should be omitted if empty when marshaling.

    // Invariants:
    //   if explicit is set, tag is non-nil.
};

const PublicKeyInfo = struct {
    raw: ?asn1.RawContent = null,
    algorithm: pkix.AlgorithmIdentifier,
    public_key: asn1.BitString,

    pub fn deinit(self: *PublicKeyInfo, allocator: mem.Allocator) void {
        if (self.raw) |*raw| raw.deinit(allocator);
        self.algorithm.deinit(allocator);
        self.public_key.deinit(allocator);
    }
};

pub const KeyUsage = packed struct {
    digital_signature: u1 = 0,
    content_commitment: u1 = 0,
    key_encipherment: u1 = 0,
    data_encipherment: u1 = 0,
    key_agreement: u1 = 0,
    cert_sign: u1 = 0,
    crl_sign: u1 = 0,
    encipher_only: u1 = 0,
    decipher_only: u1 = 0,

    fn is_none(self: KeyUsage) bool {
        return self.digital_signature == 0 and
            self.content_commitment == 0 and
            self.key_encipherment == 0 and
            self.data_encipherment == 0 and
            self.key_agreement == 0 and
            self.cert_sign == 0 and
            self.crl_sign == 0 and
            self.encipher_only == 0 and
            self.decipher_only == 0;
    }
};

pub const ExtKeyUsage = enum {
    any,
    server_auth,
    client_auth,
    code_signing,
    email_protection,
    ipsec_end_system,
    ipsec_tunnel,
    ipsec_user,
    time_stamping,
    ocsp_signing,
    microsoft_server_gated_crypto,
    netscape_server_gated_crypto,
    microsoft_commercial_code_signing,
    microsoft_kernel_code_signing,

    fn fromOid(oid: asn1.ObjectIdentifier) ?ExtKeyUsage {
        for (ext_key_usage_oids) |m| {
            if (oid.eql(m.oid)) {
                return m.usage;
            }
        }
        return null;
    }

    // RFC 5280, 4.2.1.12  Extended Key Usage
    //
    // anyExtendedKeyUsage OBJECT IDENTIFIER ::= { id-ce-extKeyUsage 0 }
    //
    // id-kp OBJECT IDENTIFIER ::= { id-pkix 3 }
    //
    // id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
    // id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
    // id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
    // id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
    // id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
    // id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
    const oid_any = asn1.ObjectIdentifier.initConst(&.{ 2, 5, 29, 37, 0 });
    const oid_server_auth = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 1 });
    const oid_client_auth = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 2 });
    const oid_code_signing = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 3 });
    const oid_email_protection = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 4 });
    const oid_ipsec_end_system = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 5 });
    const oid_ipsec_tunnel = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 6 });
    const oid_ipsec_user = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 7 });
    const oid_time_stamping = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 8 });
    const oid_ocsp_signing = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 5, 5, 7, 3, 9 });
    const oid_microsoft_server_gated_crypto = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 4, 1, 311, 10, 3, 3 });
    const oid_netscape_server_gated_crypto = asn1.ObjectIdentifier.initConst(&.{ 2, 16, 840, 1, 113730, 4, 1 });
    const oid_microsoft_commercial_code_signing = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 4, 1, 311, 2, 1, 22 });
    const oid_microsoft_kernel_code_signing = asn1.ObjectIdentifier.initConst(&.{ 1, 3, 6, 1, 4, 1, 311, 61, 1, 1 });
};

const ExtKeyUsageOidMapping = struct {
    usage: ExtKeyUsage,
    oid: asn1.ObjectIdentifier,
};

const ext_key_usage_oids = [_]ExtKeyUsageOidMapping{
    .{ .usage = .any, .oid = ExtKeyUsage.oid_any },
    .{ .usage = .server_auth, .oid = ExtKeyUsage.oid_server_auth },
    .{ .usage = .client_auth, .oid = ExtKeyUsage.oid_client_auth },
    .{ .usage = .code_signing, .oid = ExtKeyUsage.oid_code_signing },
    .{ .usage = .email_protection, .oid = ExtKeyUsage.oid_email_protection },
    .{ .usage = .ipsec_end_system, .oid = ExtKeyUsage.oid_ipsec_end_system },
    .{ .usage = .ipsec_tunnel, .oid = ExtKeyUsage.oid_ipsec_tunnel },
    .{ .usage = .ipsec_user, .oid = ExtKeyUsage.oid_ipsec_user },
    .{ .usage = .time_stamping, .oid = ExtKeyUsage.oid_time_stamping },
    .{ .usage = .ocsp_signing, .oid = ExtKeyUsage.oid_ocsp_signing },
    .{ .usage = .microsoft_server_gated_crypto, .oid = ExtKeyUsage.oid_microsoft_server_gated_crypto },
    .{ .usage = .netscape_server_gated_crypto, .oid = ExtKeyUsage.oid_netscape_server_gated_crypto },
    .{ .usage = .microsoft_commercial_code_signing, .oid = ExtKeyUsage.oid_microsoft_commercial_code_signing },
    .{ .usage = .microsoft_kernel_code_signing, .oid = ExtKeyUsage.oid_microsoft_kernel_code_signing },
};

pub const CertificateType = enum {
    leaf,
    intermediate,
    root,
};

pub const Certificate = struct {
    raw: []const u8,
    raw_tbs_certificate: []const u8,
    version: i64,
    serial_number: math.big.int.Const,
    signature_algorithm: SignatureAlgorithm,
    raw_issuer: []const u8,
    issuer: pkix.Name,
    not_before: datetime.datetime.Datetime,
    not_after: datetime.datetime.Datetime,
    raw_subject: []const u8,
    subject: pkix.Name,
    raw_subject_public_key_info: []const u8,
    public_key_algorithm: crypto.PublicKeyAlgorithm,
    public_key: crypto.PublicKey,

    // basic_constraints_valid indicates whether is_ca is true and max_path_len
    // is not null.
    basic_constraints_valid: bool = false,
    is_ca: bool = false,
    max_path_len: ?u64 = null,

    key_usage: KeyUsage = .{},
    ext_key_usages: []const ExtKeyUsage = &[_]ExtKeyUsage{},
    unknown_usages: []asn1.ObjectIdentifier = &[_]asn1.ObjectIdentifier{},

    subject_key_id: []const u8 = &[_]u8{},
    authority_key_id: []const u8 = &[_]u8{},

    // RFC 5280, 4.2.2.1 (Authority Information Access)
    ocsp_servers: []const []const u8 = &[_][]const u8{},
    issuing_certificate_urls: []const []const u8 = &[_][]const u8{},

    // Subject Alternate Name values. (Note that these values may not be valid
    // if invalid values were contained within a parsed certificate. For
    // example, an element of DNSNames may not be a valid DNS domain name.)
    dns_names: []const []const u8 = &[_][]const u8{},
    email_addresses: []const []const u8 = &[_][]const u8{},
    ip_addresses: []std.net.Address = &[_]std.net.Address{},
    uris: []Uri = &[_]Uri{},

    // Name constraints
    // if true then the name constraints are marked critical.
    permitted_dns_domains_critical: bool = false,
    permitted_dns_domains: []const []const u8 = &[_][]const u8{},
    excluded_dns_domains: []const []const u8 = &[_][]const u8{},
    permitted_ip_ranges: []netx.IpAddressNet = &[_]netx.IpAddressNet{},
    excluded_ip_ranges: []netx.IpAddressNet = &[_]netx.IpAddressNet{},
    permitted_email_addresses: []const []const u8 = &[_][]const u8{},
    excluded_email_addresses: []const []const u8 = &[_][]const u8{},
    permitted_uri_domains: []const []const u8 = &[_][]const u8{},
    excluded_uri_domains: []const []const u8 = &[_][]const u8{},

    policy_identifiers: []asn1.ObjectIdentifier = &[_]asn1.ObjectIdentifier{},

    crl_distribution_points: []const []const u8 = &[_][]const u8{},

    extensions: []pkix.Extension,
    signature: []const u8 = &[_]u8{},
    unhandled_critical_extensions: []*const pkix.Extension = &[_]*const pkix.Extension{},

    pub fn parse(allocator: mem.Allocator, der: []const u8) !Certificate {
        var input = asn1.String.init(der);
        // we read the SEQUENCE including length and tag bytes so that
        // we can populate Certificate.raw, before unwrapping the
        // SEQUENCE so it can be operated on
        input = input.readAsn1Element(.sequence) catch return error.MalformedCertificate;

        var cert = blk: {
            var raw = try allocator.dupe(u8, input.bytes);
            errdefer allocator.free(raw);

            input = asn1.String.init(raw);
            input = input.readAsn1(.sequence) catch return error.MalformedCertificate;

            var tbs = input.readAsn1Element(.sequence) catch return error.MalformedTbsCertificate;
            const raw_tbs_certificate = tbs.bytes;

            // do the same trick again as above to extract the raw
            // bytes for Certificate.RawTBSCertificate
            tbs = tbs.readAsn1(.sequence) catch return error.MalformedTbsCertificate;

            var version = tbs.readOptionalAsn1Integer(
                i64,
                @intToEnum(asn1.TagAndClass, 0).constructed().contextSpecific(),
                allocator,
                0,
            ) catch return error.MalformedVersion;
            if (version < 0) {
                return error.MalformedVersion;
            }
            // for backwards compat reasons Version is one-indexed,
            // rather than zero-indexed as defined in 5280
            version += 1;
            if (version > 3) {
                return error.InvalidVersion;
            }

            // we ignore the presence of negative serial numbers because
            // of their prevalence, despite them being invalid
            // TODO(rolandshoemaker): revist this decision, there are currently
            // only 10 trusted certificates with negative serial numbers
            // according to censys.io.
            var serial_number = tbs.readAsn1Integer(
                math.big.int.Const,
                allocator,
            ) catch return error.MalformedSerialNumber;
            errdefer bigint.deinitConst(serial_number, allocator);

            var sig_ai_seq = tbs.readAsn1(
                .sequence,
            ) catch return error.MalformedSignatureAlgorithmIdentifier;
            // Before parsing the inner algorithm identifier, extract
            // the outer algorithm identifier and make sure that they
            // match.
            var outer_sig_ai_seq = input.readAsn1(
                .sequence,
            ) catch return error.MalformedAlgorithmIdentifier;
            if (!mem.eql(u8, outer_sig_ai_seq.bytes, sig_ai_seq.bytes)) {
                return error.SignatureAlgorithmIdentifierMismatch;
            }
            var sig_ai = try pkix.AlgorithmIdentifier.parse(allocator, &sig_ai_seq);
            defer sig_ai.deinit(allocator);
            const signature_algorithm = try SignatureAlgorithm.fromAlgorithmIdentifier(&sig_ai);

            var issuer_seq = tbs.readAsn1Element(.sequence) catch return error.MalformedIssuer;
            const raw_issuer = issuer_seq.bytes;
            var issuer_rdns = try parseName(allocator, &issuer_seq);
            defer issuer_rdns.deinit(allocator);
            var issuer = try pkix.Name.fromRdnSequence(allocator, &issuer_rdns);
            errdefer issuer.deinit(allocator);

            var validity = tbs.readAsn1(.sequence) catch return error.MalformedValidity;
            var not_before = try parseTime(&validity);
            var not_after = try parseTime(&validity);

            var subject_seq = tbs.readAsn1Element(.sequence) catch return error.MalformedSubject;
            const raw_subject = subject_seq.bytes;
            var subject_rdns = try parseName(allocator, &subject_seq);
            defer subject_rdns.deinit(allocator);
            var subject = try pkix.Name.fromRdnSequence(allocator, &subject_rdns);
            errdefer subject.deinit(allocator);

            var raw_subject_public_key_info: []const u8 = undefined;
            var public_key_algorithm: crypto.PublicKeyAlgorithm = undefined;
            var pk_info = blk2: {
                var spki = tbs.readAsn1Element(.sequence) catch return error.MalformedSpki;
                raw_subject_public_key_info = spki.bytes;
                spki = spki.readAsn1(.sequence) catch return error.MalformedSpki;
                var pk_ai_seq = spki.readAsn1(
                    .sequence,
                ) catch return error.MalformedPublicKeyAlgorithmIdentifier;
                var pk_ai = try pkix.AlgorithmIdentifier.parse(allocator, &pk_ai_seq);
                errdefer pk_ai.deinit(allocator);
                public_key_algorithm = crypto.PublicKeyAlgorithm.fromOid(pk_ai.algorithm);
                var spk = try asn1.BitString.read(&spki, allocator);
                break :blk2 PublicKeyInfo{ .algorithm = pk_ai, .public_key = spk };
            };
            defer pk_info.deinit(allocator);
            var public_key = try parsePublicKey(allocator, public_key_algorithm, &pk_info);
            errdefer public_key.deinit(allocator);

            var extensions = std.ArrayListUnmanaged(pkix.Extension){};
            errdefer memx.deinitArrayListAndElems(pkix.Extension, &extensions, allocator);
            if (version > 1) {
                _ = tbs.skipOptionalAsn1(asn1.TagAndClass.init(1).constructed().contextSpecific()) catch
                    return error.MalformedIssuerUniqueId;
                _ = tbs.skipOptionalAsn1(asn1.TagAndClass.init(2).constructed().contextSpecific()) catch
                    return error.MalformedSubjectUniqueId;
                if (version == 3) {
                    if (tbs.readOptionalAsn1(asn1.TagAndClass.init(3).constructed().contextSpecific()) catch
                        return error.MalformedExtensions) |*extensions_str|
                    {
                        var extensions_str2 = try extensions_str.readAsn1(.sequence);
                        while (!extensions_str2.empty()) {
                            var extension_str = extensions_str2.readAsn1(.sequence) catch
                                return error.MalformedExtension;
                            var ext = try pkix.Extension.parse(&extension_str, allocator);
                            try extensions.append(allocator, ext);
                        }
                    }
                }
            }
            break :blk Certificate{
                .raw = raw,
                .raw_tbs_certificate = raw_tbs_certificate,
                .version = version,
                .serial_number = serial_number,
                .signature_algorithm = signature_algorithm,
                .raw_issuer = raw_issuer,
                .issuer = issuer,
                .not_before = not_before,
                .not_after = not_after,
                .raw_subject = raw_subject,
                .subject = subject,
                .raw_subject_public_key_info = raw_subject_public_key_info,
                .public_key_algorithm = public_key_algorithm,
                .public_key = public_key,
                .extensions = extensions.toOwnedSlice(allocator),
            };
        };
        errdefer cert.deinit(allocator);
        try cert.processExtensions(allocator);

        var signature = try asn1.BitString.read(&input, allocator);
        defer signature.deinit(allocator);
        cert.signature = try signature.rightAlign(allocator);

        return cert;
    }

    pub fn eql(self: *const Certificate, other: *const Certificate) bool {
        return mem.eql(u8, self.raw, other.raw);
    }

    pub fn deinit(self: *Certificate, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        allocator.free(self.serial_number.limbs);
        self.issuer.deinit(allocator);
        self.subject.deinit(allocator);
        self.public_key.deinit(allocator);
        if (self.ext_key_usages.len > 0) allocator.free(self.ext_key_usages);
        memx.deinitSliceAndElems(asn1.ObjectIdentifier, self.unknown_usages, allocator);
        if (self.subject_key_id.len > 0) allocator.free(self.subject_key_id);
        if (self.authority_key_id.len > 0) allocator.free(self.authority_key_id);
        memx.freeElemsAndFreeSlice([]const u8, self.ocsp_servers, allocator);
        memx.freeElemsAndFreeSlice([]const u8, self.issuing_certificate_urls, allocator);
        memx.freeElemsAndFreeSlice([]const u8, self.dns_names, allocator);
        memx.freeElemsAndFreeSlice([]const u8, self.email_addresses, allocator);
        if (self.ip_addresses.len > 0) {
            allocator.free(self.ip_addresses);
        }
        memx.deinitSliceAndElems(Uri, self.uris, allocator);
        memx.deinitSliceAndElems(asn1.ObjectIdentifier, self.policy_identifiers, allocator);
        memx.freeElemsAndFreeSlice([]const u8, self.crl_distribution_points, allocator);

        memx.freeElemsAndFreeSlice([]const u8, self.permitted_dns_domains, allocator);
        memx.freeElemsAndFreeSlice([]const u8, self.excluded_dns_domains, allocator);
        if (self.permitted_ip_ranges.len > 0) {
            allocator.free(self.permitted_ip_ranges);
        }
        if (self.excluded_ip_ranges.len > 0) {
            allocator.free(self.excluded_ip_ranges);
        }
        memx.freeElemsAndFreeSlice([]const u8, self.permitted_email_addresses, allocator);
        memx.freeElemsAndFreeSlice([]const u8, self.excluded_email_addresses, allocator);
        memx.freeElemsAndFreeSlice([]const u8, self.permitted_uri_domains, allocator);
        memx.freeElemsAndFreeSlice([]const u8, self.excluded_uri_domains, allocator);

        memx.deinitSliceAndElems(pkix.Extension, self.extensions, allocator);
        if (self.signature.len > 0) allocator.free(self.signature);
        if (self.unhandled_critical_extensions.len > 0) {
            allocator.free(self.unhandled_critical_extensions);
        }
    }

    pub fn format(
        self: Certificate,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        _ = try writer.write("Certificate{ ");
        try std.fmt.format(writer, "version = {}", .{self.version});
        try std.fmt.format(writer, ", serial_number = {}", .{self.serial_number});
        try std.fmt.format(writer, ", signature_algorithm = {}", .{self.signature_algorithm});
        try std.fmt.format(writer, ", issuer = {}", .{self.issuer});
        try std.fmt.format(writer, ", not_before = ", .{});
        try writeUtcTime(&self.not_before, writer);
        try std.fmt.format(writer, ", not_after = ", .{});
        try writeUtcTime(&self.not_after, writer);
        try std.fmt.format(writer, ", subject = {}", .{self.subject});
        try std.fmt.format(writer, ", public_key_algorithm = {}", .{self.public_key_algorithm});
        try std.fmt.format(writer, ", public_key = {}", .{self.public_key});
        try std.fmt.format(writer, ", key_usage = {}", .{self.key_usage});
        try std.fmt.format(writer, ", ext_key_usages = {any}", .{self.ext_key_usages});
        try std.fmt.format(writer, ", unknown_usages = {any}", .{self.unknown_usages});
        try std.fmt.format(
            writer,
            ", basic_constraints_valid = {}",
            .{self.basic_constraints_valid},
        );
        try std.fmt.format(writer, ", is_ca = {}", .{self.is_ca});
        try std.fmt.format(writer, ", max_path_len = {}", .{self.max_path_len});
        try std.fmt.format(
            writer,
            ", subject_key_id = {s}",
            .{std.fmt.fmtSliceHexLower(self.subject_key_id)},
        );
        try std.fmt.format(
            writer,
            ", authority_key_id = {s}",
            .{std.fmt.fmtSliceHexLower(self.authority_key_id)},
        );
        _ = try writer.write(", ocsp_servers = ");
        try fmtx.formatStringSlice(self.ocsp_servers, fmt, options, writer);
        _ = try writer.write(", issuing_certificate_urls = ");
        try fmtx.formatStringSlice(self.issuing_certificate_urls, fmt, options, writer);
        _ = try writer.write(", dns_names = ");
        try fmtx.formatStringSlice(self.dns_names, fmt, options, writer);
        _ = try writer.write(", email_addresses = ");
        try fmtx.formatStringSlice(self.email_addresses, fmt, options, writer);
        try std.fmt.format(writer, ", ip_addresses = {any}", .{self.ip_addresses});

        _ = try writer.write(", uris = {");
        for (self.uris) |uri, i| {
            if (i > 0) {
                _ = try writer.write(", ");
            }
            try std.fmt.format(writer, "\"{s}\"", .{uri});
        }
        _ = try writer.write("}");

        try std.fmt.format(writer, ", policy_identifiers = {any}", .{self.policy_identifiers});
        _ = try writer.write(", crl_distribution_points = ");
        try fmtx.formatStringSlice(self.crl_distribution_points, fmt, options, writer);

        _ = try writer.write(", permitted_dns_domains = ");
        try fmtx.formatStringSlice(self.permitted_dns_domains, fmt, options, writer);
        _ = try writer.write(", excluded_dns_domains = ");
        try fmtx.formatStringSlice(self.excluded_dns_domains, fmt, options, writer);
        // TODO: print permitted_ip_ranges
        // TODO: print excluded_ip_ranges
        _ = try writer.write(", permitted_email_addresses = ");
        try fmtx.formatStringSlice(self.permitted_email_addresses, fmt, options, writer);
        _ = try writer.write(", excluded_email_addresses = ");
        try fmtx.formatStringSlice(self.excluded_email_addresses, fmt, options, writer);
        _ = try writer.write(", permitted_uri_domains = ");
        try fmtx.formatStringSlice(self.permitted_uri_domains, fmt, options, writer);
        _ = try writer.write(", excluded_uri_domains = ");
        try fmtx.formatStringSlice(self.excluded_uri_domains, fmt, options, writer);

        try std.fmt.format(writer, ", extensions = {any}", .{self.extensions});
        try std.fmt.format(writer, ", signature = {}", .{std.fmt.fmtSliceHexLower(self.signature)});
        _ = try writer.write(" }");
    }

    fn processExtensions(self: *Certificate, allocator: mem.Allocator) !void {
        var unhandled_critical_extensions = std.ArrayListUnmanaged(*const pkix.Extension){};

        for (self.extensions) |*ext| {
            // std.log.debug("Certificate.processExtensions oid={}", .{ext.id});
            var unhandled = false;
            if (ext.id.components.len == 4 and
                mem.startsWith(u32, ext.id.components, &[_]u32{ 2, 5, 29 }))
            {
                switch (ext.id.components[3]) {
                    15 => self.key_usage = try parseKeyUsageExtension(allocator, ext.value),
                    19 => try self.parseBasicConstraintsExtension(ext.value),
                    17 => if (try self.parseSanExtension(allocator, ext.value)) {
                        // If we didn't parse anything then we do the critical check, below.
                        unhandled = true;
                    },
                    30 => if (try self.parseNameConstraintsExtension(allocator, ext)) {
                        unhandled = true;
                    },
                    31 => try self.parseCrlDistributionPointsExtension(allocator, ext.value),
                    35 => self.authority_key_id = try parseAuthorityKeyIdExtension(
                        allocator,
                        ext.value,
                    ),
                    37 => try self.parseExtKeyUsageExtension(allocator, ext.value),
                    14 => self.subject_key_id = try parseSubjectKeyIdExtension(
                        allocator,
                        ext.value,
                    ),
                    32 => try self.parseCertificatePoliciesExtension(allocator, ext.value),
                    else => unhandled = true,
                }
            } else if (ext.id.eql(asn1.ObjectIdentifier.extension_authority_info_access)) {
                try self.parseAuthorityInfoAccessExtension(allocator, ext.value);
            } else {
                // Unknown extensions are recorded if critical.
                unhandled = true;
            }

            if (ext.critical and unhandled) {
                try unhandled_critical_extensions.append(allocator, ext);
            }
        }
        if (unhandled_critical_extensions.items.len > 0) {
            self.unhandled_critical_extensions = unhandled_critical_extensions.toOwnedSlice(
                allocator,
            );
        }
    }

    fn parseExtKeyUsageExtension(
        self: *Certificate,
        allocator: mem.Allocator,
        der: []const u8,
    ) !void {
        var s = asn1.String.init(der);
        var ext_key_usages = std.ArrayListUnmanaged(ExtKeyUsage){};
        errdefer ext_key_usages.deinit(allocator);
        var unknown_usages = std.ArrayListUnmanaged(asn1.ObjectIdentifier){};
        errdefer memx.deinitArrayListAndElems(asn1.ObjectIdentifier, &unknown_usages, allocator);

        s = s.readAsn1(.sequence) catch return error.InvalidExtendedKeyUsages;
        while (!s.empty()) {
            var oid = asn1.ObjectIdentifier.parse(allocator, &s) catch
                return error.InvalidExtendedKeyUsages;
            if (ExtKeyUsage.fromOid(oid)) |eku| {
                try ext_key_usages.append(allocator, eku);
                oid.deinit(allocator);
            } else {
                try unknown_usages.append(allocator, oid);
            }
        }

        if (ext_key_usages.items.len > 0) {
            self.ext_key_usages = ext_key_usages.toOwnedSlice(allocator);
        }
        if (unknown_usages.items.len > 0) {
            self.unknown_usages = unknown_usages.toOwnedSlice(allocator);
        }
    }

    fn parseBasicConstraintsExtension(
        self: *Certificate,
        der: []const u8,
    ) !void {
        var s = asn1.String.init(der);
        s = s.readAsn1(.sequence) catch return error.InvalidBasicConstraints;
        var is_ca = false;
        if (s.peekAsn1Tag(.boolean)) {
            is_ca = s.readAsn1Boolean() catch return error.InvalidBasicConstraints;
        }
        var max_path_len: ?u64 = null;
        if (!s.empty() and s.peekAsn1Tag(.integer)) {
            max_path_len = s.readAsn1Uint64() catch return error.InvalidBasicConstraints;
        }

        self.basic_constraints_valid = true;
        self.is_ca = is_ca;
        self.max_path_len = max_path_len;
    }

    fn parseAuthorityInfoAccessExtension(
        self: *Certificate,
        allocator: mem.Allocator,
        der: []const u8,
    ) !void {
        // RFC 5280 4.2.2.1: Authority Information Access
        var s = asn1.String.init(der);
        s = s.readAsn1(.sequence) catch return error.InvalidAuthorityInfoAccess;
        var ocsp_servers = std.ArrayListUnmanaged([]const u8){};
        errdefer memx.freeElemsAndDeinitArrayList([]const u8, &ocsp_servers, allocator);
        var issuing_certificate_urls = std.ArrayListUnmanaged([]const u8){};
        errdefer memx.freeElemsAndDeinitArrayList([]const u8, &issuing_certificate_urls, allocator);
        while (!s.empty()) {
            var aia_der = s.readAsn1(.sequence) catch return error.InvalidAuthorityInfoAccess;
            var method = asn1.ObjectIdentifier.parse(allocator, &aia_der) catch return error.InvalidAuthorityInfoAccess;
            defer method.deinit(allocator);
            if (!aia_der.peekAsn1Tag(asn1.TagAndClass.init(6).contextSpecific())) {
                continue;
            }
            if (aia_der.readOptionalAsn1(asn1.TagAndClass.init(6).contextSpecific()) catch
                return error.InvalidAuthorityInfoAccess) |inner_der|
            {
                if (method.eql(asn1.ObjectIdentifier.authority_info_access_ocsp)) {
                    try ocsp_servers.append(allocator, try allocator.dupe(u8, inner_der.bytes));
                } else if (method.eql(asn1.ObjectIdentifier.authority_info_access_issuers)) {
                    try issuing_certificate_urls.append(allocator, try allocator.dupe(u8, inner_der.bytes));
                }
            }
        }
        if (ocsp_servers.items.len > 0) {
            self.ocsp_servers = ocsp_servers.toOwnedSlice(allocator);
        }
        if (issuing_certificate_urls.items.len > 0) {
            self.issuing_certificate_urls = issuing_certificate_urls.toOwnedSlice(allocator);
        }
    }

    const name_type_email = 1;
    const name_type_dns = 2;
    const name_type_uri = 6;
    const name_type_ip = 7;

    fn parseSanExtension(
        self: *Certificate,
        allocator: mem.Allocator,
        der: []const u8,
    ) !bool {
        var s = asn1.String.init(der);
        s = s.readAsn1(.sequence) catch return error.InvalidSubjectAlternativeNames;
        var email_addresses = std.ArrayListUnmanaged([]const u8){};
        errdefer memx.freeElemsAndDeinitArrayList([]const u8, &email_addresses, allocator);
        var dns_names = std.ArrayListUnmanaged([]const u8){};
        errdefer memx.freeElemsAndDeinitArrayList([]const u8, &dns_names, allocator);
        var uris = std.ArrayListUnmanaged(Uri){};
        errdefer memx.deinitArrayListAndElems(Uri, &uris, allocator);
        var ip_addresses = std.ArrayListUnmanaged(std.net.Address){};
        errdefer if (ip_addresses.items.len > 0) ip_addresses.deinit(allocator);
        while (!s.empty()) {
            var tag: asn1.TagAndClass = undefined;
            var san_der = s.readAnyAsn1(&tag) catch return error.InvalidSubjectAlternativeNames;
            switch (@enumToInt(tag) ^ 0x80) {
                name_type_email => {
                    const email = san_der.bytes;
                    if (!isValidIa5String(email)) {
                        return error.InvalidSubjectAlternativeNames;
                    }
                    try email_addresses.append(allocator, try allocator.dupe(u8, email));
                },
                name_type_dns => {
                    const name = san_der.bytes;
                    if (!isValidIa5String(name)) {
                        return error.InvalidSubjectAlternativeNames;
                    }
                    try dns_names.append(allocator, try allocator.dupe(u8, name));
                },
                name_type_uri => {
                    var uri = try parseSanExtensionUri(allocator, san_der.bytes);
                    errdefer uri.deinit(allocator);
                    try uris.append(allocator, uri);
                },
                name_type_ip => {
                    const ip_data = san_der.bytes;
                    const address = netx.addressFromBytes(ip_data) catch
                        return error.InvalidSubjectAlternativeNames;
                    try ip_addresses.append(allocator, address);
                },
                else => {},
            }
        }
        var unhandled = true;
        if (email_addresses.items.len > 0) {
            self.email_addresses = email_addresses.toOwnedSlice(allocator);
            unhandled = false;
        }
        if (dns_names.items.len > 0) {
            self.dns_names = dns_names.toOwnedSlice(allocator);
            unhandled = false;
        }
        if (uris.items.len > 0) {
            self.uris = uris.toOwnedSlice(allocator);
            unhandled = false;
        }
        if (ip_addresses.items.len > 0) {
            self.ip_addresses = ip_addresses.toOwnedSlice(allocator);
            unhandled = false;
        }
        return unhandled;
    }

    fn parseCertificatePoliciesExtension(
        self: *Certificate,
        allocator: mem.Allocator,
        der: []const u8,
    ) !void {
        var s = asn1.String.init(der);
        s = s.readAsn1(.sequence) catch return error.InvaliCertificatePolicies;
        var oids = std.ArrayListUnmanaged(asn1.ObjectIdentifier){};
        errdefer memx.deinitArrayListAndElems(asn1.ObjectIdentifier, &oids, allocator);
        while (!s.empty()) {
            var cp = s.readAsn1(.sequence) catch return error.InvaliCertificatePolicies;
            var oid = asn1.ObjectIdentifier.parse(allocator, &cp) catch
                return error.InvaliCertificatePolicies;
            try oids.append(allocator, oid);
        }
        if (oids.items.len > 0) {
            self.policy_identifiers = oids.toOwnedSlice(allocator);
        }
    }

    fn parseCrlDistributionPointsExtension(
        self: *Certificate,
        allocator: mem.Allocator,
        der: []const u8,
    ) !void {
        // RFC 5280, 4.2.1.13

        // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
        //
        // DistributionPoint ::= SEQUENCE {
        //     distributionPoint       [0]     DistributionPointName OPTIONAL,
        //     reasons                 [1]     ReasonFlags OPTIONAL,
        //     cRLIssuer               [2]     GeneralNames OPTIONAL }
        //
        // DistributionPointName ::= CHOICE {
        //     fullName                [0]     GeneralNames,
        //     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
        var s = asn1.String.init(der);
        s = s.readAsn1(.sequence) catch return error.InvaliCrlDistributionPoints;
        var uris = std.ArrayListUnmanaged([]const u8){};
        errdefer memx.freeElemsAndDeinitArrayList([]const u8, &uris, allocator);
        while (!s.empty()) {
            var dp_der = s.readAsn1(.sequence) catch return error.InvaliCrlDistributionPoints;
            if (dp_der.readOptionalAsn1(asn1.TagAndClass.init(0).constructed().contextSpecific()) catch
                return error.InvaliCrlDistributionPoints) |*dp_name_der|
            {
                var dp_name_der2 = dp_name_der.readAsn1(
                    asn1.TagAndClass.init(0).constructed().contextSpecific(),
                ) catch
                    return error.InvaliCrlDistributionPoints;
                while (!dp_name_der2.empty()) {
                    if (dp_name_der2.readOptionalAsn1(asn1.TagAndClass.init(6).contextSpecific()) catch
                        return error.InvaliCrlDistributionPoints) |uri_der|
                    {
                        try uris.append(allocator, try allocator.dupe(u8, uri_der.bytes));
                    } else {
                        break;
                    }
                }
            }
        }
        if (uris.items.len > 0) {
            self.crl_distribution_points = uris.toOwnedSlice(allocator);
        }
    }

    fn parseNameConstraintsExtension(
        self: *Certificate,
        allocator: mem.Allocator,
        ext: *const pkix.Extension,
    ) !bool {
        // RFC 5280, 4.2.1.10

        // NameConstraints ::= SEQUENCE {
        //      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
        //      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
        //
        // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
        //
        // GeneralSubtree ::= SEQUENCE {
        //      base                    GeneralName,
        //      minimum         [0]     BaseDistance DEFAULT 0,
        //      maximum         [1]     BaseDistance OPTIONAL }
        //
        // BaseDistance ::= INTEGER (0..MAX)

        var outer = asn1.String.init(ext.value);
        var toplevel = outer.readAsn1(.sequence) catch
            return error.InvalidNameConstraintsExtension;
        if (!outer.empty()) return error.InvalidNameConstraintsExtension;
        var permitted = toplevel.readOptionalAsn1(
            asn1.TagAndClass.init(0).contextSpecific().constructed(),
        ) catch
            return error.InvalidNameConstraintsExtension;
        var excluded = toplevel.readOptionalAsn1(
            asn1.TagAndClass.init(1).contextSpecific().constructed(),
        ) catch
            return error.InvalidNameConstraintsExtension;
        if (!toplevel.empty()) return error.InvalidNameConstraintsExtension;

        if ((permitted == null and excluded == null) or
            ((permitted == null or permitted.?.empty()) and
            (excluded == null or excluded.?.empty())))
        {
            return error.InvalidNameConstraintsExtension;
        }

        var unhandled = false;
        if (permitted) |permitted2| {
            var permitted3 = permitted2;
            if (self.parseNameConstraintsExtensionSubtrees(
                allocator,
                &permitted3,
                &self.permitted_dns_domains,
                &self.permitted_ip_ranges,
                &self.permitted_email_addresses,
                &self.permitted_uri_domains,
            ) catch return error.InvalidNameConstraintsExtension) {
                unhandled = true;
            }
        }
        if (excluded) |excluded2| {
            var excluded3 = excluded2;
            if (self.parseNameConstraintsExtensionSubtrees(
                allocator,
                &excluded3,
                &self.excluded_dns_domains,
                &self.excluded_ip_ranges,
                &self.excluded_email_addresses,
                &self.excluded_uri_domains,
            ) catch return error.InvalidNameConstraintsExtension) {
                unhandled = true;
            }
        }
        self.permitted_dns_domains_critical = ext.critical;
        return unhandled;
    }

    fn parseNameConstraintsExtensionSubtrees(
        self: *Certificate,
        allocator: mem.Allocator,
        subtrees: *asn1.String,
        dns_names: *[]const []const u8,
        ips: *[]netx.IpAddressNet,
        emails: *[]const []const u8,
        uri_domains: *[]const []const u8,
    ) !bool {
        _ = self;
        var dns_name_list = std.ArrayListUnmanaged([]const u8){};
        errdefer memx.freeElemsAndDeinitArrayList([]const u8, &dns_name_list, allocator);
        var ip_list = std.ArrayListUnmanaged(netx.IpAddressNet){};
        errdefer ip_list.deinit(allocator);
        var email_list = std.ArrayListUnmanaged([]const u8){};
        errdefer memx.freeElemsAndDeinitArrayList([]const u8, &email_list, allocator);
        var uri_domain_list = std.ArrayListUnmanaged([]const u8){};
        errdefer memx.freeElemsAndDeinitArrayList([]const u8, &uri_domain_list, allocator);

        var unhandled = false;
        while (!subtrees.empty()) {
            var seq = subtrees.readAsn1(.sequence) catch
                return error.InvalidNameConstraintsExtension;
            var tag: asn1.TagAndClass = undefined;
            var value = seq.readAnyAsn1(&tag) catch
                return error.InvalidNameConstraintsExtension;

            const dns_tag = @intToEnum(asn1.TagAndClass, 2 | asn1.TagAndClass.class_context_specific);
            const email_tag = @intToEnum(asn1.TagAndClass, 1 | asn1.TagAndClass.class_context_specific);
            const ip_tag = @intToEnum(asn1.TagAndClass, 7 | asn1.TagAndClass.class_context_specific);
            const uri_tag = @intToEnum(asn1.TagAndClass, 6 | asn1.TagAndClass.class_context_specific);

            switch (tag) {
                dns_tag => {
                    const domain = value.bytes;
                    if (!isValidIa5String(domain)) {
                        return error.InvalidNameConstraintsExtension;
                    }
                    const trimmed_domain = if (mem.startsWith(u8, domain, ".")) blk: {
                        // constraints can have a leading
                        // period to exclude the domain
                        // itself, but that's not valid in a
                        // normal domain name.
                        break :blk domain[1..];
                    } else domain;
                    if (domainToReverseLabels(allocator, trimmed_domain)) |reverse_labels| {
                        memx.freeElemsAndFreeSlice([]const u8, reverse_labels, allocator);
                    } else |_| {
                        return error.InvalidNameConstraintsExtension;
                    }
                    try dns_name_list.append(allocator, try allocator.dupe(u8, domain));
                },
                ip_tag => {
                    var mask: []const u8 = undefined;
                    var ip_net: netx.IpAddressNet = undefined;
                    switch (value.bytes.len) {
                        8 => {
                            mask = value.bytes[4..8];
                            ip_net = netx.IpAddressNet{
                                .in = netx.Ip4AddressNet{
                                    .ip = std.net.Ip4Address.init(value.bytes[0..4].*, 0),
                                    .mask = mask[0..4].*,
                                },
                            };
                        },
                        32 => {
                            mask = value.bytes[16..32];
                            ip_net = netx.IpAddressNet{
                                .in6 = netx.Ip6AddressNet{
                                    .ip = std.net.Ip6Address.init(value.bytes[0..16].*, 0, 0, 0),
                                    .mask = mask[0..16].*,
                                },
                            };
                        },
                        else => return error.InvalidNameConstraintsExtension,
                    }
                    if (!isValidIpMask(mask)) {
                        return error.InvalidNameConstraintsExtension;
                    }
                    try ip_list.append(allocator, ip_net);
                },
                email_tag => {
                    const constraint = value.bytes;
                    if (!isValidIa5String(constraint)) {
                        return error.InvalidNameConstraintsExtension;
                    }
                    // If the constraint contains an @ then
                    // it specifies an exact mailbox name.
                    if (memx.containsScalar(u8, constraint, '@')) {
                        if (Rfc2821Mailbox.parse(allocator, constraint)) |*mailbox| {
                            mailbox.deinit(allocator);
                        } else |_| {
                            return error.InvalidNameConstraintsExtension;
                        }
                    } else {
                        // Otherwise it's a domain name.
                        const domain = if (mem.startsWith(u8, constraint, "."))
                            constraint[1..]
                        else
                            constraint;
                        if (domainToReverseLabels(allocator, domain)) |reverse_labels| {
                            memx.freeElemsAndFreeSlice([]const u8, reverse_labels, allocator);
                        } else |_| {
                            return error.InvalidNameConstraintsExtension;
                        }
                    }
                    try email_list.append(allocator, try allocator.dupe(u8, constraint));
                },
                uri_tag => {
                    const domain = value.bytes;
                    if (!isValidIa5String(domain)) {
                        return error.InvalidNameConstraintsExtension;
                    }
                    if (std.net.Address.parseIp(domain, 0)) |_| {
                        std.log.warn(
                            "x509: failed to parse URI constraint {s}: cannot be IP address",
                            .{domain},
                        );
                        return error.InvalidNameConstraintsExtension;
                    } else |_| {}
                    const trimmed_domain = if (mem.startsWith(u8, domain, ".")) blk: {
                        // constraints can have a leading
                        // period to exclude the domain
                        // itself, but that's not valid in a
                        // normal domain name.
                        break :blk domain[1..];
                    } else domain;
                    if (domainToReverseLabels(allocator, trimmed_domain)) |reverse_labels| {
                        memx.freeElemsAndFreeSlice([]const u8, reverse_labels, allocator);
                    } else |_| {
                        return error.InvalidNameConstraintsExtension;
                    }
                    try uri_domain_list.append(allocator, try allocator.dupe(u8, domain));
                },
                else => unhandled = true,
            }
        }
        if (dns_name_list.items.len > 0) {
            dns_names.* = dns_name_list.toOwnedSlice(allocator);
        }
        if (ip_list.items.len > 0) {
            ips.* = ip_list.toOwnedSlice(allocator);
        }
        if (email_list.items.len > 0) {
            emails.* = email_list.toOwnedSlice(allocator);
        }
        if (uri_domain_list.items.len > 0) {
            uri_domains.* = uri_domain_list.toOwnedSlice(allocator);
        }
        return unhandled;
    }

    pub fn verify(
        self: *const Certificate,
        allocator: mem.Allocator,
        opts: *const VerifyOptions,
    ) !VerifiedCertChains {
        // Platform-specific verification needs the ASN.1 contents so
        // this makes the behavior consistent across platforms.
        if (self.raw.len == 0) {
            return error.NotParsed;
        }

        try self.isValid(allocator, .leaf, &[_]*Certificate{}, opts);

        if (opts.dns_name.len > 0) {
            try self.verifyHostname(opts.dns_name);
        }

        var candidate_chains = if (opts.roots.contains(self)) blk: {
            var chains = try allocator.alloc([]*const Certificate, 1);
            errdefer allocator.free(chains);
            chains[0] = try allocator.dupe(*const Certificate, &[_]*const Certificate{self});
            break :blk chains;
        } else blk: {
            var arena_allocator = std.heap.ArenaAllocator.init(allocator);
            defer arena_allocator.deinit();
            var allocator2 = arena_allocator.allocator();

            var cache = CertChainCache.init(allocator2);
            defer {
                deinitCertChainCache(&cache, allocator2);
                cache.deinit();
            }
            var current_chain = try allocator2.dupe(*const Certificate, &[_]*const Certificate{self});
            defer allocator2.free(current_chain);
            var sig_checks: usize = 0;
            var chains = try self.buildChains(allocator2, &cache, current_chain, opts, &sig_checks);
            break :blk try dupeChains(allocator, chains);
        };
        errdefer {
            for (candidate_chains) |chain| {
                allocator.free(chain);
            }
            allocator.free(candidate_chains);
        }

        const key_usages = if (opts.key_usages.len == 0)
            &[_]ExtKeyUsage{.server_auth}
        else
            opts.key_usages;

        // If any key usage is acceptable then we're done.
        if (memx.containsScalar(ExtKeyUsage, key_usages, .any)) {
            return VerifiedCertChains.init(candidate_chains);
        }

        var ret_chains = std.ArrayListUnmanaged([]*const Certificate){};
        errdefer ret_chains.deinit(allocator);
        for (candidate_chains) |candidate| {
            if (try checkChainForKeyUsage(allocator, candidate, key_usages)) {
                try ret_chains.append(allocator, candidate);
            }
        }

        if (ret_chains.items.len == 0) {
            return error.CertificateIncompatibleUsage;
        }

        allocator.free(candidate_chains);
        return VerifiedCertChains.init(ret_chains.toOwnedSlice(allocator));
    }

    const BuildChainsError = error{
        ConstraintViolation,
        InvalidCertificate,
        SignatureCheckAttemptsExceedsLimit,
        UnknownAuthority,
    } || CheckSignatureError || IsValidError;

    fn buildChains(
        self: *const Certificate,
        allocator: mem.Allocator,
        cache: *CertChainCache,
        current_chain: []*const Certificate,
        opts: *const VerifyOptions,
        sig_checks: *usize,
    ) BuildChainsError![]const []*const Certificate {
        // TODO: Fix memory leaks. Currently workarounded with ArenaAllocator.
        std.log.debug(
            "buildChains start, c=0x{x} {s}",
            .{ @ptrToInt(self), self.subject.common_name },
        );

        for (current_chain) |c, i| {
            std.log.debug(
                "buildChains start, chain #{}=0x{x} {s}",
                .{ i, @ptrToInt(c), c.subject.common_name },
            );
        }
        var chain_list = std.ArrayListUnmanaged([]*const Certificate){};
        errdefer chain_list.deinit(allocator);

        var roots = try opts.roots.findPotentialParents(self, allocator);
        defer if (roots.len > 0) allocator.free(roots);
        for (roots) |root| {
            std.log.debug(
                "buildChains before considerCandidate, root=0x{x} {s}",
                .{ @ptrToInt(root), root.subject.common_name },
            );

            try considerCandidate(
                self,
                allocator,
                .root,
                root,
                current_chain,
                opts,
                cache,
                sig_checks,
                &chain_list,
            );
        }

        if (opts.intermediates) |intermediates| {
            var intermediates2 = try intermediates.findPotentialParents(self, allocator);
            defer if (intermediates2.len > 0) allocator.free(intermediates2);
            for (intermediates2) |intermediate| {
                std.log.debug(
                    "buildChains before considerCandidate, intermediate=0x{x} {s}",
                    .{ @ptrToInt(intermediate), intermediate.subject.common_name },
                );
                try considerCandidate(
                    self,
                    allocator,
                    .intermediate,
                    intermediate,
                    current_chain,
                    opts,
                    cache,
                    sig_checks,
                    &chain_list,
                );
            }
        }

        if (chain_list.items.len == 0) {
            return error.UnknownAuthority;
        }

        return chain_list.toOwnedSlice(allocator);
    }

    pub const CheckSignatureFromError = error{
        ConstraintViolation,
        UnsupportedAlgorithm,
    } || CheckSignatureError;

    // CheckSignatureFrom verifies that the signature on c is a valid signature
    // from parent.
    pub fn checkSignatureFrom(
        self: *const Certificate,
        allocator: mem.Allocator,
        parent: *const Certificate,
    ) CheckSignatureFromError!void {
        // RFC 5280, 4.2.1.9:
        // "If the basic constraints extension is not present in a version 3
        // certificate, or the extension is present but the cA boolean is not
        // asserted, then the certified public key MUST NOT be used to verify
        // certificate signatures."
        if ((parent.version == 3 and !parent.basic_constraints_valid) or
            (parent.basic_constraints_valid and !parent.is_ca))
        {
            return error.ConstraintViolation;
        }

        if (!parent.key_usage.is_none() and parent.key_usage.cert_sign == 0) {
            return error.ConstraintViolation;
        }

        if (parent.public_key_algorithm == .unknown) {
            return error.UnsupportedAlgorithm;
        }

        // TODO: don't ignore the path length constraint.

        try parent.checkSignature(
            allocator,
            self.signature_algorithm,
            self.raw_tbs_certificate,
            self.signature,
        );
    }

    // CheckSignature verifies that signature is a valid signature over signed from
    // self's public key.
    fn checkSignature(
        self: *const Certificate,
        allocator: mem.Allocator,
        algo: SignatureAlgorithm,
        signed: []const u8,
        signature: []const u8,
    ) CheckSignatureError!void {
        try checkSignaturePublicKey(allocator, algo, signed, signature, self.public_key);
    }

    // max_chain_signature_checks is the maximum number of checkSignatureFrom calls
    // that an invocation of buildChains will (transitively) make. Most chains are
    // less than 15 certificates long, so this leaves space for multiple chains and
    // for failed checks due to different intermediates having the same Subject.
    const max_chain_signature_checks = 100;

    pub fn verifyHostname(
        self: *const Certificate,
        hostname: []const u8,
    ) !void {
        std.log.debug("Certificate.verifyHostname start, hostname={s}", .{hostname});
        // IP addresses may be written in [ ].
        const candidate_ip = if (hostname.len >= 3 and
            hostname[0] == '[' and hostname[hostname.len - 1] == ']')
            hostname[1 .. hostname.len - 1]
        else
            hostname;
        if (std.net.Address.parseIp(candidate_ip, 0)) |ip| {
            // We only match IP addresses against IP SANs.
            // See RFC 6125, Appendix B.2.
            for (self.ip_addresses) |candidate| {
                if (ip.eql(candidate)) {
                    std.log.debug("Certificate.verifyHostname IP matched", .{});
                    return;
                }
            }
            return error.CertificateHostname;
        } else |_| {}

        const candidate_name = hostname;
        const valid_candidate_name = validHostnameInput(candidate_name);
        for (self.dns_names) |match| {
            // Ideally, we'd only match valid hostnames according to RFC 6125 like
            // browsers (more or less) do, but in practice Go is used in a wider
            // array of contexts and can't even assume DNS resolution. Instead,
            // always allow perfect matches, and only apply wildcard and trailing
            // dot processing to valid hostnames.
            if (valid_candidate_name and validHostnamePattern(match)) {
                if (matchHostnames(match, candidate_name)) {
                    std.log.debug("Certificate.verifyHostname wildcard hostname matched", .{});
                    return;
                }
            } else {
                if (matchExactly(match, candidate_name)) {
                    std.log.debug("Certificate.verifyHostname exact hostname matched", .{});
                    return;
                }
            }
        }
        std.log.debug("Certificate.verifyHostname not matched", .{});
        return error.CertificateHostname;
    }

    const IsValidError = error{
        CannotParseDnsName,
        InternalError,
        InvalidCertificate,
        InvalidIpSan,
        InvalidMailbox,
        InvalidSubjectAlternativeNames,
        OutOfMemory,
        UnhandledCriticalExtension,
    } || Uri.ParseError;

    fn isValid(
        self: *const Certificate,
        allocator: mem.Allocator,
        cert_type: CertificateType,
        current_chain: []*const Certificate,
        opts: *const VerifyOptions,
    ) IsValidError!void {
        if (self.unhandled_critical_extensions.len > 0) {
            return error.UnhandledCriticalExtension;
        }

        if (current_chain.len > 0) {
            const child = current_chain[current_chain.len - 1];
            if (!mem.eql(u8, child.raw_issuer, self.raw_subject)) {
                return error.InvalidCertificate;
            }
        }

        var now = opts.current_time orelse datetime.datetime.Datetime.now();
        if (now.lt(self.not_before)) {
            return error.InvalidCertificate;
        } else if (now.gt(self.not_after)) {
            return error.InvalidCertificate;
        }

        const max_constraint_comparisons = opts.max_constraint_comparisons orelse 250000;
        var comparison_count: usize = 0;

        var leaf: ?*const Certificate = null;
        if (cert_type == .intermediate or cert_type == .root) {
            if (current_chain.len == 0) {
                return error.InternalError;
            }
            leaf = current_chain[0];
        }

        if ((cert_type == .intermediate or cert_type == .root) and
            self.hasNameConstraints() and leaf.?.hasSanExtension())
        {
            // TODO: implement
            const der = self.getSanExtension().?;
            var s = asn1.String.init(der);
            s = s.readAsn1(.sequence) catch return error.InvalidSubjectAlternativeNames;
            // var email_addresses = std.ArrayListUnmanaged([]const u8){};
            // errdefer memx.freeElemsAndDeinitArrayList([]const u8, &email_addresses, allocator);
            // var dns_names = std.ArrayListUnmanaged([]const u8){};
            // errdefer memx.freeElemsAndDeinitArrayList([]const u8, &dns_names, allocator);
            // var uris = std.ArrayListUnmanaged([]const u8){};
            // errdefer memx.freeElemsAndDeinitArrayList([]const u8, &uris, allocator);
            // var ip_addresses = std.ArrayListUnmanaged(std.net.Address){};
            // errdefer if (ip_addresses.items.len > 0) ip_addresses.deinit(allocator);
            while (!s.empty()) {
                var tag: asn1.TagAndClass = undefined;
                var san_der = s.readAnyAsn1(&tag) catch return error.InvalidSubjectAlternativeNames;
                switch (@enumToInt(tag) ^ 0x80) {
                    name_type_email => try verifyEmailSan(
                        self,
                        allocator,
                        &comparison_count,
                        max_constraint_comparisons,
                        san_der.bytes,
                    ),
                    name_type_dns => try verifyDnsSan(
                        self,
                        allocator,
                        &comparison_count,
                        max_constraint_comparisons,
                        san_der.bytes,
                    ),
                    name_type_uri => try verifyUriSan(
                        self,
                        allocator,
                        &comparison_count,
                        max_constraint_comparisons,
                        san_der.bytes,
                    ),
                    name_type_ip => try verifyIpSan(
                        self,
                        allocator,
                        &comparison_count,
                        max_constraint_comparisons,
                        san_der.bytes,
                    ),
                    else => {},
                }
            }
        }
    }

    fn hasNameConstraints(self: *const Certificate) bool {
        return oidInExtensions(asn1.ObjectIdentifier.extension_name_constraints, self.extensions);
    }

    fn hasSanExtension(self: *const Certificate) bool {
        return oidInExtensions(asn1.ObjectIdentifier.extension_subject_alt_name, self.extensions);
    }

    fn getSanExtension(self: *const Certificate) ?[]const u8 {
        for (self.extensions) |*ext| {
            if (ext.id.eql(asn1.ObjectIdentifier.extension_subject_alt_name)) {
                return ext.value;
            }
        }
        return null;
    }
};

fn dupeChains(
    allocator: mem.Allocator,
    chains: []const []*const Certificate,
) error{OutOfMemory}![]const []*const Certificate {
    var chains2 = try allocator.alloc([]*const Certificate, chains.len);
    for (chains) |chain, i| {
        chains2[i] = try allocator.dupe(*const Certificate, chain);
    }
    return chains2;
}

const CheckSignatureError = error{
    UnsupportedAlgorithm,
    SignaturePublicKeyAlgoMismatch,
} || rsa.VerifyPkcs1v15Error;

// checkSignaturePublicKey verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
fn checkSignaturePublicKey(
    allocator: mem.Allocator,
    algo: SignatureAlgorithm,
    signed: []const u8,
    signature: []const u8,
    public_key: crypto.PublicKey,
) CheckSignatureError!void {
    var hash_type: ?HashType = null;
    var pub_key_algo: ?crypto.PublicKeyAlgorithm = null;
    for (signature_algorithm_details) |detail| {
        if (detail.algo == algo) {
            hash_type = detail.hash_type;
            pub_key_algo = detail.pub_key_algo;
        }
    }
    if (hash_type == null) {
        return error.UnsupportedAlgorithm;
    }

    const signed2 = if (hash_type.? == .direct_signing) blk: {
        break :blk try allocator.dupe(u8, signed);
    } else blk: {
        var h = crypto.Hash.init(hash_type.?);
        h.update(signed);
        break :blk try h.allocFinal(allocator);
    };
    defer allocator.free(signed2);

    switch (public_key) {
        .rsa => |*k| {
            if (pub_key_algo.? != .rsa) {
                return error.SignaturePublicKeyAlgoMismatch;
            }
            if (algo.is_rsa_pss()) {
                @panic("not implemented yet");
            } else {
                try rsa.verifyPkcs1v15(allocator, k, hash_type.?, signed2, signature);
            }
        },
        .ecdsa => |k| {
            if (pub_key_algo.? != .ecdsa) {
                return error.SignaturePublicKeyAlgoMismatch;
            }
            _ = k;
            @panic("not implemented yet");
        },
        .ed25519 => |k| {
            if (pub_key_algo.? != .ed25519) {
                return error.SignaturePublicKeyAlgoMismatch;
            }
            _ = k;
            @panic("not implemented yet");
        },
        else => return error.UnsupportedAlgorithm,
    }
    _ = signature;
}

const CertChainCache = std.AutoHashMap(*const Certificate, []const []*const Certificate);

fn deinitCertChainCache(cache: *CertChainCache, allocator: mem.Allocator) void {
    while (true) {
        if (cache.iterator().next()) |*entry| {
            var chains = entry.value_ptr.*;
            for (chains) |chain| {
                allocator.free(chain);
            }
            allocator.free(chains);
            _ = cache.remove(entry.key_ptr.*);
        } else {
            break;
        }
    }
}

fn considerCandidate(
    c: *const Certificate,
    allocator: mem.Allocator,
    cert_type: CertificateType,
    candidate: *const Certificate,
    current_chain: []*const Certificate,
    opts: *const VerifyOptions,
    cache: *CertChainCache,
    sig_checks: *usize,
    chains: *std.ArrayListUnmanaged([]*const Certificate),
) Certificate.BuildChainsError!void {
    for (current_chain) |cert| {
        if (cert.eql(candidate)) {
            return;
        }
    }

    sig_checks.* += 1;
    if (sig_checks.* >= Certificate.max_chain_signature_checks) {
        return error.SignatureCheckAttemptsExceedsLimit;
    }

    try c.checkSignatureFrom(allocator, candidate);

    try candidate.isValid(allocator, cert_type, current_chain, opts);

    switch (cert_type) {
        .root => {
            var chain = try appendToFreshChain(allocator, current_chain, candidate);
            errdefer allocator.free(chain);
            try chains.append(allocator, chain);
        },
        .intermediate => {
            var child_chains = if (cache.get(candidate)) |child_chains2|
                child_chains2
            else blk: {
                var chain = try appendToFreshChain(allocator, current_chain, candidate);
                errdefer allocator.free(chain);
                var child_chains2 = try candidate.buildChains(allocator, cache, chain, opts, sig_checks);
                try cache.put(candidate, child_chains2);
                break :blk child_chains2;
            };
            try chains.appendSlice(allocator, child_chains);
        },
        else => {},
    }
}

fn appendToFreshChain(
    allocator: mem.Allocator,
    chain: []*const Certificate,
    cert: *const Certificate,
) ![]*const Certificate {
    var new_chain = try allocator.alloc(*const Certificate, chain.len + 1);
    mem.copy(*const Certificate, new_chain, chain);
    new_chain[chain.len] = cert;
    return new_chain;
}

fn parseSanExtensionUri(allocator: mem.Allocator, input: []const u8) !Uri {
    if (!isValidIa5String(input)) {
        return error.InvalidUri;
    }
    var uri = try Uri.parse(allocator, input);
    errdefer uri.deinit(allocator);

    if (uri.components.host) |host| {
        if (domainToReverseLabels(allocator, host)) |reverse_labels| {
            memx.freeElemsAndFreeSlice([]const u8, reverse_labels, allocator);
        } else |_| {
            return error.InvalidNameConstraintsExtension;
        }
    }

    return uri;
}

fn oidInExtensions(oid: asn1.ObjectIdentifier, extensions: []const pkix.Extension) bool {
    for (extensions) |*ext| {
        if (ext.id.eql(oid)) {
            return true;
        }
    }
    return false;
}

// isValidIpMask reports whether mask consists of zero or more 1 bits, followed by zero bits.
fn isValidIpMask(mask: []const u8) bool {
    var seen_zero = false;
    for (mask) |b| {
        if (seen_zero) {
            if (b != 0) {
                return false;
            }

            continue;
        }

        switch (b) {
            0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe => seen_zero = true,
            0xff => {},
            else => return false,
        }
    }
    return true;
}

fn isValidIa5String(s: []const u8) bool {
    for (s) |b| {
        // Per RFC5280 "IA5String is limited to the set of ASCII characters"
        if (!std.ascii.isASCII(b)) {
            return false;
        }
    }
    return true;
}

fn parseKeyUsageExtension(allocator: mem.Allocator, der: []const u8) !KeyUsage {
    var s = asn1.String.init(der);
    var usage_bits = asn1.BitString.read(&s, allocator) catch return error.InvalidKeyUsage;
    defer usage_bits.deinit(allocator);

    return KeyUsage{
        .digital_signature = usage_bits.at(0),
        .content_commitment = usage_bits.at(1),
        .key_encipherment = usage_bits.at(2),
        .data_encipherment = usage_bits.at(3),
        .key_agreement = usage_bits.at(4),
        .cert_sign = usage_bits.at(5),
        .crl_sign = usage_bits.at(6),
        .encipher_only = usage_bits.at(7),
        .decipher_only = usage_bits.at(8),
    };
}

fn parseSubjectKeyIdExtension(allocator: mem.Allocator, der: []const u8) ![]const u8 {
    // RFC 5280, 4.2.1.2
    var s = asn1.String.init(der);
    var skid = s.readAsn1(.octet_string) catch return error.InvalidSubjectKeyId;
    return try allocator.dupe(u8, skid.bytes);
}

fn parseAuthorityKeyIdExtension(allocator: mem.Allocator, der: []const u8) ![]const u8 {
    // RFC 5280, 4.2.1.1
    var s = asn1.String.init(der);
    s = s.readAsn1(.sequence) catch return error.InvalidAuthorityKeyId;
    if (s.readOptionalAsn1(asn1.TagAndClass.init(0).contextSpecific()) catch
        return error.InvalidAuthorityKeyId) |akid|
    {
        return try allocator.dupe(u8, akid.bytes);
    }
    return &[_]u8{};
}

fn parsePublicKey(
    allocator: mem.Allocator,
    algo: crypto.PublicKeyAlgorithm,
    key_data: *const PublicKeyInfo,
) !crypto.PublicKey {
    var pk = try key_data.public_key.rightAlign(allocator);
    defer allocator.free(pk);
    var der = asn1.String.init(pk);
    switch (algo) {
        .rsa => {
            // RSA public keys must have a NULL in the parameters.
            // See RFC 3279, Section 2.3.1.
            if (key_data.algorithm.parameters) |params| {
                if (!mem.eql(u8, params.full_bytes, asn1.null_bytes)) {
                    return error.RsaKeyMissingNullParameters;
                }
            } else return error.RsaKeyMissingNullParameters;
            der = der.readAsn1(.sequence) catch return error.InvalidRsaPublicKey;
            var n = der.readAsn1Integer(math.big.int.Const, allocator) catch
                return error.InvalidRsaModulus;
            errdefer bigint.deinitConst(n, allocator);
            const e = der.readAsn1Integer(i64, allocator) catch
                return error.InvalidRsaPublicExponent;
            if (!n.positive) {
                return error.NonPositiveRsaModulus;
            }
            if (e <= 0) {
                return error.NonPositiveRsaPublicExponent;
            }
            return crypto.PublicKey{ .rsa = .{ .modulus = n, .exponent = @intCast(u64, e) } };
        },
        .ecdsa => {
            var named_curve_oid = if (key_data.algorithm.parameters) |params| blk: {
                var params_der = asn1.String.init(params.full_bytes);
                break :blk asn1.ObjectIdentifier.parse(allocator, &params_der) catch
                    return error.InvalidEcdsaParameters;
            } else return error.InvalidEcdsaParameters;
            defer named_curve_oid.deinit(allocator);
            if (CurveId.fromOid(named_curve_oid)) |curve_id| {
                const data = der.bytes;
                if (data.len == 0 or data[0] != 4) { // uncompressed form
                    return error.InvalidCurvePoints;
                }
                const pub_key = ecdsa.PublicKey.init(curve_id, data[1..]) catch
                    return error.InvalidCurvePoints;
                return crypto.PublicKey{ .ecdsa = pub_key };
            }
            return error.UnsupportedEllipticCurve;
        },
        else => {
            std.log.err("unsupported public_key type, algo={}", .{algo});
            return crypto.PublicKey{ .unknown = {} };
        },
    }
}

const PrivateKey = struct {};

fn parsePrivateKey(allocator: mem.Allocator, der: *asn1.String) !PrivateKey {
    _ = allocator;
    _ = der;
    @panic("not implemented yet");
}

// parsePkcs8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, or a ed25519.PrivateKey.
// More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
pub fn parsePkcs8PrivateKey(allocator: mem.Allocator, der: []const u8) !PrivateKey {
    _ = allocator;
    _ = der;
    @panic("not implemented yet");
}

const Pkcs8 = struct {
    version: i64,
    algo: pkix.AlgorithmIdentifier,
    private_key: []const u8,

    pub fn deinit(self: *Pkcs8, allocator: mem.Allocator) void {
        self.algo.deinit(allocator);
        if (self.private_key.len > 0) allocator.free(self.private_key);
    }
};

fn parseName(allocator: mem.Allocator, raw: *asn1.String) !pkix.RdnSequence {
    return try pkix.RdnSequence.parse(allocator, raw);
}

fn parseTime(der: *asn1.String) !datetime.datetime.Datetime {
    if (der.peekAsn1Tag(.utc_time)) {
        var s = try der.readAsn1(.utc_time);
        const value = s.bytes;
        if (value.len < 13) return error.MalformedUtcTime;

        const year = blk: {
            const yy = std.fmt.parseInt(u16, value[0..2], 10) catch return error.MalformedUtcTime;
            // UTCTime only encodes times prior to 2050.
            // See https://tools.ietf.org/html/rfc5280#section-4.1.2.5.1
            break :blk yy + @as(u16, if (yy < 50) 2000 else 1900);
        };
        const month = std.fmt.parseInt(u8, value[2..4], 10) catch return error.MalformedUtcTime;
        const day = std.fmt.parseInt(u8, value[4..6], 10) catch return error.MalformedUtcTime;
        const hour = std.fmt.parseInt(u8, value[6..8], 10) catch return error.MalformedUtcTime;
        const minute = std.fmt.parseInt(u8, value[8..10], 10) catch return error.MalformedUtcTime;
        const second = std.fmt.parseInt(u8, value[10..12], 10) catch return error.MalformedUtcTime;
        if (value[12] != 'Z') return error.MalformedUtcTime;
        return datetime.datetime.Datetime.create(
            year,
            month,
            day,
            hour,
            minute,
            second,
            0,
            &datetime.timezones.UTC,
        );
    } else if (der.peekAsn1Tag(.generalized_time)) {
        return try readASN1GeneralizedTime(der);
    } else {
        return error.UnsupportedTimeFormat;
    }
}

fn readASN1GeneralizedTime(der: *asn1.String) !datetime.datetime.Datetime {
    var t = try der.readAsn1(.generalized_time);
    const value = t.bytes;
    if (value.len < "20060102150405Z".len) return error.MalformedGeneralizedTime;

    const year = std.fmt.parseInt(u16, value[0..4], 10) catch return error.MalformedGeneralizedTime;
    const month = std.fmt.parseInt(u8, value[4..6], 10) catch return error.MalformedGeneralizedTime;
    const day = std.fmt.parseInt(u8, value[6..8], 10) catch return error.MalformedGeneralizedTime;
    const hour = std.fmt.parseInt(u8, value[8..10], 10) catch return error.MalformedGeneralizedTime;
    const minute = std.fmt.parseInt(u8, value[10..12], 10) catch return error.MalformedGeneralizedTime;
    const second = std.fmt.parseInt(u8, value[12..14], 10) catch return error.MalformedGeneralizedTime;
    if (value[14] != 'Z') return error.MalformedGeneralizedTime;
    return datetime.datetime.Datetime.create(
        year,
        month,
        day,
        hour,
        minute,
        second,
        0,
        &datetime.timezones.UTC,
    );
}

fn formatUtcTime(dt: *const datetime.datetime.Datetime, allocator: mem.Allocator) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        dt.date.year,
        dt.date.month,
        dt.date.day,
        dt.time.hour,
        dt.time.minute,
        dt.time.second,
    });
}

fn writeUtcTime(dt: *const datetime.datetime.Datetime, writer: anytype) !void {
    try std.fmt.format(writer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        dt.date.year,
        dt.date.month,
        dt.date.day,
        dt.time.hour,
        dt.time.minute,
        dt.time.second,
    });
}

pub fn parseAsn1String(
    allocator: mem.Allocator,
    tag: asn1.TagAndClass,
    value: []const u8,
) ![]const u8 {
    switch (tag) {
        .t61_string => return try allocator.dupe(u8, value),
        .printable_string => {
            for (value) |b| {
                if (!isX509Printable(b)) {
                    return error.InvalidPrintableString;
                }
            }
            return try allocator.dupe(u8, value);
        },
        .utf8_string => {
            if (std.unicode.utf8ValidateSlice(value)) {
                return try allocator.dupe(u8, value);
            } else {
                return error.InvalidUtf8String;
            }
        },
        .ia5_string => {
            if (!isValidIa5String(value)) {
                return error.InvalidIa5String;
            }
            return try allocator.dupe(u8, value);
        },
        // TODO: implement
        else => {
            std.log.err("Unsupported asn1 string type, tag={}", .{tag});
            return error.UnsupportedStringType;
        },
    }
}

fn isX509Printable(b: u8) bool {
    return printable_char_bitset.isSet(b);
}

const printable_char_bitset = makeStaticCharBitSet(_isX509Printable);

fn _isX509Printable(b: u8) bool {
    return 'a' <= b and b <= 'z' or
        'A' <= b and b <= 'Z' or
        '0' <= b and b <= '9' or
        '\'' <= b and b <= ')' or
        '+' <= b and b <= '/' or
        b == ' ' or
        b == ':' or
        b == '=' or
        b == '?' or
        // This is technically not allowed in a PrintableString.
        // However, x509 certificates with wildcard strings don't
        // always use the correct string type so we permit it.
        b == '*' or
        // This is not technically allowed either. However, not
        // only is it relatively common, but there are also a
        // handful of CA certificates that contain it. At least
        // one of which will not expire until 2027.
        b == '&';
}

const testing = std.testing;

test "isX509Printable" {
    var c: u8 = 0;
    while (true) : (c += 1) {
        try testing.expectEqual(_isX509Printable(c), isX509Printable(c));
        if (c == '\xff') break;
    }
}

test "SignatureAlgorithm" {
    try testing.expectEqual(2, @enumToInt(SignatureAlgorithm.md5_with_rsa));
    try testing.expectEqual(16, @enumToInt(SignatureAlgorithm.pure_ed25519));
}

test "Certificate.parse" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    // const test_rsa_pss_certificate = "\x30\x82\x02\x58\x30\x82\x01\x8d\xa0\x03\x02\x01\x02\x02\x11\x00\xf2\x99\x26\xeb\x87\xea\x8a\x0d\xb9\xfc\xc2\x47\x34\x7c\x11\xb0\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01\x20\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x1e\x17\x0d\x31\x37\x31\x31\x32\x33\x31\x36\x31\x36\x31\x30\x5a\x17\x0d\x31\x38\x31\x31\x32\x33\x31\x36\x31\x36\x31\x30\x5a\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xdb\x46\x7d\x93\x2e\x12\x27\x06\x48\xbc\x06\x28\x21\xab\x7e\xc4\xb6\xa2\x5d\xfe\x1e\x52\x45\x88\x7a\x36\x47\xa5\x08\x0d\x92\x42\x5b\xc2\x81\xc0\xbe\x97\x79\x98\x40\xfb\x4f\x6d\x14\xfd\x2b\x13\x8b\xc2\xa5\x2e\x67\xd8\xd4\x09\x9e\xd6\x22\x38\xb7\x4a\x0b\x74\x73\x2b\xc2\x34\xf1\xd1\x93\xe5\x96\xd9\x74\x7b\xf3\x58\x9f\x6c\x61\x3c\xc0\xb0\x41\xd4\xd9\x2b\x2b\x24\x23\x77\x5b\x1c\x3b\xbd\x75\x5d\xce\x20\x54\xcf\xa1\x63\x87\x1d\x1e\x24\xc4\xf3\x1d\x1a\x50\x8b\xaa\xb6\x14\x43\xed\x97\xa7\x75\x62\xf4\x14\xc8\x52\xd7\x02\x03\x01\x00\x01\xa3\x46\x30\x44\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa0\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30\x0f\x06\x03\x55\x1d\x11\x04\x08\x30\x06\x87\x04\x7f\x00\x00\x01\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01\x20\x03\x81\x81\x00\xcd\xac\x4e\xf2\xce\x5f\x8d\x79\x88\x10\x42\x70\x7f\x7c\xbf\x1b\x5a\x8a\x00\xef\x19\x15\x4b\x40\x15\x17\x71\x00\x6c\xd4\x16\x26\xe5\x49\x6d\x56\xda\x0c\x1a\x13\x9f\xd8\x46\x95\x59\x3c\xb6\x7f\x87\x76\x5e\x18\xaa\x03\xea\x06\x75\x22\xdd\x78\xd2\xa5\x89\xb8\xc9\x23\x64\xe1\x28\x38\xce\x34\x6c\x6e\x06\x7b\x51\xf1\xa7\xe6\xf4\xb3\x7f\xfa\xb1\x3f\x14\x11\x89\x66\x79\xd1\x8e\x88\x0e\x0b\xa0\x9e\x30\x2a\xc0\x67\xef\xca\x46\x02\x88\xe9\x53\x81\x22\x69\x22\x97\xad\x80\x93\xd4\xf7\xdd\x70\x14\x24\xd7\x70\x0a\x46\xa1";
    // var cert = try Certificate.parse(allocator, test_rsa_pss_certificate);
    // const der = @embedFile("../../tests/google.com.crt.der");
    const der = @embedFile("../../tests/naruh.com.server.der");
    // const der = @embedFile("../../tests/github.der");
    var cert = try Certificate.parse(allocator, der);
    defer cert.deinit(allocator);
    try testing.expectEqual(@as(i64, 3), cert.version);

    var serial_str = try cert.serial_number.toStringAlloc(allocator, 10, .lower);
    defer allocator.free(serial_str);
    // try testing.expectEqualStrings("322468385791552616392937435680808374704", serial_str);
    std.log.debug("certificate={any}", .{cert});
}

test "Certificate.verify" {
    const pem = @import("pem.zig");
    const assert = std.debug.assert;

    testing.log_level = .debug;
    const allocator = testing.allocator;

    var root_pool = try CertPool.init(allocator, true);
    defer root_pool.deinit();

    const max_bytes = 1024 * 1024 * 1024;
    const pem_certs = try std.fs.cwd().readFileAlloc(
        allocator,
        "/etc/ssl/certs/ca-certificates.crt",
        max_bytes,
    );
    defer allocator.free(pem_certs);

    try root_pool.appendCertsFromPem(pem_certs);

    const leaf_pem = @embedFile("../../tests/google.com.crt.pem");
    var offset: usize = 0;
    var leaf_block = try pem.Block.decode(allocator, leaf_pem, &offset);
    defer leaf_block.deinit(allocator);
    assert(mem.eql(u8, leaf_block.label, pem.Block.certificate_label));
    var leaf_der = leaf_block.bytes;
    var cert = try Certificate.parse(allocator, leaf_der);
    defer cert.deinit(allocator);

    const giag2_intermediate = @embedFile("../../tests/google.intermediate.crt.pem");
    var intermediate_pool = try CertPool.init(allocator, true);
    defer intermediate_pool.deinit();
    try intermediate_pool.appendCertsFromPem(giag2_intermediate);

    const opts = VerifyOptions{
        .roots = &root_pool,
        .dns_name = "www.google.com",
        .intermediates = &intermediate_pool,
    };
    var chains = try cert.verify(allocator, &opts);
    defer chains.deinit(allocator);
}

test "Certificate.isValid" {
    const pem = @import("pem.zig");
    const assert = std.debug.assert;

    testing.log_level = .debug;
    const allocator = testing.allocator;

    var root_pool = try CertPool.init(allocator, true);
    defer root_pool.deinit();

    const max_bytes = 1024 * 1024 * 1024;
    const pem_certs = try std.fs.cwd().readFileAlloc(
        allocator,
        "/etc/ssl/certs/ca-certificates.crt",
        max_bytes,
    );
    defer allocator.free(pem_certs);

    try root_pool.appendCertsFromPem(pem_certs);

    const leaf_pem = @embedFile("../../tests/google.com.crt.pem");
    var offset: usize = 0;
    var leaf_block = try pem.Block.decode(allocator, leaf_pem, &offset);
    defer leaf_block.deinit(allocator);
    assert(mem.eql(u8, leaf_block.label, pem.Block.certificate_label));
    var leaf_der = leaf_block.bytes;
    var cert = try Certificate.parse(allocator, leaf_der);
    defer cert.deinit(allocator);

    const giag2_intermediate = @embedFile("../../tests/google.intermediate.crt.pem");
    var intermediate_pool = try CertPool.init(allocator, true);
    defer intermediate_pool.deinit();
    try intermediate_pool.appendCertsFromPem(giag2_intermediate);

    const opts = VerifyOptions{
        .roots = &root_pool,
        .intermediates = &intermediate_pool,
    };
    try cert.isValid(allocator, .leaf, &[_]*Certificate{}, &opts);
}
