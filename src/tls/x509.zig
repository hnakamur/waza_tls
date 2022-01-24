const std = @import("std");
const math = std.math;
const mem = std.mem;
const datetime = @import("datetime");
const CurveId = @import("handshake_msg.zig").CurveId;
const asn1 = @import("asn1.zig");
const pkix = @import("pkix.zig");
const crypto = @import("crypto.zig");
const bigint = @import("big_int.zig");
const makeStaticCharBitSet = @import("../parser/lex.zig").makeStaticCharBitSet;
const memx = @import("../memx.zig");

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
    // hash: Hash,
};

const signature_algorithm_details = [_]SignatureAlgorithmDetail{
    .{
        .algo = .md2_with_rsa,
        .name = "MD2-RSA",
        .oid = asn1.ObjectIdentifier.signature_md2_with_rsa,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .md5_with_rsa,
        .name = "MD5-RSA",
        .oid = asn1.ObjectIdentifier.signature_md5_with_rsa,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .sha1_with_rsa,
        .name = "SHA1-RSA",
        .oid = asn1.ObjectIdentifier.signature_sha1_with_rsa,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .sha1_with_rsa,
        .name = "SHA1-RSA",
        .oid = asn1.ObjectIdentifier.iso_signature_sha1_with_rsa,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .sha256_with_rsa,
        .name = "SHA256-RSA",
        .oid = asn1.ObjectIdentifier.signature_sha256_with_rsa,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .sha384_with_rsa,
        .name = "SHA384-RSA",
        .oid = asn1.ObjectIdentifier.signature_sha384_with_rsa,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .sha512_with_rsa,
        .name = "SHA512-RSA",
        .oid = asn1.ObjectIdentifier.signature_sha512_with_rsa,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .sha256_with_rsa_pss,
        .name = "SHA256-RSAPSS",
        .oid = asn1.ObjectIdentifier.signature_rsa_pss,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .sha384_with_rsa_pss,
        .name = "SHA384-RSAPSS",
        .oid = asn1.ObjectIdentifier.signature_rsa_pss,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .sha512_with_rsa_pss,
        .name = "SHA512-RSAPSS",
        .oid = asn1.ObjectIdentifier.signature_rsa_pss,
        .pub_key_algo = .rsa,
    },
    .{
        .algo = .dsa_with_sha1,
        .name = "DSA-SHA1",
        .oid = asn1.ObjectIdentifier.signature_dsa_with_sha1,
        .pub_key_algo = .dsa,
    },
    .{
        .algo = .dsa_with_sha256,
        .name = "DSA-SHA256",
        .oid = asn1.ObjectIdentifier.signature_dsa_with_sha256,
        .pub_key_algo = .dsa,
    },
    .{
        .algo = .ecdsa_with_sha1,
        .name = "ECDSA-SHA1",
        .oid = asn1.ObjectIdentifier.signature_ecdsa_with_sha1,
        .pub_key_algo = .ecdsa,
    },
    .{
        .algo = .ecdsa_with_sha256,
        .name = "ECDSA-SHA256",
        .oid = asn1.ObjectIdentifier.signature_ecdsa_with_sha256,
        .pub_key_algo = .ecdsa,
    },
    .{
        .algo = .ecdsa_with_sha384,
        .name = "ECDSA-SHA384",
        .oid = asn1.ObjectIdentifier.signature_ecdsa_with_sha384,
        .pub_key_algo = .ecdsa,
    },
    .{
        .algo = .ecdsa_with_sha512,
        .name = "ECDSA-SHA512",
        .oid = asn1.ObjectIdentifier.signature_ecdsa_with_sha512,
        .pub_key_algo = .ecdsa,
    },
    .{
        .algo = .pure_ed25519,
        .name = "Ed25519",
        .oid = asn1.ObjectIdentifier.signature_ed25519,
        .pub_key_algo = .ed25519,
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

    basic_constraints_valid: bool = false,
    is_ca: bool = false,
    max_path_len: ?u64 = null,

    key_usage: KeyUsage = .{},
    ext_key_usages: []const ExtKeyUsage = &[_]ExtKeyUsage{},
    unknown_usages: []asn1.ObjectIdentifier = &[_]asn1.ObjectIdentifier{},

    subject_key_id: []const u8 = &[_]u8{},

    extensions: []pkix.Extension,
    signature: []const u8 = &[_]u8{},
    unhandled_critical_extensions: []*const pkix.Extension = &[_]*const pkix.Extension{},

    pub fn parse(allocator: mem.Allocator, der: []const u8) !Certificate {
        var input = asn1.String.init(der);
        // we read the SEQUENCE including length and tag bytes so that
        // we can populate Certificate.raw, before unwrapping the
        // SEQUENCE so it can be operated on
        input = input.readAsn1Element(.sequence) catch return error.MalformedCertificate;
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
        std.log.debug("sig_ai={}", .{sig_ai});
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
        var pk_info = blk: {
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
            break :blk PublicKeyInfo{ .algorithm = pk_ai, .public_key = spk };
        };
        defer pk_info.deinit(allocator);
        var public_key = try parsePublicKey(allocator, public_key_algorithm, &pk_info);
        errdefer public_key.deinit(allocator);

        var cert = blk: {
            var extensions = std.ArrayListUnmanaged(pkix.Extension){};
            errdefer extensions.deinit(allocator);
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
        try cert.processExtensions(allocator);

        var signature = try asn1.BitString.read(&input, allocator);
        defer signature.deinit(allocator);
        cert.signature = try signature.rightAlign(allocator);

        return cert;
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
        try std.fmt.format(writer, ", extensions = {any}", .{self.extensions});
        try std.fmt.format(writer, ", signature = {}", .{std.fmt.fmtSliceHexLower(self.signature)});
        _ = try writer.write(" }");
    }

    fn processExtensions(self: *Certificate, allocator: mem.Allocator) !void {
        var unhandled_critical_extensions = std.ArrayListUnmanaged(*const pkix.Extension){};

        for (self.extensions) |*ext| {
            std.log.debug("Certificate.processExtensions oid={}", .{ext.id});
            var unhandled = false;
            if (ext.id.components.len == 4 and
                mem.startsWith(u32, ext.id.components, &[_]u32{ 2, 5, 29 }))
            {
                switch (ext.id.components[3]) {
                    15 => self.key_usage = try parseKeyUsageExtension(allocator, ext.value),
                    19 => try self.parseBasicConstraintsExtension(ext.value),
                    17 => {},
                    30 => {},
                    31 => {},
                    35 => {},
                    37 => try self.parseExtKeyUsageExtension(allocator, ext.value),
                    14 => self.subject_key_id = try parseSubjectKeyIdExtension(
                        allocator,
                        ext.value,
                    ),
                    32 => {},
                    else => unhandled = true,
                }
            } else if (ext.id.eql(asn1.ObjectIdentifier.extension_authority_info_access)) {
                // RFC 5280 4.2.2.1: Authority Information Access
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
};

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
    var s = asn1.String.init(der);

    // RFC 5280, 4.2.1.2
    var skid = s.readAsn1(.octet_string) catch return error.InvalidSubjectKeyId;
    return try allocator.dupe(u8, skid.bytes);
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
        else => {
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
        @panic("not implemented yet");
    } else {
        return error.UnsupportedTimeFormat;
    }
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
const fmtx = @import("../fmtx.zig");

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
    const der = @embedFile("../../tests/google.com.crt.der");
    // const der = @embedFile("../../tests/github.der");
    var cert = try Certificate.parse(allocator, der);
    defer cert.deinit(allocator);
    try testing.expectEqual(@as(i64, 3), cert.version);

    var serial_str = try cert.serial_number.toStringAlloc(allocator, 10, .lower);
    defer allocator.free(serial_str);
    // try testing.expectEqualStrings("322468385791552616392937435680808374704", serial_str);
    std.log.debug("certificate={any}", .{cert});
}
