const std = @import("std");
const math = std.math;
const mem = std.mem;
const CurveId = @import("handshake_msg.zig").CurveId;
const asn1 = @import("asn1.zig");
const pkix = @import("pkix.zig");
const makeStaticCharBitSet = @import("../parser/lex.zig").makeStaticCharBitSet;

const KeyType = enum {
    rsa,
    ec,
};

pub const PublicKey = union(KeyType) {
    const Self = @This();

    pub const empty = Self{ .ec = .{ .id = .x25519, .curve_point = &[_]u8{} } };

    /// RSA public key
    rsa: struct {
        //Positive std.math.big.int.Const numbers.
        modulus: []const usize,
        exponent: []const usize,
    },
    /// Elliptic curve public key
    ec: struct {
        id: CurveId,
        /// Public curve point (uncompressed format)
        curve_point: []const u8,
    },

    pub fn deinit(self: Self, alloc: mem.Allocator) void {
        switch (self) {
            .rsa => |rsa| {
                alloc.free(rsa.modulus);
                alloc.free(rsa.exponent);
            },
            .ec => |ec| alloc.free(ec.curve_point),
        }
    }

    pub fn eql(self: Self, other: Self) bool {
        if (@as(KeyType, self) != @as(KeyType, other))
            return false;
        switch (self) {
            .rsa => |rsa| {
                return mem.eql(usize, rsa.exponent, other.rsa.exponent) and
                    mem.eql(usize, rsa.modulus, other.rsa.modulus);
            },
            .ec => |ec| {
                return ec.id == other.ec.id and mem.eql(u8, ec.curve_point, other.ec.curve_point);
            },
        }
    }
};

pub const PrivateKey = union(KeyType) {
    const Self = @This();

    pub const empty = Self{ .ec = .{ .id = .x25519, .curve_point = &[_]u8{} } };

    /// RSA public key
    rsa: struct {
        //Positive std.math.big.int.Const numbers.
        modulus: []const usize,
        exponent: []const usize,
    },
    /// Elliptic curve public key
    ec: struct {
        id: CurveId,
        /// Public curve point (uncompressed format)
        curve_point: []const u8,
    },

    pub fn deinit(self: Self, alloc: mem.Allocator) void {
        switch (self) {
            .rsa => |rsa| {
                alloc.free(rsa.modulus);
                alloc.free(rsa.exponent);
            },
            .ec => |ec| alloc.free(ec.curve_point),
        }
    }

    pub fn eql(self: Self, other: Self) bool {
        if (@as(KeyType, self) != @as(KeyType, other))
            return false;
        switch (self) {
            .rsa => |rsa| {
                return mem.eql(usize, rsa.exponent, other.rsa.exponent) and
                    mem.eql(usize, rsa.modulus, other.rsa.modulus);
            },
            .ec => |ec| {
                return ec.id == other.ec.id and mem.eql(u8, ec.curve_point, other.ec.curve_point);
            },
        }
    }
};

pub const SignatureAlgorithm = enum(u8) {
    md2_with_rsa = 1, // Unsupported.
    md5_with_rsa, // Only supported for signing, not verification.
    sha1WithRSA, // Only supported for signing, not verification.
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
        if (ai.algorithm.eql(oid_signature_ed25519)) {
            // RFC 8410, Section 3
            // > For all of the OIDs, the parameters MUST be absent.
            if (ai.parameters) |params| {
                if (params.full_bytes.len != 0) {
                    return error.UnknownSignatureAlgorithm;
                }
            }
        }

        if (!ai.algorithm.eql(oid_signature_rsa_pss)) {
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

test "fromAlgorithmIdentifier" {
    const ai = pkix.AlgorithmIdentifier{ .algorithm = oid_signature_ed25519 };
    var algo = try SignatureAlgorithm.fromAlgorithmIdentifier(&ai);
    std.log.debug("algo={}\n", .{algo});
    // try testing.expectEqual(oid_signature_ed25519, ObjectIdentifier{ .components = &[_]u32{ 1, 3, 101, 112 } });
}

pub const oid_signature_rsa_pss = asn1.ObjectIdentifier{
    .components = &[_]u32{ 1, 2, 840, 113549, 1, 1, 10 },
};
pub const oid_signature_ed25519 = asn1.ObjectIdentifier{ .components = &[_]u32{ 1, 3, 101, 112 } };

pub const PublicKeyAlgorithm = enum(u8) {
    rsa = 1,
    dsa, // Unsupported.
    ecdsa,
    ed25519,
};

pub const SignatureAlgorithmDetail = struct {
    algo: SignatureAlgorithm,
    name: []const u8,
    oid: asn1.ObjectIdentifier,
    pub_key_algo: PublicKeyAlgorithm,
    // hash: Hash,
};

const signature_algorithm_details = [_]SignatureAlgorithmDetail{
    // .{.algo = md2_with_rsa, .name = "MD2-RSA", }
    .{
        .algo = .pure_ed25519,
        .name = "Ed25519",
        .oid = oid_signature_ed25519,
        .pub_key_algo = .ed25519,
    },
};

// PssParameters reflects the parameters in an AlgorithmIdentifier that
// specifies RSA PSS. See RFC 3447, Appendix A.2.3.
const PssParameters = struct {
    // The following three fields are not marked as
    // optional because the default values specify SHA-1,
    // which is no longer suitable for use in signatures.
    hash_algorithm: ?pkix.AlgorithmIdentifier = null,
    mask_gen_algorithm: ?pkix.AlgorithmIdentifier = null,
    salt_length: ?usize = null,
    trailer_field: usize,
};

// fieldParameters is the parsed representation of tag string from a structure field.
const FieldParameters = struct {
    optional: bool, // true iff the field is OPTIONAL
    explicit: bool, // true iff an EXPLICIT tag is in use.
    application: bool, // true iff an APPLICATION tag is in use.
    private: bool, // true iff a PRIVATE tag is in use.
    default_value: ?i64 = null, // a default value for INTEGER typed fields (maybe nil).
    tag: ?asn1.Tag = null, // the EXPLICIT or IMPLICIT tag (maybe nil).
    string_type: usize, // the string tag to use when marshaling.
    time_type: usize, // the time tag to use when marshaling.
    set: bool, // true iff this should be encoded as a SET
    omit_empty: bool, // true iff this should be omitted if empty when marshaling.

    // Invariants:
    //   if explicit is set, tag is non-nil.
};

const Certificate = struct {
    raw: []const u8,
    raw_tbs_certificate: []const u8,
    version: i64,
    serial_number: math.big.int.Managed,
    signature_algorithm: pkix.AlgorithmIdentifier,
    raw_issuer: []const u8,
    issuer: pkix.Name,

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
            @intToEnum(asn1.Tag, 0).constructed().contextSpecific(),
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
            math.big.int.Managed,
            allocator,
        ) catch return error.MalformedSerialNumber;
        errdefer serial_number.deinit();

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
        errdefer sig_ai.deinit(allocator);

        var issuer_seq = tbs.readAsn1Element(.sequence) catch return error.MalformedIssuer;
        const raw_issuer = issuer_seq.bytes;

        var issuer_rdns = try parseName(allocator, &issuer_seq);
        defer issuer_rdns.deinit(allocator);
        var issuer = try pkix.Name.fromRdnSequence(allocator, &issuer_rdns);
        errdefer issuer.deinit(allocator);

        var validity = tbs.readAsn1(.sequence) catch return error.MalformedValidity;
        _ = validity;

        return Certificate{
            .raw = raw,
            .raw_tbs_certificate = raw_tbs_certificate,
            .version = version,
            .serial_number = serial_number,
            .signature_algorithm = sig_ai,
            .raw_issuer = raw_issuer,
            .issuer = issuer,
        };
    }

    pub fn deinit(self: *Certificate, allocator: mem.Allocator) void {
        allocator.free(self.raw);
        self.serial_number.deinit();
        self.signature_algorithm.deinit(allocator);
        self.issuer.deinit(allocator);
    }
};

fn parseName(allocator: mem.Allocator, raw: *asn1.String) !pkix.RdnSequence {
    return try pkix.RdnSequence.parse(allocator, raw);
}

pub fn parseAsn1String(allocator: mem.Allocator, tag: asn1.Tag, value: []const u8) ![]const u8 {
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
        // TODO: implement
        else => return error.UnsupportedStringType,
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

test "PublicKey/PrivateKey" {
    std.log.debug("PublicKey.empty={}\n", .{PublicKey.empty});
    std.log.debug("PrivateKey.empty={}\n", .{PrivateKey.empty});
}

test "Certificate.parse" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    const test_rsa_pss_certificate = "\x30\x82\x02\x58\x30\x82\x01\x8d\xa0\x03\x02\x01\x02\x02\x11\x00\xf2\x99\x26\xeb\x87\xea\x8a\x0d\xb9\xfc\xc2\x47\x34\x7c\x11\xb0\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01\x20\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x1e\x17\x0d\x31\x37\x31\x31\x32\x33\x31\x36\x31\x36\x31\x30\x5a\x17\x0d\x31\x38\x31\x31\x32\x33\x31\x36\x31\x36\x31\x30\x5a\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xdb\x46\x7d\x93\x2e\x12\x27\x06\x48\xbc\x06\x28\x21\xab\x7e\xc4\xb6\xa2\x5d\xfe\x1e\x52\x45\x88\x7a\x36\x47\xa5\x08\x0d\x92\x42\x5b\xc2\x81\xc0\xbe\x97\x79\x98\x40\xfb\x4f\x6d\x14\xfd\x2b\x13\x8b\xc2\xa5\x2e\x67\xd8\xd4\x09\x9e\xd6\x22\x38\xb7\x4a\x0b\x74\x73\x2b\xc2\x34\xf1\xd1\x93\xe5\x96\xd9\x74\x7b\xf3\x58\x9f\x6c\x61\x3c\xc0\xb0\x41\xd4\xd9\x2b\x2b\x24\x23\x77\x5b\x1c\x3b\xbd\x75\x5d\xce\x20\x54\xcf\xa1\x63\x87\x1d\x1e\x24\xc4\xf3\x1d\x1a\x50\x8b\xaa\xb6\x14\x43\xed\x97\xa7\x75\x62\xf4\x14\xc8\x52\xd7\x02\x03\x01\x00\x01\xa3\x46\x30\x44\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa0\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30\x0f\x06\x03\x55\x1d\x11\x04\x08\x30\x06\x87\x04\x7f\x00\x00\x01\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01\x20\x03\x81\x81\x00\xcd\xac\x4e\xf2\xce\x5f\x8d\x79\x88\x10\x42\x70\x7f\x7c\xbf\x1b\x5a\x8a\x00\xef\x19\x15\x4b\x40\x15\x17\x71\x00\x6c\xd4\x16\x26\xe5\x49\x6d\x56\xda\x0c\x1a\x13\x9f\xd8\x46\x95\x59\x3c\xb6\x7f\x87\x76\x5e\x18\xaa\x03\xea\x06\x75\x22\xdd\x78\xd2\xa5\x89\xb8\xc9\x23\x64\xe1\x28\x38\xce\x34\x6c\x6e\x06\x7b\x51\xf1\xa7\xe6\xf4\xb3\x7f\xfa\xb1\x3f\x14\x11\x89\x66\x79\xd1\x8e\x88\x0e\x0b\xa0\x9e\x30\x2a\xc0\x67\xef\xca\x46\x02\x88\xe9\x53\x81\x22\x69\x22\x97\xad\x80\x93\xd4\xf7\xdd\x70\x14\x24\xd7\x70\x0a\x46\xa1";
    var cert = try Certificate.parse(allocator, test_rsa_pss_certificate);
    defer cert.deinit(allocator);
    try testing.expectEqual(@as(i64, 3), cert.version);

    var serial_str = try cert.serial_number.toString(allocator, 10, .lower);
    defer allocator.free(serial_str);
    try testing.expectEqualStrings("322468385791552616392937435680808374704", serial_str);
}

test "parseCertificate" {
    const allocator = testing.allocator;
    const test_rsa_pss_certificate = "\x30\x82\x02\x58\x30\x82\x01\x8d\xa0\x03\x02\x01\x02\x02\x11\x00\xf2\x99\x26\xeb\x87\xea\x8a\x0d\xb9\xfc\xc2\x47\x34\x7c\x11\xb0\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01\x20\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x1e\x17\x0d\x31\x37\x31\x31\x32\x33\x31\x36\x31\x36\x31\x30\x5a\x17\x0d\x31\x38\x31\x31\x32\x33\x31\x36\x31\x36\x31\x30\x5a\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xdb\x46\x7d\x93\x2e\x12\x27\x06\x48\xbc\x06\x28\x21\xab\x7e\xc4\xb6\xa2\x5d\xfe\x1e\x52\x45\x88\x7a\x36\x47\xa5\x08\x0d\x92\x42\x5b\xc2\x81\xc0\xbe\x97\x79\x98\x40\xfb\x4f\x6d\x14\xfd\x2b\x13\x8b\xc2\xa5\x2e\x67\xd8\xd4\x09\x9e\xd6\x22\x38\xb7\x4a\x0b\x74\x73\x2b\xc2\x34\xf1\xd1\x93\xe5\x96\xd9\x74\x7b\xf3\x58\x9f\x6c\x61\x3c\xc0\xb0\x41\xd4\xd9\x2b\x2b\x24\x23\x77\x5b\x1c\x3b\xbd\x75\x5d\xce\x20\x54\xcf\xa1\x63\x87\x1d\x1e\x24\xc4\xf3\x1d\x1a\x50\x8b\xaa\xb6\x14\x43\xed\x97\xa7\x75\x62\xf4\x14\xc8\x52\xd7\x02\x03\x01\x00\x01\xa3\x46\x30\x44\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa0\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30\x0f\x06\x03\x55\x1d\x11\x04\x08\x30\x06\x87\x04\x7f\x00\x00\x01\x30\x41\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a\x30\x34\xa0\x0f\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa1\x1c\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\xa2\x03\x02\x01\x20\x03\x81\x81\x00\xcd\xac\x4e\xf2\xce\x5f\x8d\x79\x88\x10\x42\x70\x7f\x7c\xbf\x1b\x5a\x8a\x00\xef\x19\x15\x4b\x40\x15\x17\x71\x00\x6c\xd4\x16\x26\xe5\x49\x6d\x56\xda\x0c\x1a\x13\x9f\xd8\x46\x95\x59\x3c\xb6\x7f\x87\x76\x5e\x18\xaa\x03\xea\x06\x75\x22\xdd\x78\xd2\xa5\x89\xb8\xc9\x23\x64\xe1\x28\x38\xce\x34\x6c\x6e\x06\x7b\x51\xf1\xa7\xe6\xf4\xb3\x7f\xfa\xb1\x3f\x14\x11\x89\x66\x79\xd1\x8e\x88\x0e\x0b\xa0\x9e\x30\x2a\xc0\x67\xef\xca\x46\x02\x88\xe9\x53\x81\x22\x69\x22\x97\xad\x80\x93\xd4\xf7\xdd\x70\x14\x24\xd7\x70\x0a\x46\xa1";
    var input = asn1.String.init(test_rsa_pss_certificate);
    input = try input.readAsn1Element(.sequence);
    input = try input.readAsn1(.sequence);
    var tbs = try input.readAsn1Element(.sequence);
    tbs = try tbs.readAsn1(.sequence);
    var cert_version = try tbs.readOptionalAsn1Integer(
        u64,
        @intToEnum(asn1.Tag, 0).constructed().contextSpecific(),
        allocator,
        0,
    );
    cert_version += 1;
    try testing.expectEqual(@as(u64, 3), cert_version);
    var serial = try tbs.readAsn1Integer(std.math.big.int.Managed, allocator);
    defer serial.deinit();

    var serial_str = try serial.toString(allocator, 10, .lower);
    defer allocator.free(serial_str);

    // var serial_debug_str = try allocDebugPrintBigIntManaged(serial, allocator);
    // std.log.debug("serial: {s}, {s}\n", .{ serial_str, serial_debug_str });
    // defer allocator.free(serial_debug_str);

    try testing.expectEqualStrings("322468385791552616392937435680808374704", serial_str);

    var sigAiSeq = try tbs.readAsn1(.sequence);
    // Before parsing the inner algorithm identifier, extract
    // the outer algorithm identifier and make sure that they
    // match.
    var outerSigAiSeq = try input.readAsn1(.sequence);
    try testing.expectEqualSlices(u8, outerSigAiSeq.bytes, sigAiSeq.bytes);

    var signAi = try pkix.AlgorithmIdentifier.parse(allocator, &sigAiSeq);
    defer signAi.deinit(allocator);

    var issuerSeq = try tbs.readAsn1Element(.sequence);
    std.log.debug("issuerSeq.bytes={s}\n", .{issuerSeq.bytes});

    std.log.debug("tbs.bytes={}\n", .{fmtx.fmtSliceHexEscapeLower(tbs.bytes)});
}
