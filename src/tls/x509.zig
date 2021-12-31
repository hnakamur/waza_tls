const std = @import("std");
const mem = std.mem;
const CurveId = @import("handshake_msg.zig").CurveId;
const asn1 = @import("asn1.zig");

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

    pub fn parseDer(allocator: mem.Allocator, reader: anytype) !PublicKey {
        if ((try reader.readByte()) != 0x30)
            return error.MalformedDER;
        const seq_len = try asn1.der.parse_length(reader);
        _ = seq_len;

        if ((try reader.readByte()) != 0x06)
            return error.MalformedDER;
        const oid_bytes = try asn1.der.parse_length(reader);
        std.log.debug("parseDer, old_bytes={}", .{oid_bytes});
        if (oid_bytes == 9) {
            // @TODO This fails in async if merged with the if
            if (!try reader.isBytes(&[9]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0xD, 0x1, 0x1, 0x1 }))
                return error.MalformedDER;
            // OID is 1.2.840.113549.1.1.1
            // RSA key
            // Skip past the NULL
            const null_byte = try reader.readByte();
            if (null_byte != 0x05)
                return error.MalformedDER;
            const null_len = try asn1.der.parse_length(reader);
            if (null_len != 0x00)
                return error.MalformedDER;
            {
                // BitString next!
                if ((try reader.readByte()) != 0x03)
                    return error.MalformedDER;
                _ = try asn1.der.parse_length(reader);
                const bit_string_unused_bits = try reader.readByte();
                if (bit_string_unused_bits != 0)
                    return error.MalformedDER;

                if ((try reader.readByte()) != 0x30)
                    return error.MalformedDER;
                _ = try asn1.der.parse_length(reader);

                // Modulus
                if ((try reader.readByte()) != 0x02)
                    return error.MalformedDER;
                const modulus = try asn1.der.parse_int(allocator, reader);
                errdefer allocator.free(modulus.limbs);
                if (!modulus.positive) return error.MalformedDER;
                // Exponent
                if ((try reader.readByte()) != 0x02)
                    return error.MalformedDER;
                const exponent = try asn1.der.parse_int(allocator, reader);
                errdefer allocator.free(exponent.limbs);
                if (!exponent.positive) return error.MalformedDER;
                return PublicKey{
                    .rsa = .{
                        .modulus = modulus.limbs,
                        .exponent = exponent.limbs,
                    },
                };
            }
        } else if (oid_bytes == 7) {
            // @TODO This fails in async if merged with the if
            if (!try reader.isBytes(&[7]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 }))
                return error.MalformedDER;
            // OID is 1.2.840.10045.2.1
            // Elliptical curve
            // We only support named curves, for which the parameter field is an OID.
            const oid_tag = try reader.readByte();
            if (oid_tag != 0x06)
                return error.MalformedDER;
            const curve_oid_bytes = try asn1.der.parse_length(reader);

            var key: PublicKey = undefined;
            if (curve_oid_bytes == 5) {
                if (!try reader.isBytes(&[4]u8{ 0x2B, 0x81, 0x04, 0x00 }))
                    return error.MalformedDER;
                // 1.3.132.0.{34, 35}
                // const last_byte = try reader.readByte();
                // if (last_byte == 0x22)
                //     key = .{ .ec = .{ .id = .secp384r1, .curve_point = undefined } }
                // else if (last_byte == 0x23)
                //     key = .{ .ec = .{ .id = .secp521r1, .curve_point = undefined } }
                // else
                return error.MalformedDER;
            } else if (curve_oid_bytes == 8) {
                if (!try reader.isBytes(&[8]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x3, 0x1, 0x7 }))
                    return error.MalformedDER;
                // key = .{ .ec = .{ .id = .secp256r1, .curve_point = undefined } };
            } else {
                return error.MalformedDER;
            }

            if ((try reader.readByte()) != 0x03)
                return error.MalformedDER;
            const byte_len = try asn1.der.parse_length(reader);
            const unused_bits = try reader.readByte();
            const bit_count = (byte_len - 1) * 8 - unused_bits;
            if (bit_count % 8 != 0)
                return error.MalformedDER;
            const bit_memory = try allocator.alloc(u8, std.math.divCeil(usize, bit_count, 8) catch unreachable);
            errdefer allocator.free(bit_memory);
            try reader.readNoEof(bit_memory[0 .. byte_len - 1]);

            key.ec.curve_point = bit_memory;
            return key;
        }
        return error.MalformedDER;
    }
};

pub fn DecodeDERError(comptime Reader: type) type {
    return Reader.Error || error{
        MalformedPEM,
        MalformedDER,
        EndOfStream,
        OutOfMemory,
    };
}

pub const Certificate = struct {
    pub const SignatureAlgorithm = struct {
        hash: enum(u8) {
            none = 0,
            md5 = 1,
            sha1 = 2,
            sha224 = 3,
            sha256 = 4,
            sha384 = 5,
            sha512 = 6,
        },
        signature: enum(u8) {
            anonymous = 0,
            rsa = 1,
            dsa = 2,
            ecdsa = 3,
        },
    };

    /// Subject distinguished name
    dn: []const u8,
    /// A "CA" anchor is deemed fit to verify signatures on certificates.
    /// A "non-CA" anchor is accepted only for direct trust (server's certificate
    /// name and key match the anchor).
    is_ca: bool = false,
    public_key: PublicKey,

    const CaptureState = struct {
        self: *Certificate,
        allocator: mem.Allocator,
        dn_allocated: bool = false,
        pk_allocated: bool = false,
    };

    fn initSubjectDn(state: *CaptureState, tag: u8, length: usize, reader: anytype) !void {
        _ = tag;

        const dn_mem = try state.allocator.alloc(u8, length);
        errdefer state.allocator.free(dn_mem);
        try reader.readNoEof(dn_mem);
        state.self.dn = dn_mem;
        state.dn_allocated = true;
    }

    fn processExtension(state: *CaptureState, tag: u8, length: usize, reader: anytype) !void {
        _ = tag;
        _ = length;

        const object_id = try asn1.der.parse_value(state.allocator, reader);
        defer object_id.deinit(state.allocator);
        if (object_id != .object_identifier) return error.DoesNotMatchSchema;
        if (object_id.object_identifier.len != 4)
            return;

        const data = object_id.object_identifier.data;
        // Basic constraints extension
        if (data[0] != 2 or data[1] != 5 or data[2] != 29 or data[3] != 19)
            return;

        const basic_constraints = try asn1.der.parse_value(state.allocator, reader);
        defer basic_constraints.deinit(state.allocator);

        switch (basic_constraints) {
            .bool => state.self.is_ca = true,
            .octet_string => |s| {
                if (s.len != 5 or s[0] != 0x30 or s[1] != 0x03 or s[2] != 0x01 or s[3] != 0x01)
                    return error.DoesNotMatchSchema;
                state.self.is_ca = s[4] != 0x00;
            },
            else => return error.DoesNotMatchSchema,
        }
    }

    fn initExtensions(state: *CaptureState, tag: u8, length: usize, reader: anytype) !void {
        _ = tag;
        _ = length;

        const schema = .{
            .sequence_of,
            .{ .capture, 0, .sequence },
        };
        const captures = .{
            state, processExtension,
        };
        try asn1.der.parse_schema(schema, captures, reader);
    }

    fn initPublicKeyInfo(state: *CaptureState, tag: u8, length: usize, reader: anytype) !void {
        _ = tag;
        _ = length;

        state.self.public_key = try PublicKey.parseDer(state.allocator, reader);
        state.pk_allocated = true;
    }

    /// Initialize a trusted anchor from distinguished encoding rules (DER) encoded data
    pub fn create(allocator: mem.Allocator, der_reader: anytype) DecodeDERError(@TypeOf(der_reader))!@This() {
        var self: @This() = undefined;
        self.is_ca = false;
        // https://tools.ietf.org/html/rfc5280#page-117
        const schema = .{
            .sequence, .{
                // tbsCertificate
                .{
                    .sequence,
                    .{
                        .{ .context_specific, 0 }, // version
                        .{.int}, // serialNumber
                        .{.sequence}, // signature
                        .{.sequence}, // issuer
                        .{.sequence}, // validity,
                        .{ .capture, 0, .sequence }, // subject
                        .{ .capture, 1, .sequence }, // subjectPublicKeyInfo
                        .{ .optional, .context_specific, 1 }, // issuerUniqueID
                        .{ .optional, .context_specific, 2 }, // subjectUniqueID
                        .{ .capture, 2, .optional, .context_specific, 3 }, // extensions
                    },
                },
                // signatureAlgorithm
                .{.sequence},
                // signatureValue
                .{.bit_string},
            },
        };

        var capture_state = CaptureState{
            .self = &self,
            .allocator = allocator,
        };
        const captures = .{
            &capture_state, initSubjectDn,
            &capture_state, initPublicKeyInfo,
            &capture_state, initExtensions,
        };

        errdefer {
            if (capture_state.dn_allocated)
                allocator.free(self.dn);
            if (capture_state.pk_allocated)
                self.public_key.deinit(allocator);
        }

        asn1.der.parse_schema(schema, captures, der_reader) catch |err| switch (err) {
            error.InvalidLength,
            error.InvalidTag,
            error.InvalidContainerLength,
            error.DoesNotMatchSchema,
            => return error.MalformedDER,
            else => |e| return e,
        };
        return self;
    }

    pub fn deinit(self: @This(), alloc: mem.Allocator) void {
        alloc.free(self.dn);
        self.public_key.deinit(alloc);
    }

    pub fn format(self: @This(), comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        try writer.print(
            \\CERTIFICATE
            \\-----------
            \\IS CA: {}
            \\Subject distinguished name (encoded):
            \\{}
            \\Public key:
            \\
        , .{ self.is_ca, std.fmt.fmtSliceHexLower(self.dn) });

        switch (self.public_key) {
            .rsa => |mod_exp| {
                const modulus = std.math.big.int.Const{ .positive = true, .limbs = mod_exp.modulus };
                const exponent = std.math.big.int.Const{ .positive = true, .limbs = mod_exp.exponent };
                try writer.print(
                    \\RSA
                    \\modulus: {}
                    \\exponent: {}
                    \\
                , .{
                    modulus,
                    exponent,
                });
            },
            .ec => |ec| {
                try writer.print(
                    \\EC (Curve: {})
                    \\point: {}
                    \\
                , .{
                    ec.id,
                    std.fmt.fmtSliceHexLower(ec.curve_point),
                });
            },
        }

        try writer.writeAll(
            \\-----------
            \\
        );
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

const testing = std.testing;

test "Certificate.create" {
    testing.log_level = .debug;
    const testECDSACertificate = "\x30\x82\x02\x00\x30\x82\x01\x62\x02\x09\x00\xb8\xbf\x2d\x47\xa0\xd2\xeb\xf4\x30\x09\x06\x07\x2a\x86\x48\xce\x3d\x04\x01\x30\x45\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x41\x55\x31\x13\x30\x11\x06\x03\x55\x04\x08\x13\x0a\x53\x6f\x6d\x65\x2d\x53\x74\x61\x74\x65\x31\x21\x30\x1f\x06\x03\x55\x04\x0a\x13\x18\x49\x6e\x74\x65\x72\x6e\x65\x74\x20\x57\x69\x64\x67\x69\x74\x73\x20\x50\x74\x79\x20\x4c\x74\x64\x30\x1e\x17\x0d\x31\x32\x31\x31\x32\x32\x31\x35\x30\x36\x33\x32\x5a\x17\x0d\x32\x32\x31\x31\x32\x30\x31\x35\x30\x36\x33\x32\x5a\x30\x45\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x41\x55\x31\x13\x30\x11\x06\x03\x55\x04\x08\x13\x0a\x53\x6f\x6d\x65\x2d\x53\x74\x61\x74\x65\x31\x21\x30\x1f\x06\x03\x55\x04\x0a\x13\x18\x49\x6e\x74\x65\x72\x6e\x65\x74\x20\x57\x69\x64\x67\x69\x74\x73\x20\x50\x74\x79\x20\x4c\x74\x64\x30\x81\x9b\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x23\x03\x81\x86\x00\x04\x00\xc4\xa1\xed\xbe\x98\xf9\x0b\x48\x73\x36\x7e\xc3\x16\x56\x11\x22\xf2\x3d\x53\xc3\x3b\x4d\x21\x3d\xcd\x6b\x75\xe6\xf6\xb0\xdc\x9a\xdf\x26\xc1\xbc\xb2\x87\xf0\x72\x32\x7c\xb3\x64\x2f\x1c\x90\xbc\xea\x68\x23\x10\x7e\xfe\xe3\x25\xc0\x48\x3a\x69\xe0\x28\x6d\xd3\x37\x00\xef\x04\x62\xdd\x0d\xa0\x9c\x70\x62\x83\xd8\x81\xd3\x64\x31\xaa\x9e\x97\x31\xbd\x96\xb0\x68\xc0\x9b\x23\xde\x76\x64\x3f\x1a\x5c\x7f\xe9\x12\x0e\x58\x58\xb6\x5f\x70\xdd\x9b\xd8\xea\xd5\xd7\xf5\xd5\xcc\xb9\xb6\x9f\x30\x66\x5b\x66\x9a\x20\xe2\x27\xe5\xbf\xfe\x3b\x30\x09\x06\x07\x2a\x86\x48\xce\x3d\x04\x01\x03\x81\x8c\x00\x30\x81\x88\x02\x42\x01\x88\xa2\x4f\xeb\xe2\x45\xc5\x48\x7d\x1b\xac\xf5\xed\x98\x9d\xae\x47\x70\xc0\x5e\x1b\xb6\x2f\xbd\xf1\xb6\x4d\xb7\x61\x40\xd3\x11\xa2\xce\xee\x0b\x7e\x92\x7e\xff\x76\x9d\xc3\x3b\x7e\xa5\x3f\xce\xfa\x10\xe2\x59\xec\x47\x2d\x7c\xac\xda\x4e\x97\x0e\x15\xa0\x6f\xd0\x02\x42\x01\x4d\xfc\xbe\x67\x13\x9c\x2d\x05\x0e\xbd\x3f\xa3\x8c\x25\xc1\x33\x13\x83\x0d\x94\x06\xbb\xd4\x37\x7a\xf6\xec\x7a\xc9\x86\x2e\xdd\xd7\x11\x69\x7f\x85\x7c\x56\xde\xfb\x31\x78\x2b\xe4\xc7\x78\x0d\xae\xcb\xbe\x9e\x4e\x36\x24\x31\x7b\x6a\x0f\x39\x95\x12\x07\x8f\x2a";
    // const testEd25519Certificate = "\x30\x82\x01\x2e\x30\x81\xe1\xa0\x03\x02\x01\x02\x02\x10\x0f\x43\x1c\x42\x57\x93\x94\x1d\xe9\x87\xe4\xf1\xad\x15\x00\x5d\x30\x05\x06\x03\x2b\x65\x70\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x1e\x17\x0d\x31\x39\x30\x35\x31\x36\x32\x31\x33\x38\x30\x31\x5a\x17\x0d\x32\x30\x30\x35\x31\x35\x32\x31\x33\x38\x30\x31\x5a\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00\x3f\xe2\x15\x2e\xe6\xe3\xef\x3f\x4e\x85\x4a\x75\x77\xa3\x64\x9e\xed\xe0\xbf\x84\x2c\xcc\x92\x26\x8f\xfa\x6f\x34\x83\xaa\xec\x8f\xa3\x4d\x30\x4b\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa0\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30\x16\x06\x03\x55\x1d\x11\x04\x0f\x30\x0d\x82\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x30\x05\x06\x03\x2b\x65\x70\x03\x41\x00\x63\x44\xed\x9c\xc4\xbe\x53\x24\x53\x9f\xd2\x10\x8d\x9f\xe8\x21\x08\x90\x95\x39\xe5\x0d\xc1\x55\xff\x2c\x16\xb7\x1d\xfc\xab\x7d\x4d\xd4\xe0\x93\x13\xd0\xa9\x42\xe0\xb6\x6b\xfe\x5d\x67\x48\xd7\x9f\x50\xbc\x6c\xcd\x4b\x03\x83\x7c\xf2\x08\x58\xcd\xac\xcf\x0c";
    var fbs = std.io.fixedBufferStream(testECDSACertificate);
    const allocator = testing.allocator;
    const cert = try Certificate.create(allocator, fbs.reader());
    std.log.debug("cert={}", .{cert});
}

test "PublicKey/PrivateKey" {
    std.debug.print("PublicKey.empty={}\n", .{PublicKey.empty});
    std.debug.print("PrivateKey.empty={}\n", .{PrivateKey.empty});
}
