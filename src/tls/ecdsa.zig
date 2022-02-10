const std = @import("std");
const math = std.math;
const mem = std.mem;
const P256 = std.crypto.ecc.P256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Aes128 = std.crypto.core.aes.Aes128;
const AesEncryptCtx = std.crypto.core.aes.AesEncryptCtx;

const CurveId = @import("handshake_msg.zig").CurveId;
const asn1 = @import("asn1.zig");
const bigint = @import("big_int.zig");
const crypto = @import("crypto.zig");
const pem = @import("pem.zig");
const fmtx = @import("../fmtx.zig");

pub const PublicKey = union(CurveId) {
    secp256r1: PublicKeyP256,
    secp384r1: void,
    secp521r1: void,
    x25519: void,

    pub fn init(curve_id: CurveId, data: []const u8) !PublicKey {
        // std.log.debug(
        //     "ecdsa.PublicKey.init curve_id={}, data={}",
        //     .{ curve_id, fmtx.fmtSliceHexColonLower(data) },
        // );
        switch (curve_id) {
            .secp256r1 => return PublicKey{ .secp256r1 = try PublicKeyP256.init(data) },
            .secp384r1 => return PublicKey{ .secp384r1 = .{} },
            else => @panic("not implemented yet"),
        }
    }
};

pub const PrivateKey = union(CurveId) {
    secp256r1: PrivateKeyP256,
    secp384r1: void,
    secp521r1: void,
    x25519: void,

    pub fn parseAsn1(
        allocator: mem.Allocator,
        der: []const u8,
        oid: ?asn1.ObjectIdentifier,
    ) !PrivateKey {
        var input = asn1.String.init(der);
        var s = try input.readAsn1(.sequence);

        const version = try s.readAsn1Uint64();
        const ec_priv_key_version = 1;
        if (version != ec_priv_key_version) {
            return error.UnsupportedEcPrivateKeyVersion;
        }

        var tag: asn1.TagAndClass = undefined;
        var s2 = try s.readAnyAsn1(&tag);
        const private_key_bytes = s2.bytes;

        const curve_id = if (oid) |oid2| blk: {
            break :blk CurveId.fromOid(oid2) orelse return error.UnsupportedEcPrivateKeyCurveOid;
        } else blk: {
            if (s.empty()) {
                return error.EcPrivateKeyCurveOidMissing;
            }
            s2 = try s.readAnyAsn1(&tag);
            var oid2 = try asn1.ObjectIdentifier.parse(allocator, &s2);
            defer oid2.deinit(allocator);
            break :blk CurveId.fromOid(oid2) orelse return error.UnsupportedEcPrivateKeyCurveOid;
        };

        return try PrivateKey.init(curve_id, private_key_bytes);
    }

    pub fn generateForTest(
        allocator: mem.Allocator,
        curve_id: CurveId,
        rand: std.rand.Random,
    ) !PrivateKey {
        return switch (curve_id) {
            .secp256r1 => PrivateKey{
                .secp256r1 = try PrivateKeyP256.generateForTest(allocator, rand),
            },
            else => @panic("not implemented yet"),
        };
    }

    pub fn init(curve_id: CurveId, data: []const u8) !PrivateKey {
        switch (curve_id) {
            .secp256r1 => {
                if (data.len != P256.Fe.encoded_length) {
                    return error.InvalidPrivateKey;
                }
                return PrivateKey{
                    .secp256r1 = try PrivateKeyP256.init(data[0..P256.Fe.encoded_length].*),
                };
            },
            else => @panic("not implemented yet"),
        }
    }

    pub fn publicKey(self: *const PrivateKey) PublicKey {
        return switch (self.*) {
            .secp256r1 => |*k| PublicKey{ .secp256r1 = k.public_key },
            else => @panic("not implemented yet"),
        };
    }

    pub fn sign(
        self: *const PrivateKey,
        allocator: mem.Allocator,
        digest: []const u8,
        opts: crypto.SignOpts,
    ) ![]const u8 {
        return switch (self.*) {
            .secp256r1 => |*k| k.sign(allocator, digest, opts),
            else => @panic("not implemented yet"),
        };
    }
};

const PublicKeyP256 = struct {
    point: P256,

    pub fn init(data: []const u8) !PublicKeyP256 {
        const s = mem.trimLeft(u8, data, "\x00");
        const p = try P256.fromSec1(s);
        return PublicKeyP256{ .point = p };
    }

    pub fn format(
        self: PublicKeyP256,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        var x_bytes: []const u8 = undefined;
        x_bytes.ptr = @intToPtr([*]const u8, @ptrToInt(&self.point.x));
        x_bytes.len = P256.Fe.encoded_length;
        var y_bytes: []const u8 = undefined;
        y_bytes.ptr = @intToPtr([*]const u8, @ptrToInt(&self.point.y));
        y_bytes.len = P256.Fe.encoded_length;
        try std.fmt.format(writer, "PublicKeyP256{{ x = {}, y = {} }} }}", .{
            fmtx.fmtSliceHexColonLower(x_bytes),
            fmtx.fmtSliceHexColonLower(y_bytes),
        });
    }
};

const PrivateKeyP256 = struct {
    public_key: PublicKeyP256,
    d: [P256.Fe.encoded_length]u8,

    pub fn init(d: [P256.Fe.encoded_length]u8) !PrivateKeyP256 {
        const pub_key_point = try P256.basePoint.mulPublic(d, .Little);
        return PrivateKeyP256{ .public_key = .{ .point = pub_key_point }, .d = d };
    }

    pub fn generateForTest(allocator: mem.Allocator, rand: std.rand.Random) !PrivateKeyP256 {
        var k = try randFieldElement(allocator, .secp256r1, rand);
        defer bigint.deinitConst(k, allocator);

        var d: []const u8 = undefined;
        d.ptr = @ptrCast([*]const u8, k.limbs.ptr);
        d.len = P256.Fe.encoded_length;
        return init(d[0..P256.Fe.encoded_length].*);
    }

    pub fn sign(
        self: *const PrivateKeyP256,
        allocator: mem.Allocator,
        digest: []const u8,
        opts: crypto.SignOpts,
    ) ![]const u8 {
        _ = self;
        _ = allocator;
        _ = digest;
        _ = opts;
        @panic("not implemented yet");
    }

    pub fn format(
        self: PrivateKeyP256,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        var d_bytes: []const u8 = undefined;
        d_bytes.ptr = @intToPtr([*]const u8, @ptrToInt(&self.d));
        d_bytes.len = P256.Fe.encoded_length;
        try std.fmt.format(writer, "PrivateKeyP256{{ public_key = {}, d = {} }} }}", .{
            self.public_key,
            fmtx.fmtSliceHexColonLower(d_bytes),
        });
    }
};

const PublicKeyP384 = struct {
    not_implemented_yet: usize = 1,
};

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
fn randFieldElement(
    allocator: mem.Allocator,
    curve_id: CurveId,
    rand: std.rand.Random,
) !std.math.big.int.Const {
    const encoded_length: usize = switch (curve_id) {
        .secp256r1 => P256.Fe.encoded_length,
        else => @panic("not implemented yet"),
    };

    // Note that for P-521 this will actually be 63 bits more than the order, as
    // division rounds down, but the extra bit is inconsequential.
    var b = try allocator.alloc(u8, encoded_length + 8);
    defer allocator.free(b);

    rand.bytes(b);

    var k = try bigint.managedFromBytes(allocator, b);
    errdefer k.deinit();

    var n = switch (curve_id) {
        // value is copied from Fe.field_order in pcurves/p256/scalar.zig
        .secp256r1 => try math.big.int.Managed.initSet(
            allocator,
            115792089210356248762697446949407573529996955224135760342422259061068512044369,
        ),
        else => @panic("not implemented yet"),
    };
    defer n.deinit();

    try n.ensureAddCapacity(n.toConst(), bigint.one);
    try n.sub(n.toConst(), bigint.one);

    var q = try math.big.int.Managed.init(allocator);
    defer q.deinit();

    try q.divFloor(&k, k.toConst(), n.toConst());
    try k.add(k.toConst(), bigint.one);
    return k.toConst();
}

pub fn signWithPrivateKey(
    allocator: mem.Allocator,
    random: std.rand.Random,
    priv_key: *const PrivateKey,
    digest: []const u8,
    opts: crypto.SignOpts,
) ![]const u8 {
    _ = allocator;
    _ = opts;

    var entropy: [32]u8 = undefined;
    random.bytes(&entropy);

    var md = Sha512.init(.{});
    const d = switch (priv_key.*) {
        .secp256r1 => |*k| k.d,
        else => @panic("not implemented yet"),
    };
    md.update(d);
    md.update(&entropy);
    md.update(digest);
    var key_buf: [Sha512.digest_length]u8 = undefined;
    md.final(&key_buf);
    const key = key_buf[0..32];
    Aes128.initEnc(key);
    @panic("not implemented yet");
}

fn hashToInt(allocator: mem.Allocator, hash: []const u8, c: CurveId) !math.big.int.Managed {
    const encoded_length: usize = switch (c) {
        .secp256r1 => P256.Fe.encoded_length,
        else => @panic("not implemented yet"),
    };

    const hash2 = if (hash.len > encoded_length)
        hash[0..encoded_length]
    else
        hash;

    var ret = try bigint.managedFromBytes(allocator, hash2);

    const field_bits: usize = switch (c) {
        .secp256r1 => P256.Fe.field_bits,
        else => @panic("not implemented yet"),
    };
    // std.log.debug(
    //     "hashToInt, encoded_length={}, hash2.len={}, field_bits={}",
    //     .{ encoded_length, hash2.len, field_bits },
    // );
    if (hash2.len * 8 > field_bits) {
        const excess: usize = hash2.len * 8 - field_bits;
        try ret.shiftRight(ret, excess);
    }
    return ret;
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
fn fermatInverse(
    allocator: mem.Allocator,
    k: math.big.int.Const,
    n: math.big.int.Const,
) !math.big.int.Const {
    var n_minus_2 = try math.big.int.Managed.init(allocator);
    defer n_minus_2.deinit();
    try n_minus_2.sub(n, bigint.two);
    return try bigint.expConst(allocator, k, n_minus_2.toConst(), n);
}

const testing = std.testing;

test "ecdsa.fermatInverse" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    var k = try math.big.int.Managed.initSet(
        allocator,
        31165868474356909094101301562817744597875721467446372694368806754002914873404,
    );
    defer k.deinit();

    var n = try math.big.int.Managed.initSet(
        allocator,
        115792089210356248762697446949407573529996955224135760342422259061068512044369,
    );
    defer n.deinit();

    var want = try math.big.int.Managed.initSet(
        allocator,
        86225417743096558800740718328827616534367331415382654615473225504007389458516,
    );
    defer want.deinit();

    var got = try fermatInverse(allocator, k.toConst(), n.toConst());
    defer bigint.deinitConst(got, allocator);

    if (!want.toConst().eq(got)) {
        var got_m = try got.toManaged(allocator);
        defer got_m.deinit();
        var got_str = try got_m.toString(allocator, 10, .lower);
        defer allocator.free(got_str);
        var want_str = try want.toString(allocator, 10, .lower);
        defer allocator.free(want_str);
        std.debug.print("\n got={s},\nwant={s}\n", .{ got_str, want_str });
    }

    try testing.expect(want.toConst().eq(got));
}

test "p256.Scalar.invert" {
    const allocator = testing.allocator;
    var k = try math.big.int.Managed.initSet(
        allocator,
        69679341414823589043920591308017428039318963656356153131478201006811587571322,
    );
    defer k.deinit();

    var want = try math.big.int.Managed.initSet(
        allocator,
        86586517801769794643900956701147035451346541280727946852964839837080582533940,
    );
    defer want.deinit();

    var k_limbs: []const u8 = undefined;
    k_limbs.ptr = @ptrCast([*]const u8, k.limbs.ptr);
    const k_scalar = try P256.scalar.Scalar.fromBytes(
        k_limbs[0..P256.scalar.encoded_length].*,
        .Little,
    );
    const k_inv_scalar = k_scalar.invert();
    const k_inv_bytes = k_inv_scalar.toBytes(.Big);
    var k_inv = try bigint.managedFromBytes(allocator, &k_inv_bytes);
    defer k_inv.deinit();
    // var k_inv_str = try k_inv.toString(allocator, 10, .lower);
    // defer allocator.free(k_inv_str);
    // std.debug.print("k_inv={s}\n", .{k_inv_str});
    try testing.expect(k_inv.eq(want));
}

test "ecdsa.hashToInt" {
    testing.log_level = .debug;

    const allocator = testing.allocator;
    const hash = "testing";
    var n = try hashToInt(allocator, hash, .secp256r1);
    defer n.deinit();

    var n_s = try n.toString(allocator, 10, .lower);
    defer allocator.free(n_s);

    try testing.expectEqualStrings("32762643847147111", n_s);
}

test "ecdsa.PrivateKey.parseAsn1" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");
    var offset: usize = 0;
    var key_block = try pem.Block.decode(allocator, key_pem, &offset);
    defer key_block.deinit(allocator);
    const key_der = key_block.bytes;
    const key = try PrivateKey.parseAsn1(allocator, key_der, null);
    std.log.debug("key={}", .{key});
}

test "randFieldElement" {
    testing.log_level = .debug;
    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const allocator = testing.allocator;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);
    var rand2 = rand.random();
    var k = try randFieldElement(allocator, .secp256r1, rand2);
    defer bigint.deinitConst(k, allocator);

    var want = try math.big.int.Managed.initSet(
        allocator,
        7535431974917535157809964245275928230175247012883497609941754139633030054175,
    );
    defer want.deinit();
    try testing.expect(want.toConst().eq(k));
}

test "PrivateKey.generateForTest" {
    testing.log_level = .debug;
    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const allocator = testing.allocator;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);
    var rand2 = rand.random();

    var priv_key = try PrivateKey.generateForTest(allocator, .secp256r1, rand2);
    // std.log.debug("priv_key={}", .{priv_key});

    const d_want = "10a8e7424b64ddaf8b3e7e428c3f6e0e253709be285c64bc41cc300fd800c11f";
    const x_want = "b4eda0b0f478fdc289d8d759f5600eb873e711f70090a8cf55ccadcfeccaf023";
    const y_want = "9f4cecf8a0eae3d3f6299cdb52fde60fb64aa3694795df1516bc9ddb05aa0ecc";

    var src: []const u8 = undefined;
    var bytes_buf: [32]u8 = undefined;
    var hex_buf: [64]u8 = undefined;

    src.ptr = @intToPtr([*]const u8, @ptrToInt(&priv_key.secp256r1.d));
    src.len = P256.Fe.encoded_length;
    mem.copy(u8, &bytes_buf, src);
    mem.reverse(u8, &bytes_buf);

    var fbs = std.io.fixedBufferStream(&hex_buf);
    try std.fmt.format(fbs.writer(), "{}", .{std.fmt.fmtSliceHexLower(&bytes_buf)});
    try testing.expectEqualStrings(d_want, &hex_buf);

    const p = priv_key.secp256r1.public_key.point.affineCoordinates();

    fbs = std.io.fixedBufferStream(&hex_buf);
    try std.fmt.format(fbs.writer(), "{}", .{std.fmt.fmtSliceHexLower(&p.x.toBytes(.Big))});
    try testing.expectEqualStrings(x_want, &hex_buf);

    fbs = std.io.fixedBufferStream(&hex_buf);
    try std.fmt.format(fbs.writer(), "{}", .{std.fmt.fmtSliceHexLower(&p.y.toBytes(.Big))});
    try testing.expectEqualStrings(y_want, &hex_buf);
}
