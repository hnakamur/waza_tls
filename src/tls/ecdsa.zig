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
const elliptic = @import("elliptic.zig");
const pem = @import("pem.zig");
const fmtx = @import("../fmtx.zig");
const AesBlock = @import("aes.zig").AesBlock;
const Ctr = @import("ctr.zig").Ctr;

pub const PublicKey = union(CurveId) {
    secp256r1: PublicKeyP256,
    secp384r1: void,
    secp521r1: void,
    x25519: void,

    pub fn init(curve_id: CurveId, data: []const u8) !PublicKey {
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

    pub fn generate(
        allocator: mem.Allocator,
        curve_id: CurveId,
        rand: std.rand.Random,
    ) !PrivateKey {
        return switch (curve_id) {
            .secp256r1 => PrivateKey{
                .secp256r1 = try PrivateKeyP256.generate(allocator, rand),
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
        random: std.rand.Random,
        digest: []const u8,
        opts: crypto.SignOpts,
    ) ![]const u8 {
        return switch (self.*) {
            .secp256r1 => |*k| k.sign(allocator, random, digest, opts),
            else => @panic("not implemented yet"),
        };
    }
};

pub const PublicKeyP256 = struct {
    point: P256,

    pub fn init(data: []const u8) !PublicKeyP256 {
        const p = try P256.fromSec1(data);
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
    d: [P256.Fe.encoded_length]u8, // little endian

    pub fn init(d_big: [P256.Fe.encoded_length]u8) !PrivateKeyP256 {
        const d = P256.Fe.orderSwap(d_big);
        const pub_key_point = try P256.basePoint.mulPublic(d, .Little);
        return PrivateKeyP256{ .public_key = .{ .point = pub_key_point }, .d = d };
    }

    pub fn generate(allocator: mem.Allocator, rand: std.rand.Random) !PrivateKeyP256 {
        var k = try math.big.int.Managed.initCapacity(
            allocator,
            P256.scalar.encoded_length / @sizeOf(math.big.Limb),
        );
        defer k.deinit();
        try randFieldElement(&k, .secp256r1, rand);

        var d: []const u8 = undefined;
        d.ptr = @ptrCast([*]const u8, k.limbs.ptr);
        d.len = P256.Fe.encoded_length;
        return init(P256.Fe.orderSwap(d[0..P256.Fe.encoded_length].*));
    }

    pub fn bigD(self: *const PrivateKeyP256) [P256.Fe.encoded_length]u8 {
        var d2: [P256.Fe.encoded_length]u8 = undefined;
        for (self.d) |x, i| d2[d2.len - 1 - i] = x;
        return d2;
    }

    pub fn sign(
        self: *const PrivateKeyP256,
        allocator: mem.Allocator,
        random: std.rand.Random,
        digest: []const u8,
        opts: crypto.SignOpts,
    ) ![]const u8 {
        _ = opts;
        const priv_key = PrivateKey{ .secp256r1 = self.* };

        const capacity = bigint.limbsCapacityForBytesLength(P256.scalar.encoded_length);
        var r = try math.big.int.Managed.initCapacity(allocator, capacity);
        defer r.deinit();
        var s = try math.big.int.Managed.initCapacity(allocator, capacity);
        defer s.deinit();

        try signWithPrivateKey(allocator, random, &priv_key, digest, &r, &s);

        var buf = std.ArrayListUnmanaged(u8){};
        errdefer buf.deinit(allocator);

        const Context = struct {
            allocator: mem.Allocator,
            r: math.big.int.Const,
            s: math.big.int.Const,

            const Self = @This();

            fn write(ctx: Self, writer: anytype) !void {
                try asn1.writeAsn1BigInt(ctx.allocator, ctx.r, writer);
                try asn1.writeAsn1BigInt(ctx.allocator, ctx.s, writer);
            }
        };
        var ctx = Context{ .allocator = allocator, .r = r.toConst(), .s = s.toConst() };
        try asn1.writeAsn1(
            allocator,
            .sequence,
            Context,
            Context.write,
            ctx,
            buf.writer(allocator),
        );
        return buf.toOwnedSlice(allocator);
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

const aes_iv = "IV for ECDSA CTR";

pub fn signWithPrivateKey(
    allocator: mem.Allocator,
    rand: std.rand.Random,
    priv_key: *const PrivateKey,
    digest: []const u8,
    r: *math.big.int.Managed,
    s: *math.big.int.Managed,
) !void {
    {
        var d_bytes = priv_key.secp256r1.bigD();
        std.log.debug("signWithPrivateKey start, priv_key.d={}, digest={}", .{
            std.fmt.fmtSliceHexLower(&d_bytes),
            std.fmt.fmtSliceHexLower(digest),
        });
    }

    var entropy: [32]u8 = undefined;
    rand.bytes(&entropy);

    var md = Sha512.init(.{});
    const d = switch (priv_key.*) {
        .secp256r1 => |*k| k.bigD(),
        else => @panic("not implemented yet"),
    };
    md.update(&d);
    md.update(&entropy);
    md.update(digest);
    var key_buf: [Sha512.digest_length]u8 = undefined;
    md.final(&key_buf);
    const key = key_buf[0..32];
    std.log.debug("signWithPrivateKey key={}", .{std.fmt.fmtSliceHexLower(key)});

    var block = try AesBlock.init(key);
    var ctr = try Ctr.init(allocator, block, aes_iv);
    defer ctr.deinit(allocator);

    var csprng = StreamRandom.init(ZeroRandom.random(), ctr);
    try signGeneric(allocator, priv_key, csprng.random(), digest, r, s);
}

fn signGeneric(
    allocator: mem.Allocator,
    priv: *const PrivateKey,
    csprng: std.rand.Random,
    hash: []const u8,
    r: *math.big.int.Managed,
    s: *math.big.int.Managed,
) !void {
    const curve_id: CurveId = switch (priv.*) {
        .secp256r1 => .secp256r1,
        else => @panic("not implemented yet"),
    };
    var n = switch (curve_id) {
        .secp256r1 => try elliptic.p256ParamN(allocator),
        else => @panic("not implemented yet"),
    };
    defer n.deinit();

    if (n.eqZero()) {
        return error.ZeroParam;
    }

    while (true) {
        var k_inv = try math.big.int.Managed.initCapacity(
            allocator,
            P256.scalar.encoded_length / @sizeOf(math.big.Limb),
        );
        defer k_inv.deinit();
        switch (curve_id) {
            .secp256r1 => {
                while (true) {
                    var k = try math.big.int.Managed.initCapacity(
                        allocator,
                        P256.scalar.encoded_length / @sizeOf(math.big.Limb),
                    );
                    defer k.deinit();
                    try randFieldElement(&k, curve_id, csprng);

                    try p256Inverse(&k_inv, k.toConst());

                    var k_bytes_ptr = @ptrCast([*]const u8, k.limbs.ptr);
                    const point = try P256.basePoint.mulPublic(
                        k_bytes_ptr[0..P256.scalar.encoded_length].*,
                        .Little,
                    );
                    const x_bytes = point.affineCoordinates().x.toBytes(.Little);
                    try bigint.setManagedBytes(r, &x_bytes, .Little);
                    try bigint.mod(r, r.toConst(), n.toConst());
                    if (!r.eqZero()) {
                        break;
                    }
                }
            },
            else => @panic("not implemented yet"),
        }

        var e = try math.big.int.Managed.initCapacity(
            allocator,
            P256.scalar.encoded_length / @sizeOf(math.big.Limb),
        );
        defer e.deinit();
        try hashToInt(&e, hash, curve_id);

        var d = switch (priv.*) {
            .secp256r1 => |*k| try bigint.constFromBytes(allocator, &k.d, .Little),
            else => @panic("not implemented yet"),
        };
        defer bigint.deinitConst(d, allocator);

        try bigint.mul(s, d, r.toConst());
        try bigint.add(s, s.toConst(), e.toConst());
        try bigint.mul(s, s.toConst(), k_inv.toConst());
        try bigint.mod(s, s.toConst(), n.toConst());
        if (!s.eqZero()) {
            break;
        }
    }
}

// out and k may be alias
fn p256Inverse(out: *math.big.int.Managed, k: std.math.big.int.Const) !void {
    var k_limbs: []const u8 = undefined;
    k_limbs.ptr = @ptrCast([*]const u8, k.limbs.ptr);
    const k_scalar = try P256.scalar.Scalar.fromBytes(
        k_limbs[0..P256.scalar.encoded_length].*,
        .Little,
    );
    const k_inv_scalar = k_scalar.invert();
    const k_inv_bytes = k_inv_scalar.toBytes(.Little);
    try bigint.setManagedBytes(out, &k_inv_bytes, .Little);
}

// randFieldElement returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.1.
fn randFieldElement(
    out: *math.big.int.Managed,
    curve_id: CurveId,
    rand: std.rand.Random,
) !void {
    const encoded_length: usize = switch (curve_id) {
        .secp256r1 => P256.Fe.encoded_length,
        else => @panic("not implemented yet"),
    };

    const allocator = out.allocator;
    // Note that for P-521 this will actually be 63 bits more than the order, as
    // division rounds down, but the extra bit is inconsequential.
    var b = try allocator.alloc(u8, encoded_length + 8);
    defer allocator.free(b);

    rand.bytes(b);

    try bigint.setManagedBytes(out, b, .Big);

    var n = switch (curve_id) {
        .secp256r1 => try elliptic.p256ParamN(allocator),
        else => @panic("not implemented yet"),
    };
    defer n.deinit();

    try bigint.sub(&n, n.toConst(), bigint.one);
    try bigint.mod(out, out.toConst(), n.toConst());
    try bigint.add(out, out.toConst(), bigint.one);
}

fn hashToInt(
    out: *math.big.int.Managed,
    hash: []const u8,
    c: CurveId,
) !void {
    const encoded_length: usize = switch (c) {
        .secp256r1 => P256.Fe.encoded_length,
        else => @panic("not implemented yet"),
    };

    const hash2 = hash[0..math.min(hash.len, encoded_length)];
    try bigint.setManagedBytes(out, hash2, .Big);

    const field_bits: usize = switch (c) {
        .secp256r1 => P256.Fe.field_bits,
        else => @panic("not implemented yet"),
    };
    if (hash2.len * @bitSizeOf(u8) > field_bits) {
        const excess: usize = hash2.len * @bitSizeOf(u8) - field_bits;
        try out.shiftRight(out, excess);
    }
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method
// (exponentiation modulo P - 2, per Euler's theorem). This has better
// constant-time properties than Euclid's method (implemented in
// math/big.Int.ModInverse and FIPS 186-4, Appendix C.1) although math/big
// itself isn't strictly constant-time so it's not perfect.
fn fermatInverse(
    out: *math.big.int.Managed,
    allocator: mem.Allocator,
    k: math.big.int.Const,
    n: math.big.int.Const,
) !void {
    var n_minus_2 = try math.big.int.Managed.init(allocator);
    defer n_minus_2.deinit();
    try bigint.sub(&n_minus_2, n, bigint.two);
    try bigint.exp(out, k, n_minus_2.toConst(), n);
}

const ZeroRandom = struct {
    pub fn bytes(_: *anyopaque, buffer: []u8) void {
        mem.set(u8, buffer, 0);
    }

    pub fn random() std.rand.Random {
        return std.rand.Random{
            .ptr = undefined,
            .fillFn = bytes,
        };
    }
};

const StreamRandom = struct {
    const Self = @This();

    r: std.rand.Random,
    s: Ctr,

    pub fn init(r: std.rand.Random, s: Ctr) StreamRandom {
        return .{ .r = r, .s = s };
    }

    pub fn bytes(self: *Self, buffer: []u8) void {
        self.r.bytes(buffer);
        self.s.xorKeyStream(buffer, buffer);
    }

    pub fn random(self: *Self) std.rand.Random {
        return std.rand.Random.init(self, bytes);
    }
};

// verifyAsn1 verifies the ASN.1 encoded signature, sig, of hash using the
// public key, pub. Its return value records whether the signature is valid.
pub fn verifyAsn1(
    allocator: mem.Allocator,
    pub_key: *const PublicKey,
    hash: []const u8,
    sig: []const u8,
) !bool {
    var input = asn1.String.init(sig);
    var inner = try input.readAsn1(.sequence);
    if (!input.empty()) return false;
    var r = try inner.readAsn1BigInt(allocator);
    defer bigint.deinitConst(r, allocator);
    var s = try inner.readAsn1BigInt(allocator);
    defer bigint.deinitConst(s, allocator);
    if (!inner.empty()) return false;

    return verifyWithPublicKey(allocator, pub_key, hash, r, s);
}

pub fn verifyWithPublicKey(
    allocator: mem.Allocator,
    pub_key: *const PublicKey,
    hash: []const u8,
    r: math.big.int.Const,
    s: math.big.int.Const,
) !bool {
    const curve_id: CurveId = switch (pub_key.*) {
        .secp256r1 => .secp256r1,
        else => @panic("not implemented yet"),
    };
    var n = switch (curve_id) {
        .secp256r1 => try elliptic.p256ParamN(allocator),
        else => @panic("not implemented yet"),
    };
    defer n.deinit();

    if ((r.eqZero() or !r.positive) or (s.eqZero() or !s.positive)) {
        return false;
    }

    if (s.order(n.toConst()).compare(.gte) or r.order(n.toConst()).compare(.gte)) {
        return false;
    }

    return try verifyGeneric(allocator, pub_key, hash, r, s);
}

pub fn verifyGeneric(
    allocator: mem.Allocator,
    pub_key: *const PublicKey,
    hash: []const u8,
    r: math.big.int.Const,
    s: math.big.int.Const,
) !bool {
    const curve_id: CurveId = switch (pub_key.*) {
        .secp256r1 => .secp256r1,
        else => @panic("not implemented yet"),
    };

    var e = try math.big.int.Managed.initCapacity(
        allocator,
        P256.scalar.encoded_length / @sizeOf(math.big.Limb),
    );
    defer e.deinit();
    try hashToInt(&e, hash, curve_id);

    var n = switch (curve_id) {
        .secp256r1 => try elliptic.p256ParamN(allocator),
        else => @panic("not implemented yet"),
    };
    defer n.deinit();

    var w = try math.big.int.Managed.initCapacity(
        allocator,
        P256.scalar.encoded_length / @sizeOf(math.big.Limb),
    );
    defer w.deinit();
    switch (curve_id) {
        .secp256r1 => try p256Inverse(&w, s),
        else => @panic("not implemented yet"),
    }

    var @"u1" = try math.big.int.Managed.init(allocator);
    defer @"u1".deinit();
    try bigint.mul(&@"u1", e.toConst(), w.toConst());
    try bigint.mod(&@"u1", @"u1".toConst(), n.toConst());

    var @"u2" = try math.big.int.Managed.init(allocator);
    defer @"u2".deinit();
    try bigint.mul(&@"u2", r, w.toConst());
    try bigint.mod(&@"u2", @"u2".toConst(), n.toConst());

    const capacity = bigint.limbsCapacityForBytesLength(P256.scalar.encoded_length);
    var x = try math.big.int.Managed.initCapacity(allocator, capacity);
    defer x.deinit();
    var y = try math.big.int.Managed.initCapacity(allocator, capacity);
    defer y.deinit();
    switch (pub_key.*) {
        .secp256r1 => |*k| {
            const u1_bytes = bigint.managedToBytesLittle(@"u1");
            const p1 = try P256.basePoint.mulPublic(
                u1_bytes[0..P256.scalar.encoded_length].*,
                .Little,
            );

            const u2_bytes = bigint.managedToBytesLittle(@"u2");
            const p2 = try k.point.mulPublic(u2_bytes[0..P256.scalar.encoded_length].*, .Little);

            const p = p1.add(p2).affineCoordinates();
            try bigint.setManagedBytes(&x, &p.x.toBytes(.Little), .Little);
            try bigint.setManagedBytes(&y, &p.y.toBytes(.Little), .Little);
        },
        else => @panic("not implemented yet"),
    }

    if (x.eqZero() and y.eqZero()) {
        return false;
    }

    try bigint.mod(&x, x.toConst(), n.toConst());
    return x.toConst().order(r) == .eq;
}

const testing = std.testing;

test "ecdsa.PrivateKey.sign" {
    testing.log_level = .err;
    const allocator = testing.allocator;
    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);

    var priv_key = try PrivateKey.generate(allocator, .secp256r1, rand.random());
    std.log.debug("priv_key.d={}", .{std.fmt.fmtSliceHexLower(&priv_key.secp256r1.bigD())});
    const want_priv_d = "\x10\xa8\xe7\x42\x4b\x64\xdd\xaf\x8b\x3e\x7e\x42\x8c\x3f\x6e\x0e\x25\x37\x09\xbe\x28\x5c\x64\xbc\x41\xcc\x30\x0f\xd8\x00\xc1\x1f";
    try testing.expectEqualSlices(u8, want_priv_d, &priv_key.secp256r1.bigD());

    const digest = "\xcf\x36\xd2\xad\xe1\xc9\x40\x5c\x53\x04\xf6\xa6\xc4\xd1\xe3\x1a\xe3\x5b\x47\xd0\x4d\x6c\x27\x69\x14\x53\xed\x24\xdd\x76\x68\xe6";
    const signed = try priv_key.sign(allocator, rand.random(), digest, .{});
    defer allocator.free(signed);

    const want = "\x30\x44\x02\x20\x7e\xe2\x36\xae\x11\x2b\xe7\xa1\x92\xec\x5d\xd7\x40\x69\xbb\x7a\xf8\x13\x1d\x51\x61\xd6\x17\x06\x58\x9a\x9f\x74\xa3\x5b\xb0\x7c\x02\x20\x26\xd3\x02\x17\x5b\x0d\x4d\x28\x17\xa1\x93\xb2\x06\xbc\x4b\x2b\x02\x17\x35\x15\xde\xc4\x02\x69\xa8\x3a\x18\x35\xb8\xda\x4d\x40";
    try testing.expectEqualSlices(u8, want, signed);
}

test "ecdsa.signWithPrivateKey and verifyWithPublicKey" {
    testing.log_level = .err;
    const allocator = testing.allocator;
    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);

    var priv_key = try PrivateKey.generate(allocator, .secp256r1, rand.random());
    {
        var d_bytes = priv_key.secp256r1.bigD();
        std.log.debug("priv.d={}", .{std.fmt.fmtSliceHexLower(&d_bytes)});
    }
    const want_priv_key_d_big = "\x10\xa8\xe7\x42\x4b\x64\xdd\xaf\x8b\x3e\x7e\x42\x8c\x3f\x6e\x0e\x25\x37\x09\xbe\x28\x5c\x64\xbc\x41\xcc\x30\x0f\xd8\x00\xc1\x1f";
    try testing.expectEqualSlices(u8, want_priv_key_d_big, &priv_key.secp256r1.bigD());

    var hashed = try allocator.dupe(u8, "testing");
    defer allocator.free(hashed);

    var r = try math.big.int.Managed.init(allocator);
    defer r.deinit();
    var s = try math.big.int.Managed.init(allocator);
    defer s.deinit();

    try signWithPrivateKey(allocator, rand.random(), &priv_key, hashed, &r, &s);

    var r_bytes = try bigint.managedToBytesBig(allocator, r);
    defer allocator.free(r_bytes);
    var s_bytes = try bigint.managedToBytesBig(allocator, s);
    defer allocator.free(s_bytes);

    const want_r_bytes = "\xe1\x4f\xd9\xeb\x5f\x74\x3e\x74\x39\x0b\x09\xc9\xdf\xff\xea\xe4\xe4\x3f\xa7\xfa\x09\x85\xda\x7d\x81\x61\xb5\xcf\x83\xb6\x1d\x46";
    const want_s_bytes = "\x67\xd2\x12\xb5\xca\x48\x80\x78\x29\x22\xf7\xe4\x1f\x7d\xc0\x54\xec\x02\x53\x89\xd2\x09\xdc\xb4\x72\x16\xe7\xbe\x98\xfe\x06\xae";

    try testing.expectEqualSlices(u8, want_r_bytes, r_bytes);
    try testing.expectEqualSlices(u8, want_s_bytes, s_bytes);

    try testing.expect(try verifyWithPublicKey(
        allocator,
        &priv_key.publicKey(),
        hashed,
        r.toConst(),
        s.toConst(),
    ));

    hashed[0] ^= 0xff;
    try testing.expect(!try verifyWithPublicKey(
        allocator,
        &priv_key.publicKey(),
        hashed,
        r.toConst(),
        s.toConst(),
    ));
}

test "StreamRandom" {
    testing.log_level = .err;
    const allocator = testing.allocator;

    const key = "\x57\x0a\xb7\x5e\xb8\x7a\xbe\x27\x4b\xc4\x19\xb6\x45\xa6\x0f\xdc\xf8\x18\x05\xee\x0a\x49\xbf\x3d\x7c\xdc\x9a\xf7\xe7\x7f\x4e\x0d";

    var block = try AesBlock.init(key);
    var ctr = try Ctr.init(allocator, block, aes_iv);
    defer ctr.deinit(allocator);

    var csprng = StreamRandom.init(ZeroRandom.random(), ctr);

    const curve_id = CurveId.secp256r1;
    var k = try math.big.int.Managed.initCapacity(
        allocator,
        P256.scalar.encoded_length / @sizeOf(math.big.Limb),
    );
    defer k.deinit();
    try randFieldElement(&k, curve_id, csprng.random());

    var k_bytes: []const u8 = undefined;
    k_bytes.ptr = @ptrCast([*]const u8, k.limbs.ptr);
    k_bytes.len = k.len() * @sizeOf(math.big.Limb);
    std.log.debug("k={}", .{std.fmt.fmtSliceHexLower(k_bytes)});

    var k_rev = try allocator.alloc(u8, k_bytes.len);
    defer allocator.free(k_rev);
    for (k_bytes) |x, i| k_rev[k_rev.len - 1 - i] = x;

    const want = "\x9a\x0d\x1c\x11\x84\x62\x41\x97\x03\x2e\x6b\xbb\xf6\x37\xfc\xb3\x80\xa3\x69\x5d\x68\xf3\x7b\xb6\x48\xda\xaf\x4e\xa3\xb4\x6e\x7a";
    try testing.expectEqualSlices(u8, want, k_rev);
}

test "ecdsa.fermatInverse" {
    testing.log_level = .err;
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

    var got = try math.big.int.Managed.init(allocator);
    defer got.deinit();
    try fermatInverse(&got, allocator, k.toConst(), n.toConst());

    if (!want.eq(got)) {
        var got_str = try got.toString(allocator, 10, .lower);
        defer allocator.free(got_str);
        var want_str = try want.toString(allocator, 10, .lower);
        defer allocator.free(want_str);
        std.debug.print("\n got={s},\nwant={s}\n", .{ got_str, want_str });
    }

    try testing.expect(want.eq(got));
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
    const k_inv_bytes = k_inv_scalar.toBytes(.Little);
    var k_inv = try bigint.managedFromBytes(allocator, &k_inv_bytes, .Little);
    defer k_inv.deinit();
    try testing.expect(k_inv.eq(want));
}

test "ecdsa.hashToInt" {
    testing.log_level = .err;

    const allocator = testing.allocator;
    const hash = "testing";
    var n = try math.big.int.Managed.initCapacity(
        allocator,
        P256.scalar.encoded_length / @sizeOf(math.big.Limb),
    );
    defer n.deinit();
    try hashToInt(&n, hash, .secp256r1);

    var n_s = try n.toString(allocator, 10, .lower);
    defer allocator.free(n_s);

    try testing.expectEqualStrings("32762643847147111", n_s);
}

test "ecdsa.PrivateKey.parseAsn1" {
    testing.log_level = .err;
    const allocator = testing.allocator;
    const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");
    var offset: usize = 0;
    var key_block = try pem.Block.decode(allocator, key_pem, &offset);
    defer key_block.deinit(allocator);
    const key_der = key_block.bytes;
    const key = try PrivateKey.parseAsn1(allocator, key_der, null);
    std.log.debug("key={}", .{key});
    //Go priv.D=c6ae5808bbcdb5ae7625078b6cef4db0f486b4790af774971fc0fffc5063c686
}

test "randFieldElement" {
    testing.log_level = .err;
    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const allocator = testing.allocator;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);
    var k = try math.big.int.Managed.initCapacity(
        allocator,
        P256.scalar.encoded_length / @sizeOf(math.big.Limb),
    );
    defer k.deinit();
    try randFieldElement(&k, .secp256r1, rand.random());

    var want = try math.big.int.Managed.initSet(
        allocator,
        7535431974917535157809964245275928230175247012883497609941754139633030054175,
    );
    defer want.deinit();
    try testing.expect(want.eq(k));
}

test "PrivateKey.generate" {
    testing.log_level = .err;
    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const allocator = testing.allocator;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);
    var rand2 = rand.random();

    var priv_key = try PrivateKey.generate(allocator, .secp256r1, rand2);
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

test "crypto.core.modes.ctr" {
    // NIST SP 800-38A pp 55-58
    const ctr = std.crypto.core.modes.ctr;

    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    const in = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const exp_out = [_]u8{
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
    };

    var out: [exp_out.len]u8 = undefined;
    var ctx = Aes128.initEnc(key);
    ctr(AesEncryptCtx(Aes128), ctx, out[0..], in[0..], iv, std.builtin.Endian.Big);
    try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
}
