const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;

const Limb = std.math.big.Limb;
const limb_bits = @typeInfo(Limb).Int.bits;
const DoubleLimb = std.math.big.DoubleLimb;
const SignedDoubleLimb = std.math.big.SignedDoubleLimb;
const Const = std.math.big.int.Const;
const Mutable = std.math.big.int.Mutable;
const Managed = std.math.big.int.Managed;

const big_zero = Const{ .limbs = &[_]Limb{0}, .positive = true };
const big_one = Const{ .limbs = &[_]Limb{1}, .positive = true };

// setBytes interprets buf as the bytes of a big-endian unsigned
// integer, sets z to that value, and returns z.
pub fn bigIntConstFromBytes(allocator: mem.Allocator, buf: []const u8) !Const {
    var limbs = try allocator.alloc(Limb, try math.divCeil(usize, buf.len, @sizeOf(Limb)));
    errdefer allocator.free(limbs);

    var limbs_bytes = @ptrCast([*]u8, limbs.ptr);
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        // Note:  note bytes in zig's big integer are little-endian ordered.
        limbs_bytes[i] = buf[buf.len - 1 - i];
    }
    mem.set(u8, limbs_bytes[i .. limbs.len * @sizeOf(Limb)], 0);

    return Const{ .limbs = limbs, .positive = true };
}

// bigIntConstExp returns x**y mod |m| (i.e. the sign of m is ignored).
// If m == 0, returns x**y unless y <= 0 then returns 1. If m != 0, y < 0,
// and x and m are not relatively prime, returns error.BadBigIntInputs.
//
// Modular exponentiation of inputs of a particular size is not a
// cryptographically constant-time operation.
pub fn bigIntConstExp(
    allocator: mem.Allocator,
    x: Const,
    y: Const,
    m: Const,
) !Const {
    // See Knuth, volume 2, section 4.6.3.
    var x2 = x;
    if (!y.positive) {
        if (m.eqZero()) {
            return try bigIntConstClone(allocator, big_one);
        }
        // for y < 0: x**y mod m == (x**(-1))**|y| mod m
        @panic("not implemented yet");
    }
    const m_abs = m.abs();
    var z = try bigIntConstExpNN(allocator, x2.abs(), y.abs(), m_abs);
    // std.log.debug("z.limbs.ptr=0x{x}", .{@ptrToInt(z.limbs.ptr)});
    z.setSign(!(!z.eqZero() and !x.positive and !y.eqZero() and y.limbs[0] & 1 == 1));
    if (!z.isPositive() and !m.eqZero()) {
        // make modulus result positive
        // z == x**y mod |m| && 0 <= z < |m|
        try z.sub(m_abs, z.toConst().abs());
        // std.log.debug("z.limbs.ptr#2=0x{x}", .{@ptrToInt(z.limbs.ptr)});
        return z.toConst().abs();
    }
    return z.toConst();
}

// bigIntConstModInverse returns the multiplicative inverse of g in the ring ℤ/nℤ.
// If g and n are not relatively prime, g has no multiplicative
// inverse in the ring ℤ/nℤ.  In this case, returns a zero.
pub fn bigIntConstModInverse(
    allocator: mem.Allocator,
    g: Const,
    n: Const,
) !Const {
    // GCD expects parameters a and b to be > 0.
    var n2 = n;
    if (!n.positive) {
        n2 = n.negate();
    }

    var g2 = try g.toManaged(allocator);
    defer g2.deinit();
    if (!g.positive) {
        try mod(&g2, g, n);
    }

    @panic("not implemented yet");
}

// mod sets r to the modulus x%y for y != 0.
// If y == 0, a division-by-zero run-time panic occurs.
// mod implements Euclidean modulus (unlike Go).
fn mod(
    r: *Managed,
    x: Const,
    y: Const,
) !void {
    var q = try Managed.init(r.allocator);
    defer q.deinit();
    try q.divTrunc(&r, x, y);
}

// GCD sets z to the greatest common divisor of a and b and returns z.
// If x or y are not nil, GCD sets their value such that z = a*x + b*y.
//
// a and b may be positive, zero or negative. (Before Go 1.14 both had
// to be > 0.) Regardless of the signs of a and b, z is always >= 0.
//
// If a == b == 0, GCD sets z = x = y = 0.
//
// If a == 0 and b != 0, GCD sets z = |b|, x = 0, y = sign(b) * 1.
//
// If a != 0 and b == 0, GCD sets z = |a|, x = sign(a) * 1, y = 0.
fn gcd(d: *Managed, x: ?*Managed, y: ?*Managed, a: Managed, b: Managed) !void {
    // try d.gcd(a, b);
    try gcdManaged(d, a, b);

    if (x) |x_out| {
        if (a.eqZero()) {
            try x_out.set(0);
        } else if (b.eqZero()) {
            try x_out.set(if (a.isPositive()) @as(i8, 1) else @as(i8, -1));
        } else {
            // TODO: implement
        }
    }
    if (y) |y_out| {
        if (b.eqZero()) {
            try y_out.set(0);
        } else if (a.eqZero()) {
            try y_out.set(if (b.isPositive()) @as(i8, 1) else @as(i8, -1));
        } else {
            // TODO: implement
        }
    }
}

/// rma may alias a or b.
/// a and b may alias each other.
///
/// rma's allocator is used for temporary storage to boost multiplication performance.
pub fn gcdManaged(rma: *Managed, a: Managed, b: Managed) !void {
    try rma.ensureCapacity(math.min(a.len(), b.len()));
    var m = rma.toMutable();
    var limbs_buffer = std.ArrayList(Limb).init(rma.allocator);
    defer limbs_buffer.deinit();
    try gcdMutable(&m, a.toConst(), b.toConst(), &limbs_buffer);
    rma.setMetadata(m.positive, m.len);
}

/// rma may alias a or b.
/// a and b may alias each other.
/// Asserts that `rma` has enough limbs to store the result. Upper bound is
/// `math.min(a.limbs.len, b.limbs.len)`.
///
/// `limbs_buffer` is used for temporary storage during the operation. When this function returns,
/// it will have the same length as it had when the function was called.
pub fn gcdMutable(rma: *Mutable, a: Const, b: Const, limbs_buffer: *std.ArrayList(Limb)) !void {
    const prev_len = limbs_buffer.items.len;
    defer limbs_buffer.shrinkRetainingCapacity(prev_len);
    const a_copy = if (rma.limbs.ptr == a.limbs.ptr) blk: {
        const start = limbs_buffer.items.len;
        try limbs_buffer.appendSlice(a.limbs);
        break :blk a.toMutable(limbs_buffer.items[start..]).toConst();
    } else a;
    const b_copy = if (rma.limbs.ptr == b.limbs.ptr) blk: {
        const start = limbs_buffer.items.len;
        try limbs_buffer.appendSlice(b.limbs);
        break :blk b.toMutable(limbs_buffer.items[start..]).toConst();
    } else b;

    return gcdLehmer(rma, a_copy, b_copy, limbs_buffer);
}

fn gcdLehmer(result: *Mutable, a_c: Const, b_c: Const, limbs_buffer: *std.ArrayList(Limb)) !void {
    var a = try a_c.toManaged(limbs_buffer.allocator);
    defer a.deinit();
    a.abs();

    var b = try b_c.toManaged(limbs_buffer.allocator);
    defer b.deinit();
    b.abs();

    if (a.toConst().order(b.toConst()) == .lt) {
        a.swap(&b);
    }

    var t_big = try Managed.init(limbs_buffer.allocator);
    defer t_big.deinit();

    var r = try Managed.init(limbs_buffer.allocator);
    defer r.deinit();

    var tmp_a = try Managed.init(limbs_buffer.allocator);
    defer tmp_a.deinit();

    while (b.len() > 1) {
        assert(a.isPositive() and b.isPositive());
        assert(a.len() >= b.len());

        var xh: SignedDoubleLimb = a.limbs[a.len() - 1];
        var yh: SignedDoubleLimb = if (a.len() > b.len()) 0 else b.limbs[a.len() - 1];

        var A: SignedDoubleLimb = 1;
        var B: SignedDoubleLimb = 0;
        var C: SignedDoubleLimb = 0;
        var D: SignedDoubleLimb = 1;

        while (yh + C != 0 and yh + D != 0) {
            const q = @divFloor(xh + A, yh + C);
            const qp = @divFloor(xh + B, yh + D);
            if (q != qp) {
                break;
            }

            var t = A - q * C;
            A = C;
            C = t;
            t = B - q * D;
            B = D;
            D = t;

            t = xh - q * yh;
            xh = yh;
            yh = t;
        }

        if (B == 0) {
            // t_big = a % b, r is unused
            try r.divTrunc(&t_big, a.toConst(), b.toConst());
            assert(t_big.isPositive());

            a.swap(&b);
            b.swap(&t_big);
        } else {
            var storage: [8]Limb = undefined;
            const Ap = fixedIntFromSignedDoubleLimb(A, storage[0..2]).toConst();
            const Bp = fixedIntFromSignedDoubleLimb(B, storage[2..4]).toConst();
            const Cp = fixedIntFromSignedDoubleLimb(C, storage[4..6]).toConst();
            const Dp = fixedIntFromSignedDoubleLimb(D, storage[6..8]).toConst();

            // t_big = Aa + Bb
            try r.mul(a.toConst(), Ap);
            try t_big.mul(b.toConst(), Bp);
            try t_big.add(r.toConst(), t_big.toConst());

            // u = Ca + Db, r as u
            try tmp_a.copy(a.toConst());
            try a.mul(tmp_a.toConst(), Cp);
            try r.mul(b.toConst(), Dp);
            try r.add(a.toConst(), r.toConst());

            a.swap(&t_big);
            b.swap(&r);
        }
    }

    // euclidean algorithm
    assert(a.toConst().order(b.toConst()) != .lt);

    while (!b.toConst().eqZero()) {
        try t_big.divTrunc(&r, a.toConst(), b.toConst());
        a.swap(&b);
        b.swap(&r);
    }

    result.copy(a.toConst());
}

// Storage must live for the lifetime of the returned value
fn fixedIntFromSignedDoubleLimb(A: SignedDoubleLimb, storage: []Limb) Mutable {
    assert(storage.len >= 2);

    const A_is_positive = A >= 0;
    const Au = @intCast(DoubleLimb, if (A < 0) -A else A);
    storage[0] = @truncate(Limb, Au);
    storage[1] = @truncate(Limb, Au >> limb_bits);
    return .{
        .limbs = storage[0..2],
        .positive = A_is_positive,
        .len = 2,
    };
}

// bigIntConstExpNN returns x**y mod m if m != 0,
// otherwise it returns x**y.
fn bigIntConstExpNN(
    allocator: mem.Allocator,
    x_abs: Const,
    y_abs: Const,
    m_abs: Const,
) !Managed {
    // x**y mod 1 == 0
    if (m_abs.eq(big_one)) {
        return try big_zero.toManaged(allocator);
    }
    // m == 0 || m > 1

    // x**0 == 1
    if (y_abs.eq(big_zero)) {
        return try big_one.toManaged(allocator);
    }
    // y > 0

    // x**1 mod m == x mod m
    if (y_abs.eq(big_one) and !m_abs.eqZero()) {
        var q = try Managed.init(allocator);
        defer q.deinit();
        var r = try Managed.init(allocator);
        errdefer r.deinit();
        // std.log.debug("r.limbs.ptr=0x{x}", .{@ptrToInt(r.limbs.ptr)});
        try q.divFloor(&r, x_abs, m_abs);
        return r;
    }
    // y > 1

    // We likely end up being as long as the modulus.
    var z = try Managed.initCapacity(allocator, m_abs.limbs.len);
    defer z.deinit();
    try z.copy(x_abs);

    // If the base is non-trivial and the exponent is large, we use
    // 4-bit, windowed exponentiation. This involves precomputing 14 values
    // (x^2...x^15) but then reduces the number of multiply-reduces by a
    // third. Even for a 32-bit exponent, this reduces the number of
    // operations. Uses Montgomery method for odd moduli.
    if (x_abs.order(big_one) == .gt and y_abs.limbs.len > 1 and !m_abs.eqZero()) {
        if (m_abs.limbs[0] & 1 == 1) {
            @panic("not implemented yet#2");
        }
        @panic("not implemented yet#3");
    }

    var v = y_abs.limbs[y_abs.limbs.len - 1]; // v > 0 because y_abs is normalized and y_abs > 0
    const shift = nlz(v) + 1;
    // std.log.debug("bigIntConstExpNN v={}, shift={}", .{ v, shift });
    v = math.shl(Limb, v, shift);
    // std.log.debug("bigIntConstExpNN shifted v={}", .{v});
    var q = try Managed.init(allocator);
    defer q.deinit();

    const mask = math.shl(Limb, 1, @bitSizeOf(Limb) - 1);

    // We walk through the bits of the exponent one by one. Each time we
    // see a bit, we square, thus doubling the power. If the bit is a one,
    // we also multiply by x, thus adding one to the power.
    const w = @bitSizeOf(Limb) - shift;
    // zz and r are used to avoid allocating in mul and div as
    // otherwise the arguments would alias.
    var zz = try Managed.init(allocator);
    defer zz.deinit();
    var r = try Managed.init(allocator);
    defer r.deinit();
    var j: usize = 0;
    while (j < w) : (j += 1) {
        try zz.sqr(z.toConst());
        zz.swap(&z);

        if (v & mask != 0) {
            try zz.mul(z.toConst(), x_abs);
            zz.swap(&z);
        }

        if (!m_abs.eqZero()) {
            try zz.divFloor(&r, z.toConst(), m_abs);
            zz.swap(&q);
            z.swap(&r);
        }

        v = math.shl(Limb, v, 1);
    }

    var i: isize = @intCast(isize, y_abs.limbs.len) - 2;
    while (i >= 0) : (i -= 1) {
        v = y_abs.limbs[@intCast(usize, i)];

        j = 0;
        while (j < @bitSizeOf(Limb)) : (j += 1) {
            try zz.sqr(z.toConst());
            zz.swap(&z);

            if (v & mask != 0) {
                try zz.mul(z.toConst(), x_abs);
                zz.swap(&z);
            }

            if (!m_abs.eqZero()) {
                try zz.divFloor(&r, z.toConst(), m_abs);
                zz.swap(&q);
                z.swap(&r);
            }

            v = math.shl(Limb, v, 1);
        }
    }
    return try z.clone();
}

// nlz returns the number of leading zeros in x.
fn nlz(x: Limb) usize {
    return @clz(Limb, x);
}

fn bigIntConstClone(
    allocator: mem.Allocator,
    x: Const,
) !Const {
    return Const{
        .limbs = try allocator.dupe(Limb, x.limbs),
        .positive = x.positive,
    };
}

const testing = std.testing;

test "std.Const const" {
    try testing.expectEqual(@as(u64, 0), try big_zero.to(u64));
    try testing.expectEqual(@as(u64, 1), try big_one.to(u64));
}

test "std.Const zero" {
    const allocator = testing.allocator;
    var zero = (try std.Managed.initSet(allocator, 0)).toConst();
    defer allocator.free(zero.limbs);
    try testing.expectEqualSlices(std.Limb, &[_]std.Limb{0}, zero.limbs);
    try testing.expect(zero.positive);
}

test "bigIntConstFromBytes" {
    testing.log_level = .debug;
    const buf = &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0xfe };
    const allocator = testing.allocator;
    var i = try bigIntConstFromBytes(allocator, buf);
    defer allocator.free(i.limbs);

    var s = try i.toStringAlloc(allocator, 10, .lower);
    defer allocator.free(s);
    try testing.expectEqualStrings("335812727627494322174", s);
}

test "bigIntConstExp" {
    testing.log_level = .debug;

    const f = struct {
        fn f(
            x_base: u8,
            x: []const u8,
            y_base: u8,
            y: []const u8,
            m_base: u8,
            m: []const u8,
            out_base: u8,
            out: []const u8,
        ) !void {
            const allocator = testing.allocator;
            var x_i = try initConst(allocator, x_base, x);
            defer allocator.free(x_i.limbs);
            var y_i = try initConst(allocator, y_base, y);
            defer allocator.free(y_i.limbs);
            var m_i = try initConst(allocator, m_base, m);
            defer allocator.free(m_i.limbs);
            var out_i = try initConst(allocator, out_base, out);
            defer allocator.free(out_i.limbs);

            var got = try bigIntConstExp(allocator, x_i, y_i, m_i);
            defer allocator.free(got.limbs);
            // std.log.debug("got.limbs.ptr=0x{x}", .{@ptrToInt(got.limbs.ptr)});
            if (!got.eq(out_i)) {
                var got_s = try got.toStringAlloc(allocator, 10, .lower);
                defer allocator.free(got_s);
                var want_s = try out_i.toStringAlloc(allocator, 10, .lower);
                defer allocator.free(want_s);
                std.debug.print("result mismatch, got={s}, want={s}\n", .{ got_s, want_s });
                return error.TestExpectedError;
            }
        }

        fn initConst(allocator: mem.Allocator, base: u8, value: []const u8) !Const {
            var m = try Managed.init(allocator);
            errdefer m.deinit();
            try m.setString(base, value);
            return m.toConst();
        }
    }.f;

    // y <= 0
    try f(10, "0", 10, "0", 10, "0", 10, "1");
    try f(10, "1", 10, "0", 10, "0", 10, "1");
    try f(10, "-10", 10, "0", 10, "0", 10, "1");
    try f(10, "1234", 10, "-1", 10, "0", 10, "1");
    // try f(10, "17", 10, "-100", 10, "1234", 10, "865");
    // try f(10, "2", 10, "-100", 10, "1234", 10, "0");

    // m == 1
    try f(10, "0", 10, "0", 10, "1", 10, "0");
    try f(10, "1", 10, "0", 10, "1", 10, "0");
    try f(10, "-10", 10, "0", 10, "1", 10, "0");
    // try f(10, "1234", 10, "-1", 10, "1", 10, "0");

    // misc
    try f(10, "5", 10, "1", 10, "3", 10, "2");
    try f(10, "5", 10, "-7", 10, "0", 10, "1");
    try f(10, "-5", 10, "-7", 10, "0", 10, "1");
    try f(10, "5", 10, "0", 10, "0", 10, "1");
    try f(10, "-5", 10, "0", 10, "0", 10, "1");
    try f(10, "5", 10, "1", 10, "0", 10, "5");
    try f(10, "-5", 10, "1", 10, "0", 10, "-5");
    try f(10, "-5", 10, "1", 10, "7", 10, "2");
    try f(10, "-2", 10, "3", 10, "2", 10, "0");
    try f(10, "5", 10, "2", 10, "0", 10, "25");
    try f(10, "1", 10, "65537", 10, "2", 10, "1");
    try f(16, "8000000000000000", 10, "2", 10, "0", 16, "40000000000000000000000000000000");
    try f(16, "8000000000000000", 10, "2", 10, "6719", 10, "4944");
    try f(16, "8000000000000000", 10, "3", 10, "6719", 10, "5447");
    try f(16, "8000000000000000", 10, "1000", 10, "6719", 10, "1603");
    try f(16, "8000000000000000", 10, "1000000", 10, "6719", 10, "3199");
}

test "bigIntDivTrunc" {
    // Zig's std.Managed.divTrunc equals to Go's math/big.QuoRem.
    const f = struct {
        fn f(x: i64, y: i64, q: i64, r: i64, d: i64, m: i64) !void {
            _ = d;
            _ = m;
            const allocator = testing.allocator;
            { // no alias
                var big_x = try Managed.initSet(allocator, x);
                defer big_x.deinit();
                var big_y = try Managed.initSet(allocator, y);
                defer big_y.deinit();
                var big_q = try Managed.init(allocator);
                defer big_q.deinit();
                var big_r = try Managed.init(allocator);
                defer big_r.deinit();
                try big_q.divTrunc(&big_r, big_x.toConst(), big_y.toConst());
                try testing.expectEqual(q, try big_q.to(i64));
                try testing.expectEqual(r, try big_r.to(i64));
            }
            // Though these test passes, Managed.divTrunc document says nothing
            // about aliases, and Mutable.divTrunc document says q may alias with
            // a or b, but says nothing about r.
            { // alias r and x, q and y
                var big_q = try Managed.initSet(allocator, y);
                defer big_q.deinit();
                var big_r = try Managed.initSet(allocator, x);
                defer big_r.deinit();
                try big_q.divTrunc(&big_r, big_r.toConst(), big_q.toConst());
                try testing.expectEqual(q, try big_q.to(i64));
                try testing.expectEqual(r, try big_r.to(i64));
            }
            { // alias q and x, r and y
                var big_q = try Managed.initSet(allocator, x);
                defer big_q.deinit();
                var big_r = try Managed.initSet(allocator, y);
                defer big_r.deinit();
                try big_q.divTrunc(&big_r, big_q.toConst(), big_r.toConst());
                try testing.expectEqual(q, try big_q.to(i64));
                try testing.expectEqual(r, try big_r.to(i64));
            }
        }
    }.f;

    try f(5, 3, 1, 2, 1, 2);
    try f(-5, 3, -1, -2, -2, 1);
    try f(5, -3, -1, 2, -1, 2);
    try f(-5, -3, 1, -2, 2, 1);
    try f(1, 2, 0, 1, 0, 1);
    try f(8, 4, 2, 0, 2, 0);
}

test "gcd" {
    const f = struct {
        fn f(d: []const u8, x: []const u8, y: []const u8, a: []const u8, b: []const u8) !void {
            const allocator = testing.allocator;

            var big_a = try strToManaged(allocator, a);
            defer big_a.deinit();
            var big_b = try strToManaged(allocator, b);
            defer big_b.deinit();

            var want_d = try strToManaged(allocator, d);
            defer want_d.deinit();
            var want_x = try strToManaged(allocator, x);
            defer want_x.deinit();
            var want_y = try strToManaged(allocator, y);
            defer want_y.deinit();

            {
                var got_d = try Managed.init(allocator);
                defer got_d.deinit();
                try gcd(&got_d, null, null, big_a, big_b);
                if (!got_d.eq(want_d)) {
                    std.debug.print("gcd d mismatch, got={}, want={}\n", .{ got_d, want_d });
                    return error.TestExpectedError;
                }
            }
            {
                var got_d = try Managed.init(allocator);
                defer got_d.deinit();
                var got_x = try Managed.init(allocator);
                defer got_x.deinit();
                try gcd(&got_d, &got_x, null, big_a, big_b);
                if (!got_d.eq(want_d)) {
                    std.debug.print("gcd d mismatch, got={}, want={}\n", .{ got_d, want_d });
                    return error.TestExpectedError;
                }
                if (!got_x.eq(want_x)) {
                    std.debug.print("gcd x mismatch, got={}, want={}\n", .{ got_x, want_x });
                    return error.TestExpectedError;
                }
            }
        }

        fn strToManaged(allocator: mem.Allocator, value: []const u8) !Managed {
            var m = try Managed.init(allocator);
            errdefer m.deinit();
            try m.setString(10, value);
            return m;
        }
    }.f;

    // a <= 0 || b <= 0
    try f("0", "0", "0", "0", "0");
    try f("7", "0", "1", "0", "7");
    try f("7", "0", "-1", "0", "-7");
    try f("11", "1", "0", "11", "0");
    try f("7", "-1", "-2", "-77", "35");
    try f("935", "-3", "8", "64515", "24310");
    try f("935", "-3", "-8", "64515", "-24310");
    try f("935", "3", "-8", "-64515", "-24310");

    try f("1", "-9", "47", "120", "23");
    try f("7", "1", "-2", "77", "35");
    try f("935", "-3", "8", "64515", "24310");
    try f("935000000000000000", "-3", "8", "64515000000000000000", "24310000000000000000");
    try f(
        "1",
        "-221",
        "22059940471369027483332068679400581064239780177629666810348940098015901108344",
        "98920366548084643601728869055592650835572950932266967461790948584315647051443",
        "991",
    );
}
