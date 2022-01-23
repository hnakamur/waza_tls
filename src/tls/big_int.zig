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

const bits = @import("bits.zig");

const big_zero = Const{ .limbs = &[_]Limb{0}, .positive = true };
const big_one = Const{ .limbs = &[_]Limb{1}, .positive = true };

// constFromBytes interprets buf as the bytes of a big-endian unsigned
// integer, sets z to that value, and returns z.
pub fn constFromBytes(allocator: mem.Allocator, buf: []const u8) !Const {
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

// expConst returns x**y mod |m| (i.e. the sign of m is ignored).
// If m == 0, returns x**y unless y <= 0 then returns 1. If m != 0, y < 0,
// and x and m are not relatively prime, returns 0.
//
// Modular exponentiation of inputs of a particular size is not a
// cryptographically constant-time operation.
fn expConst(
    allocator: mem.Allocator,
    x: Const,
    y: Const,
    m: Const,
) !Const {
    // See Knuth, volume 2, section 4.6.3.
    var x2 = x;
    var x3: ?Const = null;
    defer if (x3) |xx3| allocator.free(xx3.limbs);
    if (!y.positive) {
        if (m.eqZero()) {
            return try cloneConst(allocator, big_one);
        }
        // for y < 0: x**y mod m == (x**(-1))**|y| mod m
        x3 = try modInverseConst(allocator, x, m);
        x2 = x3.?;
        if (x2.eqZero()) {
            return try cloneConst(allocator, big_zero);
        }
    }
    const m_abs = m.abs();
    var z = try expNn(allocator, x2.abs(), y.abs(), m_abs);
    z.setSign(!(!z.eqZero() and !x.positive and !y.eqZero() and y.limbs[0] & 1 == 1));
    if (!z.isPositive() and !m.eqZero()) {
        // make modulus result positive
        // z == x**y mod |m| && 0 <= z < |m|
        try z.sub(m_abs, z.toConst().abs());
        return z.toConst().abs();
    }
    return z.toConst();
}

// modInverseConst returns the multiplicative inverse of g in the ring ℤ/nℤ.
// If g and n are not relatively prime, g has no multiplicative
// inverse in the ring ℤ/nℤ.  In this case, returns a zero.
fn modInverseConst(
    allocator: mem.Allocator,
    g: Const,
    n: Const,
) !Const {
    // GCD expects parameters a and b to be > 0.
    var n2 = try n.toManaged(allocator);
    defer n2.deinit();
    if (!n.positive) {
        n2.negate();
    }

    var g2 = try g.toManaged(allocator);
    defer g2.deinit();
    if (!g.positive) {
        try mod(&g2, g, n2.toConst());
    }

    var d = try Managed.init(allocator);
    defer d.deinit();
    var x = try Managed.init(allocator);
    defer x.deinit();
    try gcdManaged(&d, &x, null, g2, n2);

    // if and only if d==1, g and n are relatively prime
    if (!d.toConst().eq(big_one)) {
        return try cloneConst(allocator, big_zero);
    }

    // x and y are such that g*x + n*y = 1, therefore x is the inverse element,
    // but it may be negative, so convert to the range 0 <= z < |n|
    var z = try Managed.init(allocator);
    if (x.isPositive()) {
        try z.copy(x.toConst());
    } else {
        try z.add(x.toConst(), n2.toConst());
    }
    return z.toConst();
}

test "modInverseConst" {
    const f = struct {
        fn f(element: []const u8, modulus: []const u8) !void {
            const allocator = testing.allocator;
            var element_m = try strToManaged(allocator, element);
            defer element_m.deinit();
            var modulus_m = try strToManaged(allocator, modulus);
            defer modulus_m.deinit();
            const inverse_c = try modInverseConst(allocator, element_m.toConst(), modulus_m.toConst());
            defer allocator.free(inverse_c.limbs);
            var inverse_m = try inverse_c.toManaged(allocator);
            defer inverse_m.deinit();
            try inverse_m.mul(inverse_c, element_m.toConst());
            try mod(&inverse_m, inverse_m.toConst(), modulus_m.toConst());
            if (!inverse_m.toConst().eq(big_one)) {
                var inverse_s = try inverse_m.toString(allocator, 10, .lower);
                defer allocator.free(inverse_s);
                std.debug.print(
                    "modInverseConst({s}, {s}) * {s} % {s} = {s}, not 1\n",
                    .{ element, modulus, element, modulus, inverse_s },
                );
                return error.TestExpectedError;
            }
        }
    }.f;
    try f("1234567", "458948883992");
    try f("239487239847", "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919");
    try f("-10", "13");
    try f("10", "-13");
    try f("-17", "-13");
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
    try q.divTrunc(r, x, y);
    if (!r.isPositive()) {
        if (y.positive) {
            try r.add(r.toConst(), y);
        } else {
            try r.sub(r.toConst(), y);
        }
    }
}

/// GCD sets rma to the greatest common divisor of a and b.
/// If x or y are not nil, GCD sets their value such that rma = a*x + b*y.
///
/// a and b may be positive, zero or negative. (Before Go 1.14 both had
/// to be > 0.) Regardless of the signs of a and b, rma is always >= 0.
///
/// If a == b == 0, GCD sets rma = x = y = 0.
///
/// If a == 0 and b != 0, GCD sets rma = |b|, x = 0, y = sign(b) * 1.
///
/// If a != 0 and b == 0, GCD sets rma = |a|, x = sign(a) * 1, y = 0.
///
/// rma may alias a or b.
/// a and b may alias each other.
///
/// rma's allocator is used for temporary storage to boost multiplication performance.
pub fn gcdManaged(rma: *Managed, x: ?*Managed, y: ?*Managed, a: Managed, b: Managed) !void {
    try rma.ensureCapacity(math.min(a.len(), b.len()));
    var m = rma.toMutable();
    var limbs_buffer = std.ArrayList(Limb).init(rma.allocator);
    defer limbs_buffer.deinit();
    try gcdMutable(&m, x, y, a.toConst(), b.toConst(), &limbs_buffer);
    rma.setMetadata(m.positive, m.len);
}

test "gcdManaged" {
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
                try gcdManaged(&got_d, null, null, big_a, big_b);
                if (!got_d.eq(want_d)) {
                    var got_d_s = try got_d.toString(allocator, 10, .lower);
                    defer allocator.free(got_d_s);
                    std.debug.print("gcd d mismatch, got={s}, want={s}\n", .{ got_d_s, d });
                    return error.TestExpectedError;
                }
            }
            {
                var got_d = try Managed.init(allocator);
                defer got_d.deinit();
                var got_x = try Managed.init(allocator);
                defer got_x.deinit();
                try gcdManaged(&got_d, &got_x, null, big_a, big_b);
                if (!got_d.eq(want_d)) {
                    var got_d_s = try got_d.toString(allocator, 10, .lower);
                    defer allocator.free(got_d_s);
                    std.debug.print("gcd d mismatch, got={s}, want={s}\n", .{ got_d_s, d });
                    return error.TestExpectedError;
                }
                if (!got_x.eq(want_x)) {
                    var got_x_s = try got_d.toString(allocator, 10, .lower);
                    defer allocator.free(got_x_s);
                    std.debug.print("gcd x mismatch, got={s}, want={s}\n", .{ got_x_s, x });
                    return error.TestExpectedError;
                }
            }
            {
                var got_d = try Managed.init(allocator);
                defer got_d.deinit();
                var got_y = try Managed.init(allocator);
                defer got_y.deinit();
                try gcdManaged(&got_d, null, &got_y, big_a, big_b);
                if (!got_d.eq(want_d)) {
                    var got_d_s = try got_d.toString(allocator, 10, .lower);
                    defer allocator.free(got_d_s);
                    std.debug.print("gcd d mismatch, got={s}, want={s}\n", .{ got_d_s, d });
                    return error.TestExpectedError;
                }
                if (!got_y.eq(want_y)) {
                    var got_y_s = try got_d.toString(allocator, 10, .lower);
                    defer allocator.free(got_y_s);
                    std.debug.print("gcd y mismatch, got={s}, want={s}\n", .{ got_y_s, y });
                    return error.TestExpectedError;
                }
            }
            {
                var got_d = try Managed.init(allocator);
                defer got_d.deinit();
                var got_x = try Managed.init(allocator);
                defer got_x.deinit();
                var got_y = try Managed.init(allocator);
                defer got_y.deinit();
                try gcdManaged(&got_d, &got_x, &got_y, big_a, big_b);
                if (!got_d.eq(want_d)) {
                    var got_d_s = try got_d.toString(allocator, 10, .lower);
                    defer allocator.free(got_d_s);
                    std.debug.print("gcd d mismatch, got={s}, want={s}\n", .{ got_d_s, d });
                    return error.TestExpectedError;
                }
                if (!got_x.eq(want_x)) {
                    var got_x_s = try got_d.toString(allocator, 10, .lower);
                    defer allocator.free(got_x_s);
                    std.debug.print("gcd x mismatch, got={s}, want={s}\n", .{ got_x_s, x });
                    return error.TestExpectedError;
                }
                if (!got_y.eq(want_y)) {
                    var got_y_s = try got_d.toString(allocator, 10, .lower);
                    defer allocator.free(got_y_s);
                    std.debug.print("gcd y mismatch, got={s}, want={s}\n", .{ got_y_s, y });
                    return error.TestExpectedError;
                }
            }
        }
    }.f;

    testing.log_level = .debug;

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

fn strToManaged(allocator: mem.Allocator, value: []const u8) !Managed {
    var m = try Managed.init(allocator);
    errdefer m.deinit();
    try m.setString(10, value);
    return m;
}

/// rma may alias a or b.
/// a and b may alias each other.
/// Asserts that `rma` has enough limbs to store the result. Upper bound is
/// `math.min(normalizedLimbsLen(a), normalizedLimbsLen(b))`.
///
/// `limbs_buffer` is used for temporary storage during the operation. When this function returns,
/// it will have the same length as it had when the function was called.
pub fn gcdMutable(
    rma: *Mutable,
    x: ?*Managed,
    y: ?*Managed,
    a: Const,
    b: Const,
    limbs_buffer: *std.ArrayList(Limb),
) !void {
    if (a.eqZero() or b.eqZero()) {
        rma.copy(if (a.eqZero()) b else a);
        rma.abs();
        if (x) |xx| {
            try xx.set(if (a.eqZero()) @as(i8, 0) else blk: {
                break :blk if (a.positive) @as(i8, 1) else @as(i8, -1);
            });
        }
        if (y) |yy| {
            try yy.set(if (b.eqZero()) @as(i8, 0) else blk: {
                break :blk if (b.positive) @as(i8, 1) else @as(i8, -1);
            });
        }
        return;
    }

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

    return lehmerGcd(rma, x, y, a_copy, b_copy, limbs_buffer);
}

fn lehmerGcd(
    result: *Mutable,
    x: ?*Managed,
    y: ?*Managed,
    a_c: Const,
    b_c: Const,
    limbs_buffer: *std.ArrayList(Limb),
) !void {
    var a = try a_c.toManaged(limbs_buffer.allocator);
    defer a.deinit();
    a.abs();

    var b = try b_c.toManaged(limbs_buffer.allocator);
    defer b.deinit();
    b.abs();

    var ua = try Managed.init(limbs_buffer.allocator);
    defer ua.deinit();

    var ub = try Managed.init(limbs_buffer.allocator);
    defer ub.deinit();

    const extended = x != null or y != null;
    if (extended) {
        // ua (ub) tracks how many times input a has been accumulated into a (b).
        try ua.set(1);
        try ub.set(0);
    }

    // ensure A >= B
    if (a.toConst().order(b.toConst()) == .lt) {
        a.swap(&b);
        ua.swap(&ub);
    }

    var q = try Managed.init(limbs_buffer.allocator);
    defer q.deinit();

    var r = try Managed.init(limbs_buffer.allocator);
    defer r.deinit();

    var s = try Managed.init(limbs_buffer.allocator);
    defer s.deinit();

    var t = try Managed.init(limbs_buffer.allocator);
    defer t.deinit();

    // loop invariant a >= b
    while (normalizedLimbsLen(&b) > 1) {
        // Simulate the effect of the single-precision steps using the cosequences.
        // a = u0*a + v0*b
        // b = u1*a + v1*b
        var @"u0": Limb = undefined;
        var @"u1": Limb = undefined;
        var v0: Limb = undefined;
        var v1: Limb = undefined;
        var even: bool = undefined;
        lehmerSimulate(&a, &b, &@"u0", &@"u1", &v0, &v1, &even);

        // multiprecision Step
        if (v0 != 0) {
            // Simulate the effect of the single-precision steps using the cosequences.
            // a = u0*a + v0*b
            // b = u1*a + v1*b
            try lehmerUpdate(&a, &b, &q, &r, &s, &t, @"u0", @"u1", v0, v1, even);

            if (extended) {
                // ua = u0*ua + v0*ub
                // ub = u1*ua + v1*ub
                try lehmerUpdate(&ua, &ub, &q, &r, &s, &t, @"u0", @"u1", v0, v1, even);
            }
        } else {
            // Single-digit calculations failed to simulate any quotients.
            // Do a standard Euclidean step.
            try euclidUpdate(&a, &b, &ua, &ub, &q, &r, &s, &t, extended);
        }
    }

    if (!b.eqZero()) {
        // extended Euclidean algorithm base case if B is a single Word
        if (normalizedLimbsLen(&a) > 1) {
            // A is longer than a single Word, so one update is needed.
            try euclidUpdate(&a, &b, &ua, &ub, &q, &r, &s, &t, extended);
        }
        if (!b.eqZero()) {
            // A and B are both a single Word.
            var a_word = a.limbs[0];
            var b_word = b.limbs[0];
            if (extended) {
                var uaw: Limb = 1;
                var ubw: Limb = 0;
                var va: Limb = 0;
                var vb: Limb = 1;
                var even = true;
                while (b_word != 0) {
                    const qw = a_word / b_word;
                    const rw = a_word % b_word;
                    a_word = b_word;
                    b_word = rw;

                    const new_ubw = uaw + qw * ubw;
                    uaw = ubw;
                    ubw = new_ubw;

                    const new_vb = va + qw * vb;
                    va = vb;
                    vb = new_vb;

                    even = !even;
                }

                try t.set(uaw);
                try s.set(va);
                t.setSign(even);
                s.setSign(!even);

                try t.mul(ua.toConst(), t.toConst());
                try s.mul(ub.toConst(), s.toConst());

                try ua.add(t.toConst(), s.toConst());
            } else {
                while (b_word != 0) {
                    const new_a_word = a_word % b_word;
                    a_word = b_word;
                    b_word = new_a_word;
                }
            }
            a.limbs[0] = a_word;
        }
    }

    if (y) |yy| {
        // y = (z - a*x)/b
        var y_m = try Managed.init(limbs_buffer.allocator);
        defer y_m.deinit();
        try y_m.mul(a_c, ua.toConst());
        if (!a_c.positive) {
            y_m.negate();
        }
        try y_m.sub(a.toConst(), y_m.toConst());
        try y_m.divTrunc(&r, y_m.toConst(), b_c);
        try yy.copy(y_m.toConst());
    }
    if (x) |xx| {
        try xx.copy(ua.toConst());
        if (!a_c.positive) {
            xx.negate();
        }
    }

    result.copy(a.toConst());
}

/// Returns the normalized limbs length without a possible sequence of leading zeros.
/// Note: This returns 1 when r == 0.
fn normalizedLimbsLen(r: anytype) usize {
    return switch (@TypeOf(r)) {
        Managed, *Managed, *const Managed => r.len(),
        Mutable, *Mutable, *const Mutable => r.len,
        Const, *const Const => r.limbs.len,
        else => @panic("Unsuported type for normalizedLimbsLen"),
    };
}

/// lehmerSimulate attempts to simulate several Euclidean update steps
/// using the leading digits of A and B.  It sets u0, u1, v0, v1
/// such that A and B can be updated as:
///		A = u0*A + v0*B
///		B = u1*A + v1*B
/// Requirements: A >= B and len(B.abs) >= 2
/// Since we are calculating with full words to avoid overflow,
/// we use 'even' to track the sign of the cosequences.
/// For even iterations: u0, v1 >= 0 && u1, v0 <= 0
/// For odd  iterations: u0, v1 <= 0 && u1, v0 >= 0
fn lehmerSimulate(
    a: *Managed,
    b: *Managed,
    @"u0": *Limb,
    @"u1": *Limb,
    v0: *Limb,
    v1: *Limb,
    even: *bool,
) void {
    // initialize the digits
    var a1: Limb = undefined;
    var a2: Limb = undefined;
    var @"u2": Limb = undefined;
    var v2: Limb = undefined;

    const m = normalizedLimbsLen(b); // m >= 2
    const n = normalizedLimbsLen(a); // n >= m >= 2

    // extract the top Word of bits from A and B
    const h = nlz(a.limbs[n - 1]);
    a1 = math.shl(Limb, a.limbs[n - 1], h) | math.shr(Limb, a.limbs[n - 2], @bitSizeOf(Limb) - h);
    // B may have implicit zero words in the high bits if the lengths differ
    a2 = if (n == m)
        math.shl(Limb, b.limbs[n - 1], h) | math.shr(Limb, b.limbs[n - 2], @bitSizeOf(Limb) - h)
    else if (n == m + 1)
        math.shr(Limb, b.limbs[n - 2], @bitSizeOf(Limb) - h)
    else
        0;

    // Since we are calculating with full words to avoid overflow,
    // we use 'even' to track the sign of the cosequences.
    // For even iterations: u0, v1 >= 0 && u1, v0 <= 0
    // For odd  iterations: u0, v1 <= 0 && u1, v0 >= 0
    // The first iteration starts with k=1 (odd).
    even.* = false;
    // variables to track the cosequences
    @"u0".* = 0;
    @"u1".* = 1;
    @"u2" = 0;
    v0.* = 0;
    v1.* = 0;
    v2 = 1;

    // Calculate the quotient and cosequences using Collins' stopping condition.
    // Note that overflow of a Word is not possible when computing the remainder
    // sequence and cosequences since the cosequence size is bounded by the input size.
    // See section 4.2 of Jebelean for details.
    while (a2 >= v2 and a1 -% a2 >= v1.* + v2) {
        const q = a1 / a2;
        const r = a1 % a2;
        a1 = a2;
        a2 = r;

        const u2_new = @"u1".* + q * @"u2";
        @"u0".* = @"u1".*;
        @"u1".* = @"u2";
        @"u2" = u2_new;

        const v2_new = @"v1".* + q * @"v2";
        @"v0".* = @"v1".*;
        @"v1".* = @"v2";
        @"v2" = v2_new;

        even.* = !even.*;
    }
}

// lehmerUpdate updates the inputs a and b such that:
//		a = u0*a + v0*b
//		b = u1*a + v1*b
// where the signs of u0, u1, v0, v1 are given by even
// For even == true: u0, v1 >= 0 && u1, v0 <= 0
// For even == false: u0, v1 <= 0 && u1, v0 >= 0
// q, r, s, t are temporary variables to avoid allocations in the multiplication
fn lehmerUpdate(
    a: *Managed,
    b: *Managed,
    q: *Managed,
    r: *Managed,
    s: *Managed,
    t: *Managed,
    @"u0": Limb,
    @"u1": Limb,
    v0: Limb,
    v1: Limb,
    even: bool,
) !void {
    try t.set(@"u0");
    try s.set(v0);
    t.setSign(even);
    s.setSign(!even);

    try t.mul(a.toConst(), t.toConst());
    try s.mul(b.toConst(), s.toConst());

    try r.set(@"u1");
    try q.set(v1);
    r.setSign(!even);
    q.setSign(even);

    try r.mul(a.toConst(), r.toConst());
    try q.mul(b.toConst(), q.toConst());

    try a.add(t.toConst(), s.toConst());
    try b.add(r.toConst(), q.toConst());
}

/// euclidUpdate performs a single step of the Euclidean GCD algorithm
/// if extended is true, it also updates the cosequence ua, ub
fn euclidUpdate(
    a: *Managed,
    b: *Managed,
    ua: *Managed,
    ub: *Managed,
    q: *Managed,
    r: *Managed,
    s: *Managed,
    t: *Managed,
    extended: bool,
) !void {
    try q.divTrunc(r, a.toConst(), b.toConst());

    const tmp: Managed = a.*;
    a.* = b.*;
    b.* = r.*;
    r.* = tmp;

    if (extended) {
        // ua, ub = ub, ua - q*ub
        try t.copy(ub.toConst());
        try s.mul(ub.toConst(), q.toConst());
        try ub.sub(ua.toConst(), s.toConst());
        try ua.copy(t.toConst());
    }
}

// expNn returns x**y mod m if m != 0,
// otherwise it returns x**y.
fn expNn(
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
    const y_abs_limbs_len = normalizedLimbsLen(y_abs);
    if (x_abs.order(big_one) == .gt and y_abs_limbs_len > 1 and !m_abs.eqZero()) {
        if (m_abs.limbs[0] & 1 == 1) {
            return try expNnMontgomery(allocator, x_abs, y_abs, m_abs);
        }
        return try expNnWindowed(allocator, x_abs, y_abs, m_abs);
    }

    var v = y_abs.limbs[y_abs_limbs_len - 1]; // v > 0 because y_abs is normalized and y_abs > 0
    const shift = nlz(v) + 1;
    v = math.shl(Limb, v, shift);
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

    var i: isize = @intCast(isize, normalizedLimbsLen(y_abs)) - 2;
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

/// expNnWindowed calculates x**y mod m using a fixed, 4-bit window.
fn expNnWindowed(
    allocator: mem.Allocator,
    x_abs: Const,
    y_abs: Const,
    m_abs: Const,
) !Managed {
    // zz and r are used to avoid allocating in mul and div as otherwise
    // the arguments would alias.
    var zz = try Managed.init(allocator);
    defer zz.deinit();
    var r = try Managed.init(allocator);
    defer r.deinit();

    const n = 4;
    // powers[i] contains x^i.
    var powers = try allocator.alloc(Managed, 1 << n);
    defer {
        for (powers) |*p| p.deinit();
        allocator.free(powers);
    }

    powers[0] = try Managed.initSet(allocator, 1);
    powers[1] = try Managed.init(allocator);
    try powers[1].copy(x_abs);
    var i: usize = 2;
    while (i < powers.len) : (i += 1) {
        powers[i] = try Managed.initSet(allocator, 0);
    }
    i = 2;
    while (i < 1 << n) : (i += 2) {
        var p2 = &powers[i / 2];
        var p = &powers[i];
        var p1 = &powers[i + 1];
        try p.sqr(p2.toConst());
        try zz.divTrunc(&r, p.toConst(), m_abs);
        p.swap(&r);
        try p1.mul(p.toConst(), x_abs);
        try zz.divTrunc(&r, p1.toConst(), m_abs);
        p1.swap(&r);
    }

    var z = try Managed.initSet(allocator, 1);
    i = y_abs.limbs.len - 1;
    while (i >= 0) : (i -= 1) {
        var yi = y_abs.limbs[i];
        var j: usize = 0;
        while (j < @bitSizeOf(Limb)) : (j += n) {
            if (i != y_abs.limbs.len - 1 or j != 0) {
                // Unrolled loop for significant performance
                // gain. Use go test -bench=".*" in crypto/rsa
                // to check performance before making changes.
                try zz.sqr(z.toConst());
                zz.swap(&z);
                try zz.divTrunc(&r, z.toConst(), m_abs);
                z.swap(&r);

                try zz.sqr(z.toConst());
                zz.swap(&z);
                try zz.divTrunc(&r, z.toConst(), m_abs);
                z.swap(&r);

                try zz.sqr(z.toConst());
                zz.swap(&z);
                try zz.divTrunc(&r, z.toConst(), m_abs);
                z.swap(&r);

                try zz.sqr(z.toConst());
                zz.swap(&z);
                try zz.divTrunc(&r, z.toConst(), m_abs);
                z.swap(&r);
            }

            try zz.mul(z.toConst(), powers[yi >> (@bitSizeOf(Limb) - n)].toConst());
            zz.swap(&z);
            try zz.divTrunc(&r, z.toConst(), m_abs);
            z.swap(&r);

            yi <<= n;
        }
        if (i == 0) {
            break;
        }
    }
    z.normalize(z.len());
    return z;
}

fn expNnMontgomery(
    allocator: mem.Allocator,
    x_abs: Const,
    y_abs: Const,
    m_abs: Const,
) !Managed {
    const m_len = normalizedLimbsLen(m_abs);

    // We want the lengths of x and m to be equal.
    // It is OK if x >= m as long as normalizedLimbsLen(x_abs) == normalizedLimbsLen(m_abs).
    var x_m = if (normalizedLimbsLen(x_abs) > m_len) blk: {
        var q = try Managed.init(allocator);
        defer q.deinit();
        var r = try Managed.initCapacity(allocator, m_len);
        try q.divTrunc(&r, x_abs, m_abs);
        // Note: now r.len() <= m_len, not guaranteed ==.
        break :blk r;
    } else try x_abs.toManaged(allocator);
    defer x_m.deinit();

    if (normalizedLimbsLen(x_m) < m_len) {
        try ensureCapacityZero(&x_m, m_len);
    }

    // Ideally the precomputations would be performed outside, and reused
    // k0 = -m**-1 mod 2**_W. Algorithm from: Dumas, J.G. "On Newton–Raphson
    // Iteration for Multiplicative Inverses Modulo Prime Powers".
    var k0: Limb = 2 -% m_abs.limbs[0];
    var t: Limb = m_abs.limbs[0] -% 1;
    var i: usize = 1;
    while (i < @bitSizeOf(Limb)) : (i <<= 1) {
        t *%= t;
        k0 *%= (t + 1);
    }
    k0 = 0 -% k0;

    // RR = 2**(2*_W*len(m)) mod m
    var rr = try Managed.initSet(allocator, 1);
    defer rr.deinit();
    var zz = try Managed.init(allocator);
    defer zz.deinit();
    try zz.shiftLeft(rr, 2 * m_len * @bitSizeOf(Limb));
    var q = try Managed.init(allocator);
    defer q.deinit();
    try q.divTrunc(&rr, zz.toConst(), m_abs);
    if (normalizedLimbsLen(rr) < m_len) {
        try ensureCapacityZero(&rr, m_len);
    }

    // one = 1, with equal length to that of m
    var one = try initManagedCapacityZero(allocator, m_len);
    defer one.deinit();
    try one.set(1);

    var m_abs_m = try initManagedCapacityZero(allocator, m_len);
    defer m_abs_m.deinit();
    try m_abs_m.copy(m_abs);

    const n = 4;
    // powers[i] contains x^i
    var powers = try allocator.alloc([]Limb, 1 << n);
    defer {
        for (powers) |p| allocator.free(p);
        allocator.free(powers);
    }

    powers[0] = try allocator.alloc(Limb, 2 * m_len);
    try montgomery(
        allocator,
        &powers[0],
        one.limbs[0..m_len],
        rr.limbs[0..m_len],
        m_abs_m.limbs[0..m_len],
        k0,
        m_len,
    );
    powers[1] = try allocator.alloc(Limb, 2 * m_len);
    try montgomery(
        allocator,
        &powers[1],
        x_m.limbs[0..m_len],
        rr.limbs[0..m_len],
        m_abs_m.limbs[0..m_len],
        k0,
        m_len,
    );
    i = 2;
    while (i < 1 << n) : (i += 1) {
        powers[i] = try allocator.alloc(Limb, 2 * m_len);
        try montgomery(
            allocator,
            &powers[i],
            powers[i - 1],
            powers[1],
            m_abs_m.limbs[0..m_len],
            k0,
            m_len,
        );
    }

    // initialize z = 1 (Montgomery 1)
    var z = try allocator.alloc(Limb, m_len);
    defer allocator.free(z);
    mem.copy(Limb, z, powers[0]);

    var zz2 = try allocator.alloc(Limb, m_len);

    // same windowed exponent, but with Montgomery multiplications
    i = y_abs.limbs.len - 1;
    while (i >= 0) : (i -= 1) {
        var yi = y_abs.limbs[i];
        var j: usize = 0;
        while (j < @bitSizeOf(Limb)) : (j += n) {
            if (i != y_abs.limbs.len - 1 or j != 0) {
                try montgomery(allocator, &zz2, z, z, m_abs_m.limbs[0..m_len], k0, m_len);
                try montgomery(allocator, &z, zz2, zz2, m_abs_m.limbs[0..m_len], k0, m_len);
                try montgomery(allocator, &zz2, z, z, m_abs_m.limbs[0..m_len], k0, m_len);
                try montgomery(allocator, &z, zz2, zz2, m_abs_m.limbs[0..m_len], k0, m_len);
            }
            try montgomery(
                allocator,
                &zz2,
                z,
                powers[yi >> (@bitSizeOf(Limb) - n)],
                m_abs_m.limbs[0..m_len],
                k0,
                m_len,
            );
            mem.swap([]Limb, &z, &zz2);
            yi <<= n;
        }
        if (i == 0) {
            break;
        }
    }
    // convert to regular number
    try montgomery(allocator, &zz2, z, one.limbs[0..m_len], m_abs_m.limbs[0..m_len], k0, m_len);

    // One last reduction, just in case.
    // See golang.org/issue/13907.
    var zz2m = Managed{
        .allocator = allocator,
        .limbs = zz2,
        .metadata = zz2.len,
    };
    var o = zz2m.order(m_abs_m);
    if (o == .gt or o == .eq) {
        // Common case is m has high bit set; in that case,
        // since zz is the same length as m, there can be just
        // one multiple of m to remove. Just subtract.
        // We think that the subtract should be sufficient in general,
        // so do that unconditionally, but double-check,
        // in case our beliefs are wrong.
        // The div is not expected to be reached.
        try zz2m.sub(zz2m.toConst(), m_abs);
        o = zz2m.order(m_abs_m);
        if (o == .gt or o == .eq) {
            try zz.copy(zz2m.toConst());
            try zz2m.divTrunc(&rr, zz.toConst(), m_abs);
        }
    }

    zz2m.normalize(zz2m.len());
    return zz2m;
}

// montgomery computes z mod m = x*y*2**(-n*_W) mod m,
// assuming k = -1/m mod 2**_W.
// z is used for storing the result which is returned;
// z must not alias x, y or m.
// See Gueron, "Efficient Software Implementations of Modular Exponentiation".
// https://eprint.iacr.org/2011/239.pdf
// In the terminology of that paper, this is an "Almost Montgomery Multiplication":
// x and y are required to satisfy 0 <= z < 2**(n*_W) and then the result
// z is guaranteed to satisfy 0 <= z < 2**(n*_W), but it may not be < m.
fn montgomery(
    allocator: mem.Allocator,
    z: *[]Limb,
    x: []const Limb,
    y: []const Limb,
    m: []const Limb,
    k: Limb,
    n: usize,
) !void {
    // This code assumes x, y, m are all the same length, n.
    // (required by addMulVVW and the for loop).
    // It also assumes that x, y are already reduced mod m,
    // or else the result will not be properly reduced.
    if (!(x.len == n and y.len == n and m.len == n)) {
        std.log.err(
            "montgomery len mismatch, x={}, y={}, m={}, n={}",
            .{ x.len, y.len, m.len, n },
        );
    }
    assert(x.len == n and y.len == n and m.len == n);

    z.* = try allocator.realloc(z.*, n * 2);
    mem.set(Limb, z.*, 0);
    var c: Limb = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var d = y[i];
        var c2 = addMulVvw(z.*[i .. n + i], x, d);
        var t = z.*[i] *% k;
        var c3 = addMulVvw(z.*[i .. n + i], m, t);
        var cx = c +% c2;
        var cy = cx +% c3;
        z.*[n + i] = cy;
        c = if (cx < c2 or cy < c3) 1 else 0;
    }
    if (c != 0) {
        _ = subVv(z.*[0..n], z.*[n..], m);
    } else {
        mem.copy(Limb, z.*[0..n], z.*[n..]);
    }
    z.* = try allocator.realloc(z.*, n);
}

fn addMulVvw(z: []Limb, x: []const Limb, y: Limb) Limb {
    var c: Limb = 0;
    var i: usize = 0;
    while (i < z.len and i < x.len) : (i += 1) {
        var z0: Limb = undefined;
        const z1 = mulAddWww(x[i], y, z[i], &z0);
        z[i] = bits.add(z0, c, 0, &c);
        c += z1;
    }
    return c;
}

// z1<<_W + z0 = x*y + c
fn mulAddWww(x: Limb, y: Limb, c: Limb, z0: *Limb) Limb {
    var lo: Limb = undefined;
    const hi = bits.mul(x, y, &lo);
    var cc: Limb = undefined;
    z0.* = bits.add(lo, c, 0, &cc);
    return hi + cc;
}

// The resulting carry c is either 0 or 1.
fn subVv(z: []Limb, x: []const Limb, y: []const Limb) Limb {
    var c: Limb = 0;
    var i: usize = 0;
    while (i < z.len and i < x.len and i < y.len) : (i += 1) {
        z[i] = bits.sub(x[i], y[i], c, &c);
    }
    return c;
}

fn initManagedCapacityZero(allocator: mem.Allocator, capacity: usize) !Managed {
    var m = try Managed.initCapacity(allocator, capacity);
    clearUnusedLimbs(&m);
    return m;
}

fn ensureCapacityZero(r: *Managed, capacity: usize) !void {
    try r.ensureCapacity(capacity);
    clearUnusedLimbs(r);
}

fn clearUnusedLimbs(r: *Managed) void {
    mem.set(Limb, r.limbs[r.len()..], 0);
}

// nlz returns the number of leading zeros in x.
fn nlz(x: Limb) usize {
    return @clz(Limb, x);
}

fn cloneConst(
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
    var zero = (try Managed.initSet(allocator, 0)).toConst();
    defer allocator.free(zero.limbs);
    try testing.expectEqualSlices(Limb, &[_]Limb{0}, zero.limbs);
    try testing.expect(zero.positive);
}

test "constFromBytes" {
    testing.log_level = .debug;
    const buf = &[_]u8{ 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0xfe };
    const allocator = testing.allocator;
    var i = try constFromBytes(allocator, buf);
    defer allocator.free(i.limbs);

    var s = try i.toStringAlloc(allocator, 10, .lower);
    defer allocator.free(s);
    try testing.expectEqualStrings("335812727627494322174", s);
}

test "expConst" {
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
            // std.log.debug(
            //     "expConst test x=({}){s}, y=({}){s}, m=({}){s}",
            //     .{ x_base, x, y_base, y, m_base, m },
            // );
            const allocator = testing.allocator;
            var x_i = try initConst(allocator, x_base, x);
            defer allocator.free(x_i.limbs);
            var y_i = try initConst(allocator, y_base, y);
            defer allocator.free(y_i.limbs);
            var m_i = try initConst(allocator, m_base, m);
            defer allocator.free(m_i.limbs);
            var out_i = try initConst(allocator, out_base, out);
            defer allocator.free(out_i.limbs);

            var got = try expConst(allocator, x_i, y_i, m_i);
            defer allocator.free(got.limbs);
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
    try f(10, "17", 10, "-100", 10, "1234", 10, "865");
    try f(10, "2", 10, "-100", 10, "1234", 10, "0");

    // m == 1
    try f(10, "0", 10, "0", 10, "1", 10, "0");
    try f(10, "1", 10, "0", 10, "1", 10, "0");
    try f(10, "-10", 10, "0", 10, "1", 10, "0");
    try f(10, "1234", 10, "-1", 10, "1", 10, "0");

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
    try f(16, "8000000000000000", 10, "-1000000", 10, "6719", 10, "3663"); // 3663 = ModInverse(3199, 6719) Issue #25865

    try f(
        16,
        "ffffffffffffffffffffffffffffffff",
        16,
        "12345678123456781234567812345678123456789",
        16,
        "01112222333344445555666677778889",
        16,
        "36168FA1DB3AAE6C8CE647E137F97A",
    );

    try f(
        10,
        "2938462938472983472983659726349017249287491026512746239764525612965293865296239471239874193284792387498274256129746192347",
        10,
        "298472983472983471903246121093472394872319615612417471234712061",
        10,
        "29834729834729834729347290846729561262544958723956495615629569234729836259263598127342374289365912465901365498236492183464",
        10,
        "23537740700184054162508175125554701713153216681790245129157191391322321508055833908509185839069455749219131480588829346291",
    );

    // test case for issue 8822
    try f(
        10,
        "11001289118363089646017359372117963499250546375269047542777928006103246876688756735760905680604646624353196869572752623285140408755420374049317646428185270079555372763503115646054602867593662923894140940837479507194934267532831694565516466765025434902348314525627418515646588160955862839022051353653052947073136084780742729727874803457643848197499548297570026926927502505634297079527299004267769780768565695459945235586892627059178884998772989397505061206395455591503771677500931269477503508150175717121828518985901959919560700853226255420793148986854391552859459511723547532575574664944815966793196961286234040892865",
        16,
        "B08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
        16,
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
        10,
        "21484252197776302499639938883777710321993113097987201050501182909581359357618579566746556372589385361683610524730509041328855066514963385522570894839035884713051640171474186548713546686476761306436434146475140156284389181808675016576845833340494848283681088886584219750554408060556769486628029028720727393293111678826356480455433909233520504112074401376133077150471237549474149190242010469539006449596611576612573955754349042329130631128234637924786466585703488460540228477440853493392086251021228087076124706778899179648655221663765993962724699135217212118535057766739392069738618682722216712319320435674779146070442",
    );

    try f(
        16,
        "-1BCE04427D8032319A89E5C4136456671AC620883F2C4139E57F91307C485AD2D6204F4F87A58262652DB5DBBAC72B0613E51B835E7153BEC6068F5C8D696B74DBD18FEC316AEF73985CF0475663208EB46B4F17DD9DA55367B03323E5491A70997B90C059FB34809E6EE55BCFBD5F2F52233BFE62E6AA9E4E26A1D4C2439883D14F2633D55D8AA66A1ACD5595E778AC3A280517F1157989E70C1A437B849F1877B779CC3CDDEDE2DAA6594A6C66D181A00A5F777EE60596D8773998F6E988DEAE4CCA60E4DDCF9590543C89F74F603259FCAD71660D30294FBBE6490300F78A9D63FA660DC9417B8B9DDA28BEB3977B621B988E23D4D954F322C3540541BC649ABD504C50FADFD9F0987D58A2BF689313A285E773FF02899A6EF887D1D4A0D2",
        16,
        "B08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
        16,
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
        10,
        "21484252197776302499639938883777710321993113097987201050501182909581359357618579566746556372589385361683610524730509041328855066514963385522570894839035884713051640171474186548713546686476761306436434146475140156284389181808675016576845833340494848283681088886584219750554408060556769486628029028720727393293111678826356480455433909233520504112074401376133077150471237549474149190242010469539006449596611576612573955754349042329130631128234637924786466585703488460540228477440853493392086251021228087076124706778899179648655221663765993962724699135217212118535057766739392069738618682722216712319320435674779146070442",
    );

    // test cases for issue 13907
    try f(16, "ffffffff00000001", 16, "ffffffff00000001", 16, "ffffffff00000001", 10, "0");
    try f(16, "ffffffffffffffff00000001", 16, "ffffffffffffffff00000001", 16, "ffffffffffffffff00000001", 10, "0");
    try f(
        16,
        "ffffffffffffffffffffffff00000001",
        16,
        "ffffffffffffffffffffffff00000001",
        16,
        "ffffffffffffffffffffffff00000001",
        10,
        "0",
    );
    try f(
        16,
        "ffffffffffffffffffffffffffffffff00000001",
        16,
        "ffffffffffffffffffffffffffffffff00000001",
        16,
        "ffffffffffffffffffffffffffffffff00000001",
        10,
        "0",
    );

    try f(
        10,
        "2",
        16,
        "B08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
        16,
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", // odd
        16,
        "6AADD3E3E424D5B713FCAA8D8945B1E055166132038C57BBD2D51C833F0C5EA2007A2324CE514F8E8C2F008A2F36F44005A4039CB55830986F734C93DAF0EB4BAB54A6A8C7081864F44346E9BC6F0A3EB9F2C0146A00C6A05187D0C101E1F2D038CDB70CB5E9E05A2D188AB6CBB46286624D4415E7D4DBFAD3BCC6009D915C406EED38F468B940F41E6BEDC0430DD78E6F19A7DA3A27498A4181E24D738B0072D8F6ADB8C9809A5B033A09785814FD9919F6EF9F83EEA519BEC593855C4C10CBEEC582D4AE0792158823B0275E6AEC35242740468FAF3D5C60FD1E376362B6322F78B7ED0CA1C5BBCD2B49734A56C0967A1D01A100932C837B91D592CE08ABFF",
    );
    try f(
        10,
        "2",
        16,
        "B08FFB20760FFED58FADA86DFEF71AD72AA0FA763219618FE022C197E54708BB1191C66470250FCE8879487507CEE41381CA4D932F81C2B3F1AB20B539D50DCD",
        16,
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF72", // even
        16,
        "7858794B5897C29F4ED0B40913416AB6C48588484E6A45F2ED3E26C941D878E923575AAC434EE2750E6439A6976F9BB4D64CEDB2A53CE8D04DD48CADCDF8E46F22747C6B81C6CEA86C0D873FBF7CEF262BAAC43A522BD7F32F3CDAC52B9337C77B3DCFB3DB3EDD80476331E82F4B1DF8EFDC1220C92656DFC9197BDC1877804E28D928A2A284B8DED506CBA304435C9D0133C246C98A7D890D1DE60CBC53A024361DA83A9B8775019083D22AC6820ED7C3C68F8E801DD4EC779EE0A05C6EB682EF9840D285B838369BA7E148FA27691D524FAEAF7C6ECE2A4B99A294B9F2C241857B5B90CC8BFFCFCF18DFA7D676131D5CD3855A5A3E8EBFA0CDFADB4D198B4A",
    );
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
