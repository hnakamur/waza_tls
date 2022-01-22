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

// expConst returns x**y mod |m| (i.e. the sign of m is ignored).
// If m == 0, returns x**y unless y <= 0 then returns 1. If m != 0, y < 0,
// and x and m are not relatively prime, returns error.BadBigIntInputs.
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
    if (!y.positive) {
        if (m.eqZero()) {
            return try cloneConst(allocator, big_one);
        }
        // for y < 0: x**y mod m == (x**(-1))**|y| mod m
        @panic("not implemented yet");
    }
    const m_abs = m.abs();
    var z = try expNn(allocator, x2.abs(), y.abs(), m_abs);
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
        return big_zero;
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
                std.debug.print(
                    "modInverseConst({}, {}) * {} % {} = {}, not 1",
                    .{ element_m, modulus_m, element_m, modulus_m, inverse_m },
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
    std.log.debug("gcdManaged start a={}, b={}", .{ a, b });
    try rma.ensureCapacity(math.min(a.len(), b.len()));
    var m = rma.toMutable();
    var limbs_buffer = std.ArrayList(Limb).init(rma.allocator);
    defer limbs_buffer.deinit();
    // var x_mut_ptr = if (x) |xx| &xx.toMutable() else null;
    // var y_mut_ptr = if (y) |yy| &yy.toMutable() else null;
    // var x_mut: Mutable = undefined;
    // var y_mut: Mutable = undefined;
    // var x_mut_ptr = if (x) |_| &x_mut else null;
    // var y_mut_ptr = if (y) |_| &y_mut else null;
    try gcdMutable(&m, x, y, a.toConst(), b.toConst(), &limbs_buffer);
    rma.setMetadata(m.positive, m.len);
    // if (x) |xx| xx.setMetadata(x_mut_ptr.?.positive, x_mut_ptr.?.len);
    // if (y) |yy| {
    //     // yy.setMetadata(y_mut_ptr.?.positive, y_mut_ptr.?.len);
    //     yy.* = y_mut_ptr.?.toManaged(rma.allocator);
    //     std.log.debug("gcdManaged set yy to {}", .{yy});
    // }
    // if (x) |xx| xx.* = x_mut.toManaged(rma.allocator);
    // if (y) |yy| yy.* = y_mut.toManaged(rma.allocator);
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
                    std.debug.print("gcd d mismatch, got={}, want={}\n", .{ got_d, want_d });
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
                    std.debug.print("gcd d mismatch, got={}, want={}\n", .{ got_d, want_d });
                    return error.TestExpectedError;
                }
                if (!got_x.eq(want_x)) {
                    std.debug.print("gcd x mismatch, got={}, want={}\n", .{ got_x, want_x });
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
                    std.debug.print("gcd d mismatch, got={}, want={}\n", .{ got_d, want_d });
                    return error.TestExpectedError;
                }
                if (!got_y.eq(want_y)) {
                    std.debug.print("gcd y mismatch, got={}, want={}\n", .{ got_y, want_y });
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
                    std.debug.print("gcd d mismatch, got={}, want={}\n", .{ got_d, want_d });
                    return error.TestExpectedError;
                }
                if (!got_x.eq(want_x)) {
                    std.debug.print("gcd x mismatch, got={}, want={}\n", .{ got_x, want_x });
                    return error.TestExpectedError;
                }
                if (!got_y.eq(want_y)) {
                    std.debug.print("gcd y mismatch, got={}, want={}\n", .{ got_y, want_y });
                    std.debug.print(
                        "gcd y mismatch, got.limbs={any}, got.metadata={x}, want.limbs={any}, want.metadata={x}\n",
                        .{ got_y.limbs, got_y.metadata, want_y.limbs, want_y.metadata },
                    );
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
        // try yy.toManaged(limbs_buffer.allocator).copy(y_m.toConst());
        // yy.* = y_m.toMutable();
        std.log.debug("lehmerGcd set yy to {}", .{yy.*});
    }
    if (x) |xx| {
        try xx.copy(ua.toConst());
        // try xx.toManaged(limbs_buffer.allocator).copy(ua.toConst());
        // var x_m = try ua.clone();
        // defer x_m.deinit();
        if (!a_c.positive) {
            xx.negate();
            // x_m.negate();
        }
        // xx.copy(x_m.toConst());
        // xx.* = x_m.toMutable();
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
            @panic("not implemented yet#2");
        }
        @panic("not implemented yet#3");
    }

    var v = y_abs.limbs[y_abs_limbs_len - 1]; // v > 0 because y_abs is normalized and y_abs > 0
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

            var got = try expConst(allocator, x_i, y_i, m_i);
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

test "swap3" {
    var a: usize = 1;
    var b: usize = 2;
    var c: usize = 3;

    const tmp = a;
    a = b;
    b = c;
    c = tmp;
    // std.mem.swap(usize, &a, &b);
    // std.mem.swap(usize, &b, &c);

    try testing.expectEqual(@as(usize, 2), a);
    try testing.expectEqual(@as(usize, 3), b);
    try testing.expectEqual(@as(usize, 1), c);
}

test "subLimbsOverflow" {
    const a: Limb = 2;
    const b: Limb = 3;
    const got = a -% b;
    const want: Limb = 18446744073709551615;
    try testing.expectEqual(want, got);
}
