const std = @import("std");
const math = std.math;
const mem = std.mem;

const big_zero = math.big.int.Const{ .limbs = &[_]math.big.Limb{0}, .positive = true };
const big_one = math.big.int.Const{ .limbs = &[_]math.big.Limb{1}, .positive = true };

// setBytes interprets buf as the bytes of a big-endian unsigned
// integer, sets z to that value, and returns z.
pub fn bigIntConstFromBytes(allocator: mem.Allocator, buf: []const u8) !math.big.int.Const {
    const Limb = math.big.Limb;
    var limbs = try allocator.alloc(Limb, try math.divCeil(usize, buf.len, @sizeOf(Limb)));
    errdefer allocator.free(limbs);

    var limbs_bytes = @ptrCast([*]u8, limbs.ptr);
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        // Note:  note bytes in zig's big integer are little-endian ordered.
        limbs_bytes[i] = buf[buf.len - 1 - i];
    }
    mem.set(u8, limbs_bytes[i .. limbs.len * @sizeOf(Limb)], 0);

    return math.big.int.Const{ .limbs = limbs, .positive = true };
}

// bigIntConstExp returns x**y mod |m| (i.e. the sign of m is ignored).
// If m == 0, returns x**y unless y <= 0 then returns 1. If m != 0, y < 0,
// and x and m are not relatively prime, returns error.BadBigIntInputs.
//
// Modular exponentiation of inputs of a particular size is not a
// cryptographically constant-time operation.
pub fn bigIntConstExp(
    allocator: mem.Allocator,
    x: math.big.int.Const,
    y: math.big.int.Const,
    m: math.big.int.Const,
) !math.big.int.Const {
    // See Knuth, volume 2, section 4.6.3.
    var x2 = x;
    if (!y.positive) {
        if (m.eqZero()) {
            return try bigIntConstClone(allocator, big_one);
        }
        @panic("not implemented yet");
    }
    const m_abs = m.abs();
    var z = try bigIntConstExpNN(allocator, x2, y, m_abs);
    if (!z.positive and !m.eqZero()) {
        // make modulus result positive
        var z2 = try z.toManaged(allocator);
        try z2.sub(m_abs, z);
        return z2.toConst();
    }
    return z;
}

// bigIntConstExpNN returns x**y mod m if m != 0,
// otherwise it returns x**y.
fn bigIntConstExpNN(
    allocator: mem.Allocator,
    x: math.big.int.Const,
    y: math.big.int.Const,
    m: math.big.int.Const,
) !math.big.int.Const {
    // x**y mod 1 == 0
    if (m.eq(big_one)) {
        return try bigIntConstClone(allocator, big_zero);
    }
    // m == 0 || m > 1

    // x**0 == 1
    if (y.eq(big_zero)) {
        return try bigIntConstClone(allocator, big_one);
    }
    // y > 0

    // x**1 mod m == x mod m
    if (y.eq(big_one) and !m.eqZero()) {
        var q = try math.big.int.Managed.init(allocator);
        defer q.deinit();
        var r = try math.big.int.Managed.init(allocator);
        errdefer r.deinit();
        try math.big.int.Managed.divFloor(&q, &r, x, m);
        return r.toConst();
    }
    // y > 1

    // if (!m.eqZero()) {

    // }
    _ = x;
    @panic("not implemented yet");
}

fn bigIntConstClone(
    allocator: mem.Allocator,
    x: math.big.int.Const,
) !math.big.int.Const {
    return math.big.int.Const{
        .limbs = try allocator.dupe(math.big.Limb, x.limbs),
        .positive = x.positive,
    };
}

const testing = std.testing;

test "std.math.big.int.Const const" {
    try testing.expectEqual(@as(u64, 0), try big_zero.to(u64));
    try testing.expectEqual(@as(u64, 1), try big_one.to(u64));
}

test "std.math.big.int.Const zero" {
    const allocator = testing.allocator;
    var zero = (try std.math.big.int.Managed.initSet(allocator, 0)).toConst();
    defer allocator.free(zero.limbs);
    try testing.expectEqualSlices(std.math.big.Limb, &[_]std.math.big.Limb{0}, zero.limbs);
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
            if (!got.eq(out_i)) {
                var got_s = try got.toStringAlloc(allocator, 10, .lower);
                defer allocator.free(got_s);
                var want_s = try out_i.toStringAlloc(allocator, 10, .lower);
                defer allocator.free(want_s);
                std.debug.print("result mismatch, got={s}, want={s}\n", .{ got_s, want_s });
                return error.TestExpectedError;
            }
        }

        fn initConst(allocator: mem.Allocator, base: u8, value: []const u8) !math.big.int.Const {
            var m = try math.big.int.Managed.init(allocator);
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
    // try f(10, "5", 10, "1", 10, "0", 10, "5");
}
