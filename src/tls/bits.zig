// --- Add with carry ---

/// add returns the sum with carry of x, y and carry: sum = x + y + carry.
/// The carry input must be 0 or 1; otherwise the behavior is undefined.
/// The carryOut output is guaranteed to be 0 or 1.
///
/// This function's execution time does not depend on the inputs.
pub fn add(x: usize, y: usize, carry: usize, carry_out: *usize) usize {
    return switch (@bitSizeOf(usize)) {
        32 => add32(x, y, carry, carry_out),
        64 => add64(x, y, carry, carry_out),
        else => @panic("unsupported bit sizeof usize"),
    };
}

/// add32 returns the sum with carry of x, y and carry: sum = x + y + carry.
/// The carry input must be 0 or 1; otherwise the behavior is undefined.
/// The carryOut output is guaranteed to be 0 or 1.
///
/// This function's execution time does not depend on the inputs.
fn add32(x: u32, y: u32, carry: u32, carry_out: *u32) u32 {
    const sum64 = @as(u64, x) + @as(u64, y) + @as(u64, carry);
    carry_out.* = @intCast(u32, sum64 >> 32);
    return @truncate(u32, sum64);
}

/// add64 returns the sum with carry of x, y and carry: sum = x + y + carry.
/// The carry input must be 0 or 1; otherwise the behavior is undefined.
/// The carryOut output is guaranteed to be 0 or 1.
///
/// This function's execution time does not depend on the inputs.
fn add64(x: u64, y: u64, carry: u64, carry_out: *u64) u64 {
    const sum = x +% y +% carry;
    // The sum will overflow if both top bits are set (x & y) or if one of them
    // is (x | y), and a carry from the lower place happened. If such a carry
    // happens, the top bit will be 1 + 0 + 1 = 0 (&^ sum).
    carry_out.* = ((x & y) | ((x | y) & ~sum)) >> 63;
    return sum;
}

// --- Subtract with borrow ---

/// sub returns the difference of x, y and borrow: diff = x - y - borrow.
/// The borrow input must be 0 or 1; otherwise the behavior is undefined.
/// The borrowOut output is guaranteed to be 0 or 1.
///
/// This function's execution time does not depend on the inputs.
pub fn sub(x: usize, y: usize, borrow: usize, borrow_out: *usize) usize {
    return switch (@bitSizeOf(usize)) {
        32 => sub32(x, y, borrow, borrow_out),
        64 => sub64(x, y, borrow, borrow_out),
        else => @panic("unsupported bit sizeof usize"),
    };
}

/// Sub32 returns the difference of x, y and borrow, diff = x - y - borrow.
/// The borrow input must be 0 or 1; otherwise the behavior is undefined.
/// The borrowOut output is guaranteed to be 0 or 1.
///
/// This function's execution time does not depend on the inputs.
fn sub32(x: u32, y: u32, borrow: u32, borrow_out: *u32) u32 {
    const diff = x -% y -% borrow;
    // The difference will underflow if the top bit of x is not set and the top
    // bit of y is set (~x & y) or if they are the same (~(x ^ y)) and a borrow
    // from the lower place happens. If that borrow happens, the result will be
    // 1 - 1 - 1 = 0 - 0 - 1 = 1 (& diff).
    borrow_out.* = ((~x & y) | (~(x ^ y) & diff)) >> 31;
    return diff;
}

/// sub64 returns the difference of x, y and borrow: diff = x - y - borrow.
/// The borrow input must be 0 or 1; otherwise the behavior is undefined.
/// The borrowOut output is guaranteed to be 0 or 1.
///
/// This function's execution time does not depend on the inputs.
fn sub64(x: u64, y: u64, borrow: u64, borrow_out: *u64) u64 {
    const diff = x -% y -% borrow;
    // See sub32 for the bit logic.
    borrow_out.* = ((~x & y) | (~(x ^ y) & diff)) >> 63;
    return diff;
}

// --- Full-width multiply ---

/// mul returns the full-width product of x and y: (hi, lo) = x * y
/// with the product bits' upper half returned in hi and the lower
/// half returned in lo.
///
/// This function's execution time does not depend on the inputs.
pub fn mul(x: usize, y: usize, lo: *usize) usize {
    return switch (@bitSizeOf(usize)) {
        32 => mul32(x, y, lo),
        64 => mul64(x, y, lo),
        else => @panic("unsupported bit sizeof usize"),
    };
}

/// mul32 returns the 64-bit product of x and y: (hi, lo) = x * y
/// with the product bits' upper half returned in hi and the lower
/// half returned in lo.
///
/// This function's execution time does not depend on the inputs.
pub fn mul32(x: u32, y: u32, lo: *u32) u32 {
    var tmp: u64 = @as(u64, x) * @as(u64, y);
    lo.* = @truncate(u32, tmp);
    return @intCast(u32, tmp >> 32);
}

/// mul64 returns the 128-bit product of x and y: (hi, lo) = x * y
/// with the product bits' upper half returned in hi and the lower
/// half returned in lo.
///
/// This function's execution time does not depend on the inputs.
pub fn mul64(x: u64, y: u64, lo: *u64) u64 {
    // We use u128 here unlike Go's version of bits.Mul64.
    var tmp: u128 = @as(u128, x) * @as(u128, y);
    lo.* = @truncate(u64, tmp);
    return @intCast(u64, tmp >> 64);
}

const std = @import("std");
const math = std.math;
const testing = std.testing;

test "bits.addsub" {
    const runTest = struct {
        fn runTest(
            msg: []const u8,
            case_id: usize,
            f: fn (usize, usize, usize, *usize) usize,
            x: usize,
            y: usize,
            c: usize,
            z: usize,
            cout: usize,
        ) !void {
            var cout1: usize = undefined;
            const z1 = f(x, y, c, &cout1);
            if (z1 != z or cout1 != cout) {
                std.debug.print(
                    "{s} #{}: got z:cout={x}:{x}; want {x}:{x}\n",
                    .{ msg, case_id, z1, cout1, z, cout },
                );
                return error.TestExpectedError;
            }
        }
    }.runTest;

    const m = math.maxInt(usize);
    for ([_]struct { x: usize, y: usize, c: usize, z: usize, cout: usize }{
        .{ .x = 0, .y = 0, .c = 0, .z = 0, .cout = 0 },
        .{ .x = 0, .y = 1, .c = 0, .z = 1, .cout = 0 },
        .{ .x = 0, .y = 0, .c = 1, .z = 1, .cout = 0 },
        .{ .x = 0, .y = 1, .c = 1, .z = 2, .cout = 0 },
        .{ .x = 12345, .y = 67890, .c = 0, .z = 80235, .cout = 0 },
        .{ .x = 12345, .y = 67890, .c = 1, .z = 80236, .cout = 0 },
        .{ .x = m, .y = 1, .c = 0, .z = 0, .cout = 1 },
        .{ .x = m, .y = 0, .c = 1, .z = 0, .cout = 1 },
        .{ .x = m, .y = 1, .c = 1, .z = 1, .cout = 1 },
        .{ .x = m, .y = m, .c = 0, .z = m - 1, .cout = 1 },
        .{ .x = m, .y = m, .c = 1, .z = m, .cout = 1 },
    }) |a, i| {
        try runTest("add", i, add, a.x, a.y, a.c, a.z, a.cout);
        try runTest("add symmetric", i, add, a.y, a.x, a.c, a.z, a.cout);
        try runTest("sub", i, sub, a.z, a.x, a.c, a.y, a.cout);
        try runTest("sub symmetric", i, sub, a.z, a.y, a.c, a.x, a.cout);
    }
}

test "bits.addsub32" {
    const runTest = struct {
        fn runTest(
            msg: []const u8,
            case_id: usize,
            f: fn (u32, u32, u32, *u32) u32,
            x: u32,
            y: u32,
            c: u32,
            z: u32,
            cout: u32,
        ) !void {
            var cout1: u32 = undefined;
            const z1 = f(x, y, c, &cout1);
            if (z1 != z or cout1 != cout) {
                std.debug.print(
                    "{s} #{}: got z:cout={x}:{x}; want {x}:{x}\n",
                    .{ msg, case_id, z1, cout1, z, cout },
                );
                return error.TestExpectedError;
            }
        }
    }.runTest;

    const m32 = math.maxInt(u32);
    for ([_]struct { x: u32, y: u32, c: u32, z: u32, cout: u32 }{
        .{ .x = 0, .y = 0, .c = 0, .z = 0, .cout = 0 },
        .{ .x = 0, .y = 1, .c = 0, .z = 1, .cout = 0 },
        .{ .x = 0, .y = 0, .c = 1, .z = 1, .cout = 0 },
        .{ .x = 0, .y = 1, .c = 1, .z = 2, .cout = 0 },
        .{ .x = 12345, .y = 67890, .c = 0, .z = 80235, .cout = 0 },
        .{ .x = 12345, .y = 67890, .c = 1, .z = 80236, .cout = 0 },
        .{ .x = m32, .y = 1, .c = 0, .z = 0, .cout = 1 },
        .{ .x = m32, .y = 0, .c = 1, .z = 0, .cout = 1 },
        .{ .x = m32, .y = 1, .c = 1, .z = 1, .cout = 1 },
        .{ .x = m32, .y = m32, .c = 0, .z = m32 - 1, .cout = 1 },
        .{ .x = m32, .y = m32, .c = 1, .z = m32, .cout = 1 },
    }) |a, i| {
        try runTest("add32", i, add32, a.x, a.y, a.c, a.z, a.cout);
        try runTest("add32 symmetric", i, add32, a.y, a.x, a.c, a.z, a.cout);
        try runTest("sub32", i, sub32, a.z, a.x, a.c, a.y, a.cout);
        try runTest("sub32 symmetric", i, sub32, a.z, a.y, a.c, a.x, a.cout);
    }
}

test "bits.addsub64" {
    const runTest = struct {
        fn runTest(
            msg: []const u8,
            case_id: usize,
            f: fn (u64, u64, u64, *u64) u64,
            x: u64,
            y: u64,
            c: u64,
            z: u64,
            cout: u64,
        ) !void {
            var cout1: u64 = undefined;
            const z1 = f(x, y, c, &cout1);
            if (z1 != z or cout1 != cout) {
                std.debug.print(
                    "{s} #{}: got z:cout={x}:{x}; want {x}:{x}\n",
                    .{ msg, case_id, z1, cout1, z, cout },
                );
                return error.TestExpectedError;
            }
        }
    }.runTest;

    const m64 = math.maxInt(u64);
    for ([_]struct { x: u64, y: u64, c: u64, z: u64, cout: u64 }{
        .{ .x = 0, .y = 0, .c = 0, .z = 0, .cout = 0 },
        .{ .x = 0, .y = 1, .c = 0, .z = 1, .cout = 0 },
        .{ .x = 0, .y = 0, .c = 1, .z = 1, .cout = 0 },
        .{ .x = 0, .y = 1, .c = 1, .z = 2, .cout = 0 },
        .{ .x = 12345, .y = 67890, .c = 0, .z = 80235, .cout = 0 },
        .{ .x = 12345, .y = 67890, .c = 1, .z = 80236, .cout = 0 },
        .{ .x = m64, .y = 1, .c = 0, .z = 0, .cout = 1 },
        .{ .x = m64, .y = 0, .c = 1, .z = 0, .cout = 1 },
        .{ .x = m64, .y = 1, .c = 1, .z = 1, .cout = 1 },
        .{ .x = m64, .y = m64, .c = 0, .z = m64 - 1, .cout = 1 },
        .{ .x = m64, .y = m64, .c = 1, .z = m64, .cout = 1 },
    }) |a, i| {
        try runTest("add64", i, add64, a.x, a.y, a.c, a.z, a.cout);
        try runTest("add64 symmetric", i, add64, a.y, a.x, a.c, a.z, a.cout);
        try runTest("sub64", i, sub64, a.z, a.x, a.c, a.y, a.cout);
        try runTest("sub64 symmetric", i, sub64, a.z, a.y, a.c, a.x, a.cout);
    }
}

test "bits.mul" {
    const T = struct {
        fn testMul(
            msg: []const u8,
            case_id: usize,
            f: fn (usize, usize, *usize) usize,
            x: usize,
            y: usize,
            hi: usize,
            lo: usize,
        ) !void {
            var lo1: usize = undefined;
            const hi1 = f(x, y, &lo1);
            if (hi1 != hi or lo1 != lo) {
                std.debug.print(
                    "{s} #{}: got hi:lo={x}:{x}; want {x}:{x}\n",
                    .{ msg, case_id, hi1, lo1, hi, lo },
                );
                return error.TestExpectedError;
            }
        }
    };

    const testMul = T.testMul;

    const m = math.maxInt(usize);
    for ([_]struct { x: usize, y: usize, hi: usize, lo: usize, r: usize }{
        .{ .x = 1 << (@bitSizeOf(usize) - 1), .y = 2, .hi = 1, .lo = 0, .r = 1 },
        .{ .x = m, .y = m, .hi = m - 1, .lo = 1, .r = 42 },
    }) |a, i| {
        try testMul("mul", i, mul, a.x, a.y, a.hi, a.lo);
        try testMul("mul symmetric", i, mul, a.y, a.x, a.hi, a.lo);
    }
}

test "bits.mul32" {
    const T = struct {
        fn testMul(
            msg: []const u8,
            case_id: usize,
            f: fn (u32, u32, *u32) u32,
            x: u32,
            y: u32,
            hi: u32,
            lo: u32,
        ) !void {
            var lo1: u32 = undefined;
            const hi1 = f(x, y, &lo1);
            if (hi1 != hi or lo1 != lo) {
                std.debug.print(
                    "{s} #{}: got hi:lo={x}:{x}; want {x}:{x}\n",
                    .{ msg, case_id, hi1, lo1, hi, lo },
                );
                return error.TestExpectedError;
            }
        }
    };

    const testMul = T.testMul;

    const m32 = math.maxInt(u32);
    for ([_]struct { x: u32, y: u32, hi: u32, lo: u32, r: u32 }{
        .{ .x = 1 << 31, .y = 2, .hi = 1, .lo = 0, .r = 1 },
        .{ .x = 0xc47dfa8c, .y = 50911, .hi = 0x98a4, .lo = 0x998587f4, .r = 13 },
        .{ .x = m32, .y = m32, .hi = m32 - 1, .lo = 1, .r = 42 },
    }) |a, i| {
        try testMul("mul32", i, mul32, a.x, a.y, a.hi, a.lo);
        try testMul("mul32 symmetric", i, mul32, a.y, a.x, a.hi, a.lo);
    }
}

test "bits.mul64" {
    const T = struct {
        fn testMul(
            msg: []const u8,
            case_id: usize,
            f: fn (u64, u64, *u64) u64,
            x: u64,
            y: u64,
            hi: u64,
            lo: u64,
        ) !void {
            var lo1: u64 = undefined;
            const hi1 = f(x, y, &lo1);
            if (hi1 != hi or lo1 != lo) {
                std.debug.print(
                    "{s} #{}: got hi:lo={x}:{x}; want {x}:{x}\n",
                    .{ msg, case_id, hi1, lo1, hi, lo },
                );
                return error.TestExpectedError;
            }
        }
    };

    const testMul = T.testMul;

    const m64 = math.maxInt(u64);
    for ([_]struct { x: u64, y: u64, hi: u64, lo: u64, r: u64 }{
        .{ .x = 1 << 63, .y = 2, .hi = 1, .lo = 0, .r = 1 },
        .{
            .x = 0x3626229738a3b9,
            .y = 0xd8988a9f1cc4a61,
            .hi = 0x2dd0712657fe8,
            .lo = 0x9dd6a3364c358319,
            .r = 13,
        },
        .{ .x = m64, .y = m64, .hi = m64 - 1, .lo = 1, .r = 42 },
    }) |a, i| {
        try testMul("mul64", i, mul64, a.x, a.y, a.hi, a.lo);
        try testMul("mul64 symmetric", i, mul64, a.y, a.x, a.hi, a.lo);
    }
}
