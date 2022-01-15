const std = @import("std");

pub fn containsScalar(comptime T: type, slice: []const T, value: T) bool {
    for (slice) |v| {
        if (v == value) return true;
    }
    return false;
}

pub fn containsScalarFn(
    comptime T: type,
    slice: []const T,
    context: anytype,
    predicate: fn (@TypeOf(context), T) bool,
) bool {
    for (slice) |v| {
        if (predicate(context, v)) return true;
    }
    return false;
}

const testing = std.testing;

test "containsScalar" {
    try testing.expect(containsScalar(u8, &[_]u8{ 0, 1 }, 1));
    try testing.expect(!containsScalar(u8, &[_]u8{ 0, 2 }, 1));
    try testing.expect(!containsScalar(u8, &[_]u8{}, 1));
}

test "containsScalarFn" {
    var a2: u8 = 1;
    const Context = struct {
        const Self = @This();
        a: u8,

        fn f(self: *const Self, v: u8) bool {
            return v == self.a;
        }
    };
    const ctx = Context{ .a = a2 };
    try testing.expect(containsScalarFn(u8, &[_]u8{ 0, 1 }, &ctx, Context.f));
    try testing.expect(!containsScalarFn(u8, &[_]u8{ 0, 2 }, &ctx, Context.f));
    try testing.expect(!containsScalarFn(u8, &[_]u8{}, &ctx, Context.f));
}