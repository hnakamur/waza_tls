const std = @import("std");
const mem = std.mem;

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

pub fn dupeStringList(
    allocator: mem.Allocator,
    string_list: []const []const u8,
) ![]const []const u8 {
    var ret_list = try allocator.alloc([]const u8, string_list.len);
    var n: usize = 0;
    errdefer {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            allocator.free(ret_list[i]);
        }
        allocator.free(ret_list);
    }
    for (string_list) |s, i| {
        ret_list[i] = try allocator.dupe(u8, s);
        n += 1;
    }
    return ret_list;
}

pub fn deinitArrayListAndElems(
    comptime T: type,
    list: *std.ArrayListUnmanaged(T),
    allocator: mem.Allocator,
) void {
    for (list.items) |*elem| elem.deinit(allocator);
    list.deinit(allocator);
}

pub fn freeElemsAndDeinitArrayList(
    comptime T: type,
    list: *std.ArrayListUnmanaged(T),
    allocator: mem.Allocator,
) void {
    for (list.items) |elem| allocator.free(elem);
    list.deinit(allocator);
}

pub fn freeElemsAndFreeSlice(
    comptime T: type,
    slice: []const T,
    allocator: mem.Allocator,
) void {
    if (slice.len > 0) {
        for (slice) |elem| allocator.free(elem);
        allocator.free(slice);
    }
}

pub fn deinitSliceAndElems(
    comptime T: type,
    slice: []T,
    allocator: mem.Allocator,
) void {
    for (slice) |*elem| elem.deinit(allocator);
    if (slice.len > 0) allocator.free(slice);
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
