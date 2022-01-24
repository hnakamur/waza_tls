const std = @import("std");

pub const Case = enum { lower, upper };

fn formatSliceHexEscapeImpl(comptime case: Case) type {
    const charset = "0123456789" ++ if (case == .upper) "ABCDEF" else "abcdef";

    return struct {
        pub fn f(
            bytes: []const u8,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            var buf: [4]u8 = undefined;

            buf[0] = '\\';
            buf[1] = 'x';

            for (bytes) |c| {
                buf[2] = charset[c >> 4];
                buf[3] = charset[c & 15];
                try writer.writeAll(&buf);
            }
        }
    };
}

const formatSliceHexEscapeLower = formatSliceHexEscapeImpl(.lower).f;
const formatSliceHexEscapeUpper = formatSliceHexEscapeImpl(.upper).f;

/// Return a Formatter for a []const u8 where every byte is formatted as a pair
/// of escaped lowercase hexadecimal digits.
pub fn fmtSliceHexEscapeLower(bytes: []const u8) std.fmt.Formatter(formatSliceHexEscapeLower) {
    return .{ .data = bytes };
}

/// Return a Formatter for a []const u8 where every byte is formatted as pair
/// of escaped uppercase hexadecimal digits.
pub fn fmtSliceHexEscapeUpper(bytes: []const u8) std.fmt.Formatter(formatSliceHexEscapeUpper) {
    return .{ .data = bytes };
}

pub fn formatStringSlice(
    slice: []const []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    _ = try writer.write("{");
    for (slice) |s, i| {
        if (i > 0) {
            _ = try writer.write(", ");
        }
        try std.fmt.format(writer, "\"{s}\"", .{s});
    }
    _ = try writer.write(" }");
}

pub fn formatStringSliceField(
    name: []const u8,
    slice: []const []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    try std.fmt.format(writer, "{s} = {{ ", .{name});
    for (slice) |s, i| {
        if (i > 0) {
            _ = try writer.write(", ");
        }
        try std.fmt.format(writer, "\"{s}\"", .{s});
    }
    _ = try writer.write(" }");
}

pub fn formatStringField(
    name: []const u8,
    s: []const u8,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    try std.fmt.format(writer, "{s} = \"{s}\"", .{ name, s });
}

const testing = std.testing;

test "fmtSliceHexEscapeLower" {
    var buf = [_]u8{0} ** 8;
    var fbs = std.io.fixedBufferStream(&buf);
    try std.fmt.format(fbs.writer(), "{}", .{fmtSliceHexEscapeLower("\x12\xab")});
    try testing.expectEqualSlices(u8, "\\x12\\xab", fbs.getWritten());
}

test "fmtSliceHexEscapeUpper" {
    var buf = [_]u8{0} ** 8;
    var fbs = std.io.fixedBufferStream(&buf);
    try std.fmt.format(fbs.writer(), "{}", .{fmtSliceHexEscapeUpper("\x12\xab")});
    try testing.expectEqualSlices(u8, "\\x12\\xAB", fbs.getWritten());
}
