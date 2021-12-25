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
