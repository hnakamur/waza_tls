const std = @import("std");
const fmt = std.fmt;
const math = std.math;
const FieldIterator = @import("field_iterator.zig").FieldIterator;

pub const Fields = struct {
    fields: []const u8,

    // caller owns memory for fields.
    pub fn init(fields: []const u8) Fields {
        return .{ .fields = fields };
    }

    pub const ContentLengthError = error{Inconsistent} || DecimalDigitsParseError;

    pub fn getContentLength(self: *const Fields) ContentLengthError!?u64 {
        var result: ?u64 = null;
        var it = FieldIterator.init(self.fields);
        while (it.nextForName("content-length")) |f| {
            const val = try parseDecimalDigits(f.value());
            if (result) |res| {
                if (val != result) {
                    return error.Inconsistent;
                }
            } else {
                result = val;
            }
        }
        return result;
    }
};

const DecimalDigitsParseError = error{
    InvalidCharacter,
    Overflow,
};

fn parseDecimalDigits(digits: []const u8) DecimalDigitsParseError!u64 {
    var result: u64 = 0;
    for (digits) |c| {
        const d = try fmt.charToDigit(c, 10);
        result = try math.add(u64, try math.mul(u64, result, 10), d);
    }
    return result;
}

const testing = std.testing;

test "parseDecimalDigits" {
    try testing.expectEqual(@as(u64, 123), try parseDecimalDigits("123"));
    try testing.expectEqual(@as(u64, 123), try parseDecimalDigits("000000123"));

    var buf = [_]u8{0} ** 21;
    const len = fmt.formatIntBuf(&buf, @as(u128, math.maxInt(u64)) + 1, 10, false, .{});
    const digits = buf[0..len];
    try testing.expectEqualStrings("18446744073709551616", digits);
    try testing.expectError(error.Overflow, parseDecimalDigits(digits));

    try testing.expectError(error.InvalidCharacter, parseDecimalDigits("123, 123"));
    try testing.expectError(error.InvalidCharacter, parseDecimalDigits("1_234"));
    try testing.expectError(error.InvalidCharacter, parseDecimalDigits("+234"));
    try testing.expectError(error.InvalidCharacter, parseDecimalDigits("-234"));
    try testing.expectError(error.InvalidCharacter, parseDecimalDigits("234."));
}

test "getContentLength" {
    // success cases

    try testing.expectEqual(
        @as(Fields.ContentLengthError!?u64, 123),
        Fields.init("content-length: 123\r\n\r\n").getContentLength(),
    );
    try testing.expectEqual(
        @as(Fields.ContentLengthError!?u64, 123),
        Fields.init("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
            "content-length: 123\r\n" ++
            "content-type: text/plain\r\n" ++
            "\r\n").getContentLength(),
    );
    try testing.expectEqual(
        @as(Fields.ContentLengthError!?u64, 123),
        Fields.init("content-length: 123\r\ncontent-length: 123\r\n\r\n").getContentLength(),
    );

    try testing.expectEqual(
        @as(Fields.ContentLengthError!?u64, null),
        Fields.init("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n\r\n").getContentLength(),
    );

    // error cases

    try testing.expectError(
        error.Inconsistent,
        Fields.init("content-length: 123\r\ncontent-length: 124\r\n\r\n").getContentLength(),
    );
    try testing.expectError(
        error.InvalidCharacter,
        Fields.init("content-length: 123, 123\r\n\r\n").getContentLength(),
    );
    try testing.expectError(
        error.Overflow,
        Fields.init("content-length: 18446744073709551616\r\n\r\n").getContentLength(),
    );
}
