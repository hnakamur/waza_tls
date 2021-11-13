const std = @import("std");
const fmt = std.fmt;
const math = std.math;
const FieldIterator = @import("field_iterator.zig").FieldIterator;
const isWhiteSpaceChar = @import("token_char.zig").isWhiteSpaceChar;

pub const FieldLine = struct {
    line: []const u8,
    colon_pos: usize,

    pub fn name(self: *const FieldLine) []const u8 {
        return self.line[0..self.colon_pos];
    }

    // return a single header line's value.
    // https://www.ietf.org/archive/id/draft-ietf-httpbis-semantics-19.html#appendix-B.2-6
    pub fn value(self: *const FieldLine) []const u8 {
        return std.mem.trim(u8, self.line[self.colon_pos + 1 ..], &[_]u8{ ' ', '\t' });
    }
};

pub const Fields = struct {
    fields: []const u8,

    // caller owns memory for fields.
    // fields must contains valid fields with last empty line with CR+LF.
    pub fn init(fields: []const u8) Fields {
        return .{ .fields = fields };
    }

    const crlf = "\r\n";

    pub const FieldLineIterator = struct {
        buf: []const u8,

        pub fn next(self: *FieldLineIterator) ?FieldLine {
            if (std.mem.startsWith(u8, self.buf, crlf)) {
                self.buf = self.buf[crlf.len..];
                return null;
            }

            if (std.mem.indexOfScalar(u8, self.buf, ':')) |colon_pos| {
                if (std.mem.indexOfPos(u8, self.buf, colon_pos, crlf)) |crlf_pos| {
                    const line = self.buf[0..crlf_pos];
                    self.buf = self.buf[crlf_pos + crlf.len ..];
                    return FieldLine{
                        .line = line,
                        .colon_pos = colon_pos,
                    };
                }
            }
            @panic("FieldLineIterator must be initialized with valid fields in buf.");
        }
    };

    pub fn fieldLineIterator(self: *const Fields) FieldLineIterator {
        return .{ .buf = self.fields };
    }

    pub const FieldNameLineIterator = struct {
        buf: []const u8,
        field_name: []const u8,

        pub fn next(self: *FieldNameLineIterator) ?FieldLine {
            while (true) {
                if (std.mem.startsWith(u8, self.buf, crlf)) {
                    self.buf = self.buf[crlf.len..];
                    return null;
                }

                if (std.mem.indexOfScalar(u8, self.buf, ':')) |colon_pos| {
                    if (std.mem.indexOfPos(u8, self.buf, colon_pos, crlf)) |crlf_pos| {
                        if (std.ascii.eqlIgnoreCase(self.buf[0..colon_pos], self.field_name)) {
                            const line = self.buf[0..crlf_pos];
                            self.buf = self.buf[crlf_pos + crlf.len ..];
                            return FieldLine{
                                .line = line,
                                .colon_pos = colon_pos,
                            };
                        } else {
                            self.buf = self.buf[crlf_pos + crlf.len ..];
                            continue;
                        }
                    }
                }
                @panic("FieldNameLineIterator must be initialized with valid fields in buf.");
            }
        }
    };

    pub fn fieldNameLineIterator(self: *const Fields, field_name: []const u8) FieldNameLineIterator {
        return .{ .buf = self.fields, .field_name = field_name };
    }

    pub const ContentLengthError = error{Inconsistent} || DecimalDigitsParseError;

    pub fn getContentLength(self: *const Fields) ContentLengthError!?u64 {
        var result: ?u64 = null;
        var it = self.fieldNameLineIterator("content-length");
        while (it.next()) |field_line| {
            var v_it = SimpleCSVIterator.init(field_line.value());
            while (v_it.next()) |v| {
                const val = try parseDecimalDigits(v);
                if (result) |res| {
                    if (val != result) {
                        return error.Inconsistent;
                    }
                } else {
                    result = val;
                }
            }
        }
        return result;
    }
};

/// iterate on comma separated values in a single field line.
/// should not be used for values containing dquote-string,
/// since this splits values with comma even in the dquote-strings.
const SimpleCSVIterator = struct {
    const State = enum {
        initial,
        on_pre_optional_white_space,
        on_value,
        on_post_optional_white_space,
    };

    buf: []const u8,

    fn init(buf: []const u8) SimpleCSVIterator {
        return .{ .buf = buf };
    }

    fn next(self: *SimpleCSVIterator) ?[]const u8 {
        if (self.buf.len == 0) return null;

        var state: State = .initial;
        var start_pos: usize = 0;
        var end_pos: usize = 0;
        var pos: usize = 0;
        while (pos < self.buf.len) : (pos += 1) {
            const c = self.buf[pos];
            switch (state) {
                .initial => if (isWhiteSpaceChar(c)) {
                    state = .on_pre_optional_white_space;
                } else {
                    state = .on_value;
                    start_pos = pos;
                },
                .on_pre_optional_white_space => if (!isWhiteSpaceChar(c)) {
                    state = .on_value;
                    start_pos = pos;
                },
                .on_value => if (c == ',') {
                    const result = self.buf[start_pos..pos];
                    self.buf = self.buf[pos + 1 ..];
                    return result;
                } else if (isWhiteSpaceChar(c)) {
                    end_pos = pos;
                    state = .on_post_optional_white_space;
                },
                .on_post_optional_white_space => if (c == ',') {
                    const result = self.buf[start_pos..end_pos];
                    self.buf = self.buf[pos + 1 ..];
                    return result;
                } else if (!isWhiteSpaceChar(c)) {
                    state = .on_value;
                },
            }
        }
        const result = switch (state) {
            .initial, .on_pre_optional_white_space => null,
            .on_value => self.buf[start_pos..],
            .on_post_optional_white_space => self.buf[start_pos..end_pos],
        };
        self.buf = self.buf[self.buf.len..];
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

fn testSimpleCSVIterator(input: []const u8, wants: [][]const u8) !void {
    var it = SimpleCSVIterator.init(input);
    var i: usize = 0;
    while (it.next()) |v| {
        const want = wants[i];
        if (testing.expectEqualStrings(want, v)) |_| {} else |err| {
            std.debug.print("input={s}, i={d}\n", .{ input, i });
            return err;
        }

        i += 1;
    }
    try testing.expectEqual(wants.len, i);
}

test "SimpleCSVIterator" {
    // normal successful cases
    {
        var wants = [_][]const u8{"123"};
        try testSimpleCSVIterator("123", &wants);
        try testSimpleCSVIterator(" \t123", &wants);
        try testSimpleCSVIterator("123\t ", &wants);
        try testSimpleCSVIterator("\t 123 \t ", &wants);
    }
    {
        var wants = [_][]const u8{ "123", "456" };
        try testSimpleCSVIterator("123,456", &wants);
        try testSimpleCSVIterator("\t 123 \t,456", &wants);
        try testSimpleCSVIterator("\t 123, 456", &wants);
        try testSimpleCSVIterator("\t 123, 456\t", &wants);
        try testSimpleCSVIterator("\t 123\t, 456\t", &wants);
    }
    {
        var wants = [_][]const u8{ "123", "456", "789" };
        try testSimpleCSVIterator("123,456,789", &wants);
        try testSimpleCSVIterator("123, 456, 789", &wants);
        try testSimpleCSVIterator("\t 123 \t,456,789", &wants);
        try testSimpleCSVIterator("\t 123, 456 , 789", &wants);
        try testSimpleCSVIterator("\t 123, 456\t,789 ", &wants);
        try testSimpleCSVIterator("\t 123\t, 456\t, 789 ", &wants);
    }

    // successful cases for values containing whitespaces
    {
        var wants = [_][]const u8{"123 456"};
        try testSimpleCSVIterator("123 456", &wants);
        try testSimpleCSVIterator(" \t123 456", &wants);
        try testSimpleCSVIterator("123 456\t ", &wants);
        try testSimpleCSVIterator("\t 123 456\t ", &wants);
    }

    {
        // bad example for using testSimpleCSVIterator for dquote-strings.
        var wants = [_][]const u8{ "\"123", "456\"", "789" };
        try testSimpleCSVIterator("\"123,456\",789", &wants);
    }
}

test "fieldLineIterator" {
    // value may contain optional white spaces.
    const input =
        "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "Last-Modified:  Wed, 22 Jul 2009 19:15:56 GMT\t \r\n" ++
        "ETag: \"34aa387-d-1568eb00\"\r\n" ++
        "Accept-Ranges: bytes\r\n" ++
        "Content-Length: 51\r\n" ++
        "Vary: Accept-Encoding\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n";
    var names = [_][]const u8{
        "Date",
        "Server",
        "Last-Modified",
        "ETag",
        "Accept-Ranges",
        "Content-Length",
        "Vary",
        "Content-Type",
    };
    var values = [_][]const u8{
        "Mon, 27 Jul 2009 12:28:53 GMT",
        "Apache",
        "Wed, 22 Jul 2009 19:15:56 GMT",
        "\"34aa387-d-1568eb00\"",
        "bytes",
        "51",
        "Accept-Encoding",
        "text/plain",
    };

    var it = Fields.init(input).fieldLineIterator();
    var i: usize = 0;
    while (it.next()) |f| {
        try testing.expectEqualStrings(names[i], f.name());
        try testing.expectEqualStrings(values[i], f.value());
        i += 1;
    }
    try testing.expectEqual(names.len, i);
}

test "fieldNameLineIterator" {
    const input =
        "Date:  \tMon, 27 Jul 2009 12:28:53 GMT \r\n" ++
        "Cache-Control: public, s-maxage=60\r\n" ++
        "Vary: Accept-Encoding\r\n" ++
        "cache-control: maxage=120\r\n" ++
        "\r\n";
    var values = [_][]const u8{
        "public, s-maxage=60",
        "maxage=120",
    };

    var it = Fields.init(input).fieldNameLineIterator("cache-control");
    var i: usize = 0;
    while (it.next()) |f| {
        if (!std.ascii.eqlIgnoreCase(f.name(), "cache-control")) {
            std.debug.print("field name mismatch, got {s}, should sqlIgnoreCase to {s}", .{
                f.name(),
                "cache-control",
            });
            return error.TestExpectedError;
        }
        try testing.expectEqualStrings(values[i], f.value());
        i += 1;
    }
    try testing.expectEqual(values.len, i);
}

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
        @as(Fields.ContentLengthError!?u64, 123),
        Fields.init("content-length: 123, 123\r\n\r\n").getContentLength(),
    );
    try testing.expectEqual(
        @as(Fields.ContentLengthError!?u64, 123),
        Fields.init("content-length: 123, 123\r\ncontent-length: 123\r\n\r\n").getContentLength(),
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
        error.Inconsistent,
        Fields.init("content-length: 123, 124\r\n\r\n").getContentLength(),
    );
    try testing.expectError(
        error.Overflow,
        Fields.init("content-length: 18446744073709551616\r\n\r\n").getContentLength(),
    );
}