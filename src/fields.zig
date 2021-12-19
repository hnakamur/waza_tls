const std = @import("std");
const fmt = std.fmt;
const math = std.math;
const assert = std.debug.assert;
const isWhiteSpaceChar = @import("parser.zig").lex.isWhiteSpaceChar;

const http_log = std.log.scoped(.http);

pub const Fields = struct {
    fields: []const u8,

    // caller owns memory for fields.
    // fields must contains valid fields with last empty line with CR+LF.
    pub fn init(fields: []const u8) Fields {
        return .{ .fields = fields };
    }

    pub const ContentLengthError = error{Inconsistent} || DecimalDigitsParseError;

    pub fn getContentLength(self: *const Fields) ContentLengthError!?u64 {
        var result: ?u64 = null;
        var it = FieldNameLineIterator.init(self.fields, "content-length");
        while (it.next()) |field_line| {
            var v_it = SimpleCSVIterator.init(field_line.value());
            while (v_it.next()) |v| {
                const val = try parseDecimalDigits(v);
                if (result) |res| {
                    if (val != res) {
                        return error.Inconsistent;
                    }
                } else {
                    result = val;
                }
            }
        }
        return result;
    }

    pub fn hasConnectionToken(self: *const Fields, token: []const u8) bool {
        var it = FieldNameLineIterator.init(self.fields, "connection");
        while (it.next()) |field_line| {
            var v_it = SimpleCSVIterator.init(field_line.value());
            while (v_it.next()) |v| {
                if (std.ascii.eqlIgnoreCase(v, token)) {
                    return true;
                }
            }
        }
        return false;
    }
};

const whiteSpaceChars = [_]u8{ ' ', '\t' };

pub const FieldLine = struct {
    line: []const u8,
    colon_pos: usize,

    pub fn name(self: *const FieldLine) []const u8 {
        return self.line[0..self.colon_pos];
    }

    // return a single header line's value.
    // https://www.ietf.org/archive/id/draft-ietf-httpbis-semantics-19.html#appendix-B.2-6
    pub fn value(self: *const FieldLine) []const u8 {
        return std.mem.trim(u8, self.line[self.colon_pos + 1 ..], &whiteSpaceChars);
    }
};

const crlf = "\r\n";

pub const FieldLineIterator = struct {
    buf: []const u8,
    total_bytes_read: usize,

    pub fn init(buf: []const u8) FieldLineIterator {
        return .{ .buf = buf, .total_bytes_read = 0 };
    }

    pub fn next(self: *FieldLineIterator) ?FieldLine {
        while (self.buf.len > crlf.len) {
            if (std.mem.indexOfScalar(u8, self.buf, ':')) |colon_pos| {
                if (std.mem.indexOfPos(u8, self.buf, colon_pos, crlf)) |crlf_pos| {
                    const line = self.buf[0..crlf_pos];
                    self.total_bytes_read += crlf_pos + crlf.len;
                    self.buf = self.buf[crlf_pos + crlf.len ..];
                    return FieldLine{
                        .line = line,
                        .colon_pos = colon_pos,
                    };
                }
            }
            // NOTE: panic would be more appropriate, but I don't know how to catch panic in test,
            // so use return for now.
            // See https://github.com/ziglang/zig/issues/1356
            http_log.warn("FieldLineIterator must be initialized with valid fields in buf.", .{});
            return null;
        }
        assert(self.buf.len == 0 or std.mem.eql(u8, self.buf, crlf));
        self.total_bytes_read += self.buf.len;
        return null;
    }

    pub fn totalBytesRead(self: *const FieldLineIterator) usize {
        return self.total_bytes_read;
    }
};

pub const FieldNameLineIterator = struct {
    buf: []const u8,
    field_name: []const u8,

    pub fn init(buf: []const u8, field_name: []const u8) FieldNameLineIterator {
        return .{ .buf = buf, .field_name = field_name };
    }

    pub fn next(self: *FieldNameLineIterator) ?FieldLine {
        while (self.buf.len > crlf.len) {
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
            // NOTE: panic would be more appropriate, but I don't know how to catch panic in test,
            // so use return for now.
            // See https://github.com/ziglang/zig/issues/1356
            http_log.warn("FieldNameLineIterator must be initialized with valid fields in buf.", .{});
            return null;
        }
        assert(self.buf.len == 0 or std.mem.eql(u8, self.buf, crlf));
        return null;
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

pub const DecimalDigitsParseError = error{
    InvalidCharacter,
    Overflow,
};

pub fn parseDecimalDigits(digits: []const u8) DecimalDigitsParseError!u64 {
    var result: u64 = 0;
    for (digits) |c| {
        const d = try fmt.charToDigit(c, 10);
        result = try math.add(u64, try math.mul(u64, result, 10), d);
    }
    return result;
}

const testing = std.testing;

test "hasConnectionToken" {
    const input =
        "Connection: close\r\n" ++
        "\r\n";

    var fields = Fields.init(input);
    try testing.expect(fields.hasConnectionToken("close"));
}

fn testSimpleCSVIterator(input: []const u8, wants: [][]const u8) !void {
    var it = SimpleCSVIterator.init(input);
    var i: usize = 0;
    while (it.next()) |v| {
        const want = wants[i];
        try testing.expectEqualStrings(want, v);
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

    {
        var it = SimpleCSVIterator.init(" ");
        try testing.expectEqual(@as( ?[]const u8, null), it.next());
    }
}

test "FieldLineIterator" {
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
    var lineLengths = [_]usize{
        "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n".len,
        "Server: Apache\r\n".len,
        "Last-Modified:  Wed, 22 Jul 2009 19:15:56 GMT\t \r\n".len,
        "ETag: \"34aa387-d-1568eb00\"\r\n".len,
        "Accept-Ranges: bytes\r\n".len,
        "Content-Length: 51\r\n".len,
        "Vary: Accept-Encoding\r\n".len,
        "Content-Type: text/plain\r\n".len,
    };

    var it = FieldLineIterator.init(input);
    var i: usize = 0;
    var total: usize = 0;
    while (it.next()) |f| {
        try testing.expectEqualStrings(names[i], f.name());
        try testing.expectEqualStrings(values[i], f.value());
        total += lineLengths[i];
        try testing.expectEqual(total, it.totalBytesRead());

        i += 1;
    }
    try testing.expectEqual(names.len, i);
    try testing.expectEqual(input.len, it.totalBytesRead());
}

test "FieldLineIterator - bad usage" {
    const input = "Date:";
    var it = FieldLineIterator.init(input);
    try testing.expectEqual(@as(?FieldLine, null), it.next());
}

test "FieldNameLineIterator" {
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

    var it = FieldNameLineIterator.init(input, "cache-control");
    var i: usize = 0;
    while (it.next()) |f| {
        try testing.expect(std.ascii.eqlIgnoreCase(f.name(), "cache-control"));
        try testing.expectEqualStrings(values[i], f.value());
        i += 1;
    }
    try testing.expectEqual(values.len, i);
}

test "FieldNameLineIterator - bad usage" {
    const input = "Date:";
    var it = FieldNameLineIterator.init(input, "Date");
    try testing.expectEqual(@as(?FieldLine, null), it.next());
}

test "parseDecimalDigits" {
    try testing.expectEqual(@as(u64, 123), try parseDecimalDigits("123"));
    try testing.expectEqual(@as(u64, 123), try parseDecimalDigits("000000123"));

    var buf = [_]u8{0} ** 21;
    const len = fmt.formatIntBuf(&buf, @as(u128, math.maxInt(u64)) + 1, 10, .lower, .{});
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
