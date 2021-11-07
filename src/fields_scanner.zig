const std = @import("std");
const token_char = @import("token_char.zig");
const isTokenChar = token_char.isTokenChar;
const isFieldVisibleChar = token_char.isFieldVisibleChar;
const isWhiteSpaceChar = token_char.isWhiteSpaceChar;

pub const FieldsScanner = struct {
    const Error = error{
        InvalidInput,
        InvalidState,
    };

    const State = enum {
        on_header,
        on_colon,
        on_optional_whitespace_after_colon,
        on_value_or_optional_whitespace_in_or_after_value,
        seen_cr,
        seen_cr_lf,
        seen_cr_lf_cr,
        done,
    };

    state: State = .on_header,
    total_bytes_read: usize = 0,

    pub fn scan(self: *FieldsScanner, chunk: []const u8) Error!bool {
        var pos: usize = 0;
        while (pos < chunk.len) : (pos += 1) {
            const c = chunk[pos];
            self.total_bytes_read += 1;
            switch (self.state) {
                .on_header => if (c == ':') {
                    self.state = .on_colon;
                } else if (!isHeaderChar(c)) {
                    return error.InvalidInput;
                },
                .on_colon, .on_optional_whitespace_after_colon => if (isFieldVisibleChar(c)) {
                    self.state = .on_value_or_optional_whitespace_in_or_after_value;
                } else if (!isWhiteSpaceChar(c)) {
                    return error.InvalidInput;
                },
                .on_value_or_optional_whitespace_in_or_after_value => if (c == '\r') {
                    self.state = .seen_cr;
                } else if (!isFieldVisibleChar(c) and !isWhiteSpaceChar(c)) {
                    return error.InvalidInput;
                },
                .seen_cr => if (c == '\n') {
                    self.state = .seen_cr_lf;
                } else {
                    return error.InvalidInput;
                },
                .seen_cr_lf => if (isHeaderChar(c)) {
                    self.state = .on_header;
                } else if (c == '\r') {
                    self.state = .seen_cr_lf_cr;
                } else {
                    return error.InvalidInput;
                },
                .seen_cr_lf_cr => if (c == '\n') {
                    self.state = .done;
                    return true;
                } else {
                    return error.InvalidInput;
                },
                else => return error.InvalidState,
            }
        }
        return false;
    }

    inline fn isHeaderChar(c: u8) bool {
        return isTokenChar(c);
    }

    pub fn totalBytesRead(self: *const FieldsScanner) usize {
        return self.total_bytes_read;
    }
};

const testing = std.testing;

test "FieldsScanner - whole in one buf" {
    const input = "Host: www.example.com\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expect(try finder.scan(input));
    try testing.expectEqual(input.len, finder.totalBytesRead());
}

test "FieldsScanner - optional whitespace before, after, in value" {
    const input = "Host: www.example.com\r\n" ++
        "Cache-Control:\tpublic, ,,s-maxage=60 \t\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expect(try finder.scan(input));
    try testing.expectEqual(input.len, finder.totalBytesRead());
}

test "FieldsScanner - no whitespace before value" {
    const input = "Host:www.example.com\r\n" ++
        "Cache-Control:public,s-maxage=60\r\n" ++
        "Accept:*/*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expect(try finder.scan(input));
    try testing.expectEqual(input.len, finder.totalBytesRead());
}

test "FieldsScanner - splitted case" {
    const input = "Host: www.example.com\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var pos: usize = 0;
    while (pos < input.len) : (pos += 1) {
        var finder = FieldsScanner{};
        try testing.expect(!try finder.scan(input[0..pos]));
        try testing.expectEqual(pos, finder.totalBytesRead());
        try testing.expect(try finder.scan(input[pos..]));
        try testing.expectEqual(input.len, finder.totalBytesRead());
    }
}

test "FieldsScanner - InvalidInput bad value char" {
    const input = "Host: www.example.com\r\n" ++
        "Cache-Control:\tpublic,\x00,,s-maxage=60 \t\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expectError(error.InvalidInput, finder.scan(input));
}

test "FieldsScanner - InvalidInput bad header character delimiter" {
    const input = "Host?: www.example.com\r\n" ++
        "Cache-Control:\tpublic, ,,s-maxage=60 \t\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expectError(error.InvalidInput, finder.scan(input));
}

test "FieldsScanner - InvalidInput bad header character control character" {
    const input = "Host\x00: www.example.com\r\n" ++
        "Cache-Control:\tpublic, ,,s-maxage=60 \t\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expectError(error.InvalidInput, finder.scan(input));
}

test "FieldsScanner - InvalidInput space before header" {
    const input = " Host: www.example.com\r\n" ++
        "Cache-Control:\tpublic, ,,s-maxage=60 \t\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expectError(error.InvalidInput, finder.scan(input));
}

test "FieldsScanner - InvalidInput space before colon" {
    const input = "Host : www.example.com\r\n" ++
        "Cache-Control:\tpublic, ,,s-maxage=60 \t\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expectError(error.InvalidInput, finder.scan(input));
}

test "FieldsScanner - InvalidInput empty value" {
    const input = "Host:\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expectError(error.InvalidInput, finder.scan(input));
}

test "FieldsScanner - InvalidInput only whitespace value" {
    const input = "Host: \r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsScanner{};
    try testing.expectError(error.InvalidInput, finder.scan(input));
}
