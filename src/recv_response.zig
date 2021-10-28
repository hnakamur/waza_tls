const std = @import("std");
const mem = std.mem;
const Version = @import("version.zig").Version;
const StatusCode = @import("status_code.zig").StatusCode;
const config = @import("config.zig");

/// A receiving response.
pub const RecvResponse = struct {
    buf: []const u8,
    version: Version,
    status_code: StatusCode,
    reason_phrase: []const u8,
    headers: []const u8,
    allocator: *mem.Allocator,

    /// `buf` must be allocated with `allocator`.
    /// It will be freed in `deinit`.
    pub fn init(allocator: *mem.Allocator, buf: []const u8, result: *const StatusLineSplitter.Result, headers_len: usize) !RecvResponse {
        const ver_buf = buf[0..result.version_len];
        const version = Version.fromText(ver_buf) catch |_| return error.BadGateway;
        const code_buf = buf[result.status_code_start_pos .. result.status_code_start_pos + result.status_code_len];
        const status_code = StatusCode.fromText(code_buf) catch |_| return error.BadGateway;
        const reason_phrase = buf[result.reason_phrase_start_pos .. result.reason_phrase_start_pos + result.reason_phrase_len];
        const headers = buf[result.total_bytes_read .. result.total_bytes_read + headers_len];

        return RecvResponse{
            .buf = buf,
            .version = version,
            .status_code = status_code,
            .reason_phrase = reason_phrase,
            .headers = headers,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RecvResponse) void {
        self.allocator.free(self.buf);
    }
};

const StatusLineSplitter = struct {
    const State = enum {
        on_version,
        post_version,
        on_status_code,
        post_status_code,
        on_reason_phrase,
        seen_cr,
        done,
    };

    const Result = struct {
        total_bytes_read: usize = 0,
        version_len: usize = 0,
        status_code_start_pos: usize = 0,
        status_code_len: usize = 0,
        reason_phrase_start_pos: usize = 0,
        reason_phrase_len: usize = 0,
    };

    const version_max_len: usize = Version.http1_1.toText().len;
    const status_code_expected_len: usize = 3;

    reason_phrase_max_len: usize = config.reason_phrase_max_len,
    state: State = .on_version,
    result: Result = undefined,

    pub fn parse(self: *StatusLineSplitter, chunk: []const u8) !bool {
        var pos: usize = 0;
        while (pos < chunk.len) {
            const c = chunk[pos];
            pos += 1;
            self.result.total_bytes_read += 1;
            switch (self.state) {
                .on_version => {
                    if (c == ' ') {
                        self.state = .post_version;
                        self.result.status_code_start_pos = self.result.total_bytes_read;
                    } else {
                        self.result.version_len += 1;
                        if (self.result.version_len > version_max_len) {
                            return error.BadGateway;
                        }
                    }
                },
                .post_version => {
                    if (c != ' ') {
                        self.result.status_code_len += 1;
                        self.state = .on_status_code;
                    } else {
                        return error.BadGateway;
                    }
                },
                .on_status_code => {
                    if (c == ' ') {
                        if (self.result.status_code_len != status_code_expected_len) {
                            return error.BadGateway;
                        }
                        self.state = .post_status_code;
                        self.result.reason_phrase_start_pos = self.result.total_bytes_read;
                    } else {
                        self.result.status_code_len += 1;
                        if (self.result.status_code_len > status_code_expected_len) {
                            return error.BadGateway;
                        }
                    }
                },
                .post_status_code => {
                    if (c == '\r') {
                        self.state = .seen_cr;
                    } else if (c != ' ') {
                        self.result.reason_phrase_len += 1;
                        self.state = .on_reason_phrase;
                    } else {
                        return error.BadGateway;
                    }
                },
                .on_reason_phrase => {
                    if (c == '\r') {
                        self.state = .seen_cr;
                    } else {
                        self.result.reason_phrase_len += 1;
                        if (self.result.reason_phrase_len > self.reason_phrase_max_len) {
                            return error.BadGateway;
                        }
                    }
                },
                .seen_cr => {
                    if (c == '\n') {
                        self.state = .done;
                        return true;
                    }
                    return error.BadGateway;
                },
                .done => return error.InvalidState,
            }
        }
        return false;
    }
};

const testing = std.testing;
const FieldsEndFinder = @import("fields_end_finder.zig").FieldsEndFinder;

test "RecvResponse - 200 OK" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const headers = "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n" ++ headers;

    var splitter = StatusLineSplitter{};
    try testing.expect(try splitter.parse(input));
    var finder = FieldsEndFinder{};
    try testing.expect(try finder.parse(input[splitter.result.total_bytes_read..]));
    try testing.expectEqual(input.len, splitter.result.total_bytes_read + finder.total_bytes_read);

    const allocator = testing.allocator;
    const buf = try allocator.dupe(u8, input);
    var resp = try RecvResponse.init(allocator, buf, &splitter.result, finder.total_bytes_read);
    defer resp.deinit();

    try testing.expectEqual(Version.http1_1, resp.version);
    try testing.expectEqual(StatusCode.ok, resp.status_code);
    try testing.expectEqualStrings(reason_phrase, resp.reason_phrase);
    try testing.expectEqualStrings(headers, resp.headers);
}

test "StatusLineSplitter - whole in one buf with reason phrase" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var splitter = StatusLineSplitter{};
    try testing.expect(try splitter.parse(input));
    const result = splitter.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineSplitter - whole in one buf without reason phrase" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var splitter = StatusLineSplitter{};
    try testing.expect(try splitter.parse(input));
    const result = splitter.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineSplitter - one byte at time" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var splitter = StatusLineSplitter{};
    var i: usize = 0;
    while (i < input.len - 2) : (i += 1) {
        try testing.expect(!try splitter.parse(input[i .. i + 1]));
    }
    try testing.expect(try splitter.parse(input[i..]));
    const result = splitter.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineSplitter - variable length chunks" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    const ends = [_]usize{
        version.len - 1,
        version.len + " ".len + status_code.len - 1,
        version.len + " ".len + status_code.len + " ".len + reason_phrase.len - 1,
        input.len,
    };
    var splitter = StatusLineSplitter{};

    var start: usize = 0;
    for (ends) |end| {
        try testing.expect((try splitter.parse(input[start..end])) == (end == input.len));
        start = end;
    }
    const result = splitter.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineSplitter - too long version" {
    const version = "HTTP/3.14";
    const status_code = "200";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var splitter = StatusLineSplitter{};
    try testing.expectError(error.BadGateway, splitter.parse(input));
}

test "StatusLineSplitter - too short status code" {
    const version = "HTTP/1.1";
    const status_code = "20";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var splitter = StatusLineSplitter{};
    try testing.expectError(error.BadGateway, splitter.parse(input));
}

test "StatusLineSplitter - too long status code" {
    const version = "HTTP/1.1";
    const status_code = "2000";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var splitter = StatusLineSplitter{};
    try testing.expectError(error.BadGateway, splitter.parse(input));
}

test "StatusLineSplitter - invalid status code character must be handled later" {
    const version = "HTTP/1.1";
    const status_code = "20A";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var splitter = StatusLineSplitter{};
    try testing.expect(try splitter.parse(input));
    const result = splitter.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineSplitter - too long reason phrase" {
    const version = "HTTP/1.1";
    const status_code = "2000";
    const reason_phrase = "a" ** (config.reason_phrase_max_len + 1);
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var splitter = StatusLineSplitter{};
    try testing.expectError(error.BadGateway, splitter.parse(input));
}
