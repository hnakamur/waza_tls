const std = @import("std");
const mem = std.mem;
const Version = @import("version.zig").Version;
const StatusCode = @import("status_code.zig").StatusCode;
const FieldsScanner = @import("fields_scanner.zig").FieldsScanner;
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
    pub fn init(allocator: *mem.Allocator, buf: []const u8, scanner: *const RecvResponseScanner) !RecvResponse {
        std.debug.assert(scanner.headers.state == .done);
        const result = scanner.status_line.result;
        const headers_len = scanner.headers.total_bytes_read;

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

pub const RecvResponseScanner = struct {
    status_line: StatusLineScanner = StatusLineScanner{},
    headers: FieldsScanner = FieldsScanner{},

    pub fn scan(self: *RecvResponseScanner, chunk: []const u8) !bool {
        if (self.status_line.state != .done) {
            const old = self.status_line.result.total_bytes_read;
            if (!try self.status_line.scan(chunk)) {
                return false;
            }
            const read = self.status_line.result.total_bytes_read - old;
            return self.headers.scan(chunk[read..]);
        }
        return self.headers.scan(chunk);
    }
};

const StatusLineScanner = struct {
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
    result: Result = Result{},

    pub fn scan(self: *StatusLineScanner, chunk: []const u8) !bool {
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

test "RecvResponse - 200 OK" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const headers = "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n" ++ headers;

    const allocator = testing.allocator;
    const buf = try allocator.dupe(u8, input);

    var scanner = RecvResponseScanner{};
    try testing.expect(try scanner.scan(buf));
    var resp = try RecvResponse.init(allocator, buf, &scanner);
    defer resp.deinit();

    try testing.expectEqual(Version.http1_1, resp.version);
    try testing.expectEqual(StatusCode.ok, resp.status_code);
    try testing.expectEqualStrings(reason_phrase, resp.reason_phrase);
    try testing.expectEqualStrings(headers, resp.headers);
}

test "RecvResponseScanner" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const headers = "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    const status_line = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";
    const input = status_line ++ headers;

    var scanner = RecvResponseScanner{};
    try testing.expect(try scanner.scan(input));
    const result = scanner.status_line.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(status_line.len, result.total_bytes_read);
    try testing.expectEqual(headers.len, scanner.headers.total_bytes_read);
}

test "StatusLineScanner - whole in one buf with reason phrase" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expect(try scanner.scan(input));
    const result = scanner.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineScanner - whole in one buf without reason phrase" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expect(try scanner.scan(input));
    const result = scanner.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineScanner - one byte at time" {
    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    var i: usize = 0;
    while (i < input.len - 2) : (i += 1) {
        try testing.expect(!try scanner.scan(input[i .. i + 1]));
    }
    try testing.expect(try scanner.scan(input[i..]));
    const result = scanner.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineScanner - variable length chunks" {
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
    var scanner = StatusLineScanner{};

    var start: usize = 0;
    for (ends) |end| {
        try testing.expect((try scanner.scan(input[start..end])) == (end == input.len));
        start = end;
    }
    const result = scanner.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineScanner - too long version" {
    const version = "HTTP/3.14";
    const status_code = "200";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}

test "StatusLineScanner - too short status code" {
    const version = "HTTP/1.1";
    const status_code = "20";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}

test "StatusLineScanner - too long status code" {
    const version = "HTTP/1.1";
    const status_code = "2000";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}

test "StatusLineScanner - invalid status code character must be handled later" {
    const version = "HTTP/1.1";
    const status_code = "20A";
    const reason_phrase = "";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expect(try scanner.scan(input));
    const result = scanner.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "StatusLineScanner - too long reason phrase" {
    const version = "HTTP/1.1";
    const status_code = "2000";
    const reason_phrase = "a" ** (config.reason_phrase_max_len + 1);
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}
