const std = @import("std");
const mem = std.mem;
const Version = @import("version.zig").Version;
const StatusCode = @import("status_code.zig").StatusCode;
const Fields = @import("fields.zig").Fields;
const FieldsScanner = @import("fields_scanner.zig").FieldsScanner;
const config = @import("config.zig");

const http_log = std.log.scoped(.http);

/// A receiving response.
pub const RecvResponse = struct {
    const Error = error{
        BadGateway,
    };

    buf: []const u8,
    version: Version,
    status_code: StatusCode,
    reason_phrase: []const u8,
    headers: Fields,

    /// Caller owns `buf`. Returned response is valid for use only while `buf` is valid.
    pub fn init(buf: []const u8, scanner: *const RecvResponseScanner) Error!RecvResponse {
        std.debug.assert(scanner.headers.state == .done);
        const result = scanner.status_line.result;
        const status_line_len = result.total_bytes_read;
        const headers_len = scanner.headers.total_bytes_read;

        const ver_buf = buf[0..result.version_len];
        const version = Version.fromBytes(ver_buf) catch return error.BadGateway;
        const code_buf = buf[result.status_code_start_pos .. result.status_code_start_pos + result.status_code_len];
        const status_code = StatusCode.fromBytes(code_buf) catch return error.BadGateway;
        const reason_phrase = buf[result.reason_phrase_start_pos .. result.reason_phrase_start_pos + result.reason_phrase_len];
        const headers = Fields.init(buf[status_line_len .. status_line_len + headers_len]);

        return RecvResponse{
            .buf = buf,
            .version = version,
            .status_code = status_code,
            .reason_phrase = reason_phrase,
            .headers = headers,
        };
    }
};

pub const RecvResponseScanner = struct {
    const Error = error{
        BadGateway,
    };

    status_line: StatusLineScanner = StatusLineScanner{},
    headers: FieldsScanner = FieldsScanner{},

    pub fn scan(self: *RecvResponseScanner, chunk: []const u8) Error!bool {
        if (self.status_line.state != .done) {
            const old = self.status_line.result.total_bytes_read;
            if (!try self.status_line.scan(chunk)) {
                http_log.debug("RecvResponseScanner.scan status line not complete", .{});
                return false;
            }
            const read = self.status_line.result.total_bytes_read - old;
            return self.headers.scan(chunk[read..]) catch |err| blk: {
                http_log.debug("RecvResponseScanner.scan err#1={s}", .{@errorName(err)});
                break :blk error.BadGateway;
            };
        }
        return self.headers.scan(chunk) catch |err| blk: {
            http_log.debug("RecvResponseScanner.scan err#2={s}", .{@errorName(err)});
            break :blk error.BadGateway;
        };
    }

    pub fn totalBytesRead(self: *const RecvResponseScanner) usize {
        return self.status_line.result.total_bytes_read +
            self.headers.total_bytes_read;
    }
};

const StatusLineScanner = struct {
    const Error = error{
        BadGateway,
    };

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

    const version_max_len: usize = Version.http1_1.toBytes().len;
    const status_code_expected_len: usize = 3;
    const reason_phrase_max_len: usize = config.reason_phrase_max_len;

    state: State = .on_version,
    result: Result = Result{},

    pub fn scan(self: *StatusLineScanner, chunk: []const u8) Error!bool {
        var pos: usize = 0;
        while (pos < chunk.len) : (pos += 1) {
            const c = chunk[pos];
            self.result.total_bytes_read += 1;
            switch (self.state) {
                .on_version => {
                    if (c == ' ') {
                        self.state = .post_version;
                        self.result.status_code_start_pos = self.result.total_bytes_read;
                    } else {
                        self.result.version_len += 1;
                        if (self.result.version_len > version_max_len) {
                            http_log.debug("StatusLineScanner.scan err#1", .{});
                            return error.BadGateway;
                        }
                    }
                },
                .post_version => {
                    if (c != ' ') {
                        self.result.status_code_len += 1;
                        self.state = .on_status_code;
                    } else {
                        http_log.debug("StatusLineScanner.scan err#2", .{});
                        return error.BadGateway;
                    }
                },
                .on_status_code => {
                    if (c == ' ') {
                        if (self.result.status_code_len != status_code_expected_len) {
                            http_log.debug("StatusLineScanner.scan err#3", .{});
                            return error.BadGateway;
                        }
                        self.state = .post_status_code;
                        self.result.reason_phrase_start_pos = self.result.total_bytes_read;
                    } else {
                        self.result.status_code_len += 1;
                        if (self.result.status_code_len > status_code_expected_len) {
                            http_log.debug("StatusLineScanner.scan err#4", .{});
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
                        http_log.debug("StatusLineScanner.scan err#5", .{});
                        return error.BadGateway;
                    }
                },
                .on_reason_phrase => {
                    if (c == '\r') {
                        self.state = .seen_cr;
                    } else {
                        self.result.reason_phrase_len += 1;
                        if (self.result.reason_phrase_len > reason_phrase_max_len) {
                            http_log.debug("StatusLineScanner.scan err#6", .{});
                            return error.BadGateway;
                        }
                    }
                },
                .seen_cr => {
                    if (c == '\n') {
                        self.state = .done;
                        return true;
                    }
                    http_log.debug("StatusLineScanner.scan err#7", .{});
                    return error.BadGateway;
                },
                .done => {
                    // NOTE: panic would be more appropriate since calling scan after complete
                    // is a programming bug. But I don't know how to catch panic in test, so
                    // use return for now.
                    // See https://github.com/ziglang/zig/issues/1356
                    // @panic("StatusLineScanner.scan called again after scan is complete");
                    http_log.debug("StatusLineScanner.scan err#8", .{});
                    return error.BadGateway;
                },
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

    var scanner = RecvResponseScanner{};
    try testing.expect(try scanner.scan(input));
    var resp = try RecvResponse.init(input, &scanner);
    try testing.expectEqual(Version.http1_1, resp.version);
    try testing.expectEqual(StatusCode.ok, resp.status_code);
    try testing.expectEqualStrings(reason_phrase, resp.reason_phrase);
    try testing.expectEqualStrings(headers, resp.headers.fields);
}

test "RecvResponseScanner - scan once complete" {
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

test "RecvResponseScanner - middle of status line" {
    // testing.log_level = .debug;

    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const headers = "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    const status_line = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";
    const input = status_line ++ headers;

    var scanner = RecvResponseScanner{};
    try testing.expect(!try scanner.scan(input[0..status_line.len-1]));
    try testing.expect(try scanner.scan(input[status_line.len-1..]));
    const result = scanner.status_line.result;
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(version.len + 1, result.status_code_start_pos);
    try testing.expectEqual(status_code.len, result.status_code_len);
    try testing.expectEqual(version.len + 1 + status_code.len + 1, result.reason_phrase_start_pos);
    try testing.expectEqual(reason_phrase.len, result.reason_phrase_len);
    try testing.expectEqual(status_line.len, result.total_bytes_read);
    try testing.expectEqual(headers.len, scanner.headers.total_bytes_read);
}

test "RecvResponseScanner - bad header with status line" {
    // testing.log_level = .debug;

    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const headers = "Date : Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    const status_line = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";
    const input = status_line ++ headers;

    var scanner = RecvResponseScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}

test "RecvResponseScanner - bad header after status line" {
    // testing.log_level = .debug;

    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const headers = "Date : Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    const status_line = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";
    const input = status_line ++ headers;

    var scanner = RecvResponseScanner{};
    try testing.expect(!try scanner.scan(input[0..status_line.len+1]));
    try testing.expectError(error.BadGateway, scanner.scan(input[status_line.len+1..]));
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
    // testing.log_level = .debug;

    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "a" ** (config.reason_phrase_max_len + 1);
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}

test "StatusLineScanner - two spaces after vrsion" {
    // testing.log_level = .debug;

    const version = "HTTP/1.1";
    const input = version ++ "  ";

    var scanner = StatusLineScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}

test "StatusLineScanner - two spaces after status code" {
    // testing.log_level = .debug;

    const version = "HTTP/1.1";
    const status_code = "200";
    const input = version ++ " " ++ status_code ++ "  ";

    var scanner = StatusLineScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}

test "StatusLineScanner - not lf after cr" {
    // testing.log_level = .debug;

    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\r";

    var scanner = StatusLineScanner{};
    try testing.expectError(error.BadGateway, scanner.scan(input));
}

test "StatusLineScanner - called again after scan is complete" {
    // testing.log_level = .debug;

    const version = "HTTP/1.1";
    const status_code = "200";
    const reason_phrase = "OK";
    const input = version ++ " " ++ status_code ++ " " ++ reason_phrase ++ "\r\n";

    var scanner = StatusLineScanner{};
    try testing.expect(try scanner.scan(input));
    try testing.expectError(error.BadGateway, scanner.scan(input));
}
