const std = @import("std");
const mem = std.mem;
const Method = @import("method.zig").Method;
const Version = @import("version.zig").Version;
const isTokenChar = @import("token_char.zig").isTokenChar;
const config = @import("config.zig");

/// A receiving request.
pub const RecvRequest = struct {
    buf: []const u8,
    method: Method,
    uri: []const u8,
    version: Version,
    headers: []const u8,
    allocator: *mem.Allocator,

    /// `buf` must be allocated with `allocator`.
    /// It will be freed in `deinit`.
    pub fn init(allocator: *mem.Allocator, buf: []const u8, result: *const RequestLineSplitter.Result, headers_len: usize) !RecvRequest {
        const method = Method.fromText(buf[0..result.method_len]) catch unreachable;
        const uri = buf[result.uri_start_pos .. result.uri_start_pos + result.uri_len];
        const ver_buf = buf[result.version_start_pos .. result.version_start_pos + result.version_len];
        const version = Version.fromText(ver_buf) catch |_| return error.BadRequest;
        const headers = buf[result.total_bytes_read .. result.total_bytes_read + headers_len];

        return RecvRequest{
            .buf = buf,
            .method = method,
            .uri = uri,
            .version = version,
            .headers = headers,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RecvRequest) void {
        self.allocator.free(self.buf);
    }
};


const RequestLineSplitter = struct {
    const State = enum {
        on_method,
        post_method,
        on_uri,
        post_uri,
        on_version,
        seen_cr,
        done,
    };

    const Result = struct {
        total_bytes_read: usize = 0,
        method_len: usize = 0,
        uri_start_pos: usize = 0,
        uri_len: usize = 0,
        version_start_pos: usize = 0,
        version_len: usize = 0,
    };

    const version_max_len: usize = Version.http1_1.toText().len;

    method_max_len: usize = config.method_max_len,
    uri_max_len: usize = config.uri_max_len,
    state: State = .on_method,
    result: Result = undefined,

    pub fn parse(self: *RequestLineSplitter, chunk: []const u8) !bool {
        var pos: usize = 0;
        while (pos < chunk.len) {
            const c = chunk[pos];
            pos += 1;
            self.result.total_bytes_read += 1;
            switch (self.state) {
                .on_method => {
                    if (c == ' ') {
                        self.state = .post_method;
                    } else {
                        self.result.method_len += 1;
                        if (!isTokenChar(c) or self.result.method_len > self.method_max_len) {
                            return error.BadRequest;
                        }
                    }
                },
                .post_method => {
                    if (c != ' ') {
                        self.result.uri_start_pos = self.result.total_bytes_read - 1;
                        self.result.uri_len += 1;
                        self.state = .on_uri;
                    } else {
                        return error.BadRequest;
                    }
                },
                .on_uri => {
                    if (c == ' ') {
                        self.state = .post_uri;
                    } else {
                        self.result.uri_len += 1;
                        if (self.result.uri_len > self.uri_max_len) {
                            return error.UriTooLong;
                        }
                    }
                },
                .post_uri => {
                    if (c != ' ') {
                        self.result.version_start_pos = self.result.total_bytes_read - 1;
                        self.result.version_len += 1;
                        self.state = .on_version;
                    } else {
                        return error.BadRequest;
                    }
                },
                .on_version => {
                    if (c == '\r') {
                        self.state = .seen_cr;
                    } else {
                        self.result.version_len += 1;
                        if (self.result.version_len > version_max_len) {
                            return error.BadRequest;
                        }
                    }
                },
                .seen_cr => {
                    if (c == '\n') {
                        self.state = .done;
                        return true;
                    }
                    return error.BadRequest;
                },
                .done => return error.InvalidState,
            }
        }
        return false;
    }
};

const testing = std.testing;
const FieldsEndFinder = @import("fields_end_finder.zig").FieldsEndFinder;

test "RecvRequest - GET method" {
    const method = "GET";
    const uri = "/where?q=now";
    const version = "HTTP/1.1";
    const headers = "Host: www.example.com\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n" ++ headers;

    var splitter = RequestLineSplitter{};
    try testing.expect(try splitter.parse(input));
    var finder = FieldsEndFinder{};
    try testing.expect(try finder.parse(input[splitter.result.total_bytes_read..]));
    try testing.expectEqual(input.len, splitter.result.total_bytes_read + finder.total_bytes_read);

    const allocator = testing.allocator;
    const buf = try allocator.dupe(u8, input);
    var req = try RecvRequest.init(allocator, buf, &splitter.result, finder.total_bytes_read);
    defer req.deinit();

    try testing.expectEqual(Method{ .get = undefined }, req.method);
    try testing.expectEqualStrings(uri, req.uri);
    try testing.expectEqual(try Version.fromText(version), req.version);
    try testing.expectEqualStrings(headers, req.headers);
}

test "RecvRequest - custom method" {
    const method = "PURGE_ALL";
    const uri = "/where?q=now";
    const version = "HTTP/1.1";
    const headers = "Host: www.example.com\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n" ++ headers;

    var splitter = RequestLineSplitter{};
    try testing.expect(try splitter.parse(input));
    var finder = FieldsEndFinder{};
    try testing.expect(try finder.parse(input[splitter.result.total_bytes_read..]));
    try testing.expectEqual(input.len, splitter.result.total_bytes_read + finder.total_bytes_read);

    const allocator = testing.allocator;
    const buf = try allocator.dupe(u8, input);
    var req = try RecvRequest.init(allocator, buf, &splitter.result, finder.total_bytes_read);
    defer req.deinit();

    switch (req.method) {
        .custom => |v| try testing.expectEqualStrings(method, v),
        else => unreachable,
    }
    try testing.expectEqualStrings(uri, req.uri);
    try testing.expectEqual(try Version.fromText(version), req.version);
    try testing.expectEqualStrings(headers, req.headers);
}

test "RequestLineSplitter - whole in one buf" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    var splitter = RequestLineSplitter{};
    try testing.expect(try splitter.parse(input));
    const result = splitter.result;
    try testing.expectEqual(method.len, result.method_len);
    try testing.expectEqual(method.len + 1, result.uri_start_pos);
    try testing.expectEqual(uri.len, result.uri_len);
    try testing.expectEqual(method.len + 1 + uri.len + 1, result.version_start_pos);
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "RequestLineSplitter - one byte at time" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    var splitter = RequestLineSplitter{};
    var i: usize = 0;
    while (i < input.len - 2) : (i += 1) {
        try testing.expect(!try splitter.parse(input[i .. i + 1]));
    }
    try testing.expect(try splitter.parse(input[i..]));
    const result = splitter.result;
    try testing.expectEqual(method.len, result.method_len);
    try testing.expectEqual(method.len + 1, result.uri_start_pos);
    try testing.expectEqual(uri.len, result.uri_len);
    try testing.expectEqual(method.len + 1 + uri.len + 1, result.version_start_pos);
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "RequestLineSplitter - variable length chunks" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    const ends = [_]usize{
        method.len - 1,
        method.len + " ".len + uri.len - 1,
        method.len + " ".len + uri.len + " ".len + version.len - 1,
        input.len,
    };
    var splitter = RequestLineSplitter{};

    var start: usize = 0;
    for (ends) |end| {
        try testing.expect((try splitter.parse(input[start..end])) == (end == input.len));
        start = end;
    }
    const result = splitter.result;
    try testing.expectEqual(method.len, result.method_len);
    try testing.expectEqual(method.len + 1, result.uri_start_pos);
    try testing.expectEqual(uri.len, result.uri_len);
    try testing.expectEqual(method.len + 1 + uri.len + 1, result.version_start_pos);
    try testing.expectEqual(version.len, result.version_len);
    try testing.expectEqual(input.len, result.total_bytes_read);
}

test "RequestLineSplitter - method too long" {
    const method = "PURGE_ALL";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    const method_max_len_test = 7;
    var splitter = RequestLineSplitter{ .method_max_len = method_max_len_test };
    try testing.expectError(error.BadRequest, splitter.parse(input));
    try testing.expectEqual(@as(usize, method_max_len_test + 1), splitter.result.total_bytes_read);
}

test "RequestLineSplitter - URI too long" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    const uri_max_len_test = 12;
    var splitter = RequestLineSplitter{ .uri_max_len = uri_max_len_test };
    try testing.expectError(error.UriTooLong, splitter.parse(input));
    const expected_total_len = method.len + " ".len + uri_max_len_test + 1;
    try testing.expectEqual(expected_total_len, splitter.result.total_bytes_read);
}

test "RequestLineSplitter - version too long" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/3.14";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    var splitter = RequestLineSplitter{};
    try testing.expectError(error.BadRequest, splitter.parse(input));
    const expected_total_len = method.len + " ".len + uri.len + " ".len + "HTTP/1.1".len + 1;
    try testing.expectEqual(expected_total_len, splitter.result.total_bytes_read);
}

test "FieldsEndFinder - whole in one buf" {
    const input = "Host: www.example.com\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var finder = FieldsEndFinder{};
    try testing.expect(try finder.parse(input));
    try testing.expectEqual(input.len, finder.totalBytesRead());
}

test "FieldsEndFinder - splitted case" {
    const input = "Host: www.example.com\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";
    var pos: usize = 0;
    while (pos < input.len) : (pos += 1) {
        var finder = FieldsEndFinder{};
        try testing.expect(!try finder.parse(input[0..pos]));
        try testing.expectEqual(pos, finder.totalBytesRead());
        try testing.expect(try finder.parse(input[pos..]));
        try testing.expectEqual(input.len, finder.totalBytesRead());
    }
}
