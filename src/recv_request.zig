const std = @import("std");
const mem = std.mem;
const Method = @import("method.zig").Method;
const Version = @import("version.zig").Version;
const isTokenChar = @import("token_char.zig").isTokenChar;
const config = @import("config.zig");

/// A receiving request.
pub const RecvRequest = struct {
    method: Method,
    uri: []const u8,
    version: Version,
    headers: []const u8,
    allocator: *mem.Allocator,

    // value of custom `method`, `uri`, and `headers` must be allocated with `allocator`.
    // they are freed in `deinit`.
    pub fn init(allocator: *mem.Allocator, method: Method, uri: []const u8, version: Version, headers: []const u8) RecvRequest {
        return .{
            .method = method,
            .uri = uri,
            .version = version,
            .headers = headers,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RecvRequest) void {
        self.allocator.free(self.headers);
        self.allocator.free(self.uri);
        switch (self.method) {
            .custom => |value| self.allocator.free(value),
            else => {},
        }
    }
};

const version_max_len: usize = Version.http1_1.toText().len;

const RequestLineParser = struct {
    const State = enum {
        on_method,
        post_method,
        on_uri,
        post_uri,
        on_version,
        seen_cr,
        done,
    };

    method_max_len: usize = config.method_max_len,
    uri_max_len: usize = config.uri_max_len,

    state: State = .on_method,
    total_bytes_read: usize = 0,
    method_len: usize = 0,
    uri_len: usize = 0,
    version_len: usize = 0,

    pub fn parse(self: *RequestLineParser, chunk: []const u8) !bool {
        var uri_start_pos: usize = 0;
        var version_start_pos: usize = 0;
        var pos: usize = 0;
        while (pos < chunk.len) {
            const c = chunk[pos];
            pos += 1;
            switch (self.state) {
                .on_method => {
                    if (c == ' ') {
                        self.method_len = self.total_bytes_read + pos - 1;
                        self.state = .post_method;
                    } else if (!isTokenChar(c) or self.total_bytes_read + pos > self.method_max_len) {
                        self.total_bytes_read += pos;
                        return error.BadRequest;
                    }
                },
                .post_method => {
                    if (c != ' ') {
                        uri_start_pos = pos - 1;
                        self.state = .on_uri;
                    } else {
                        self.total_bytes_read += pos;
                        return error.BadRequest;
                    }
                },
                .on_uri => {
                    if (c == ' ') {
                        self.state = .post_uri;
                        self.uri_len += pos - 1 - uri_start_pos;
                    } else if (self.uri_len + pos - uri_start_pos > self.uri_max_len) {
                        self.total_bytes_read += pos;
                        return error.UriTooLong;
                    }
                },
                .post_uri => {
                    if (c != ' ') {
                        version_start_pos = pos - 1;
                        self.state = .on_version;
                    } else {
                        self.total_bytes_read += pos;
                        return error.BadRequest;
                    }
                },
                .on_version => {
                    if (c == '\r') {
                        self.version_len += pos - 1 - version_start_pos;
                        self.state = .seen_cr;
                    } else if (self.version_len + pos - version_start_pos > version_max_len) {
                        self.total_bytes_read += pos;
                        return error.BadRequest;
                    }
                },
                .seen_cr => {
                    self.total_bytes_read += pos;
                    return if (c == '\n') true else error.BadRequest;
                },
                .done => return error.InvalidState,
            }
        }
        self.total_bytes_read += chunk.len;
        switch (self.state) {
            .on_uri => self.uri_len += pos - uri_start_pos,
            .on_version => self.version_len += pos - version_start_pos,
            else => {},
        }
        return false;
    }

    pub fn totalBytesRead(self: *const RequestLineParser) usize {
        return self.total_bytes_read;
    }
};

const FieldSectionEndFinder = struct {
    const State = enum {
        initial,
        seen_cr,
        seen_cr_lf,
        seen_cr_lf_cr,
        seen_cr_lf_cr_lf,
    };

    state: State = .initial,
    total_bytes_read: usize = 0,

    pub fn reachesToEnd(self: *FieldSectionEndFinder, buf: []const u8) !bool {
        var pos: usize = 0;
        while (pos < buf.len) {
            switch (self.state) {
                .initial => {
                    if (std.mem.indexOfScalarPos(u8, buf, pos, '\r')) |cr_pos| {
                        self.state = .seen_cr;
                        pos = cr_pos + "\r".len;
                    } else {
                        self.total_bytes_read += buf.len;
                        return false;
                    }
                },
                .seen_cr => {
                    if (buf[pos] == '\n') {
                        self.state = .seen_cr_lf;
                        pos += 1;
                    } else {
                        self.total_bytes_read += pos + 1;
                        return error.InvalidInput;
                    }
                },
                .seen_cr_lf => {
                    self.state = if (buf[pos] == '\r') .seen_cr_lf_cr else .initial;
                    pos += 1;
                },
                .seen_cr_lf_cr => {
                    if (buf[pos] == '\n') {
                        self.state = .seen_cr_lf_cr_lf;
                        self.total_bytes_read += pos + 1;
                        return true;
                    } else {
                        self.total_bytes_read += pos + 1;
                        return error.InvalidInput;
                    }
                },
                .seen_cr_lf_cr_lf => return error.InvalidState,
            }
        }
        self.total_bytes_read += buf.len;
        return false;
    }

    pub fn totalBytesRead(self: *const FieldSectionEndFinder) usize {
        return self.total_bytes_read;
    }
};

const testing = std.testing;

test "RcvRequest - GET method" {
    const allocator = testing.allocator;
    const method = Method{ .get = undefined };
    const uri = try allocator.dupe(u8, "http://www.example.org/where?q=now");
    const headers = try allocator.dupe(u8, "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n");
    var req = RecvRequest.init(allocator, method, uri, Version.http1_1, headers);
    defer req.deinit();
}

test "RcvRequest - custom method" {
    const allocator = testing.allocator;
    const method = Method{ .custom = try allocator.dupe(u8, "PURGE_ALL") };
    const uri = try allocator.dupe(u8, "http://www.example.org/where?q=now");
    const headers = try allocator.dupe(u8, "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n");
    var req = RecvRequest.init(allocator, method, uri, Version.http1_1, headers);
    defer req.deinit();
}

test "RequestLineParser - whole in one buf" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    var parser = RequestLineParser{};
    try testing.expect(try parser.parse(input));
    try testing.expectEqual(method.len, parser.method_len);
    try testing.expectEqual(uri.len, parser.uri_len);
    try testing.expectEqual(version.len, parser.version_len);
    try testing.expectEqual(input.len, parser.totalBytesRead());
}

test "RequestLineParser - one byte at time" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    var parser = RequestLineParser{};
    var i: usize = 0;
    while (i < input.len - 2) : (i += 1) {
        try testing.expect(!try parser.parse(input[i .. i + 1]));
    }
    try testing.expect(try parser.parse(input[i..]));
    try testing.expectEqual(method.len, parser.method_len);
    try testing.expectEqual(uri.len, parser.uri_len);
    try testing.expectEqual(version.len, parser.version_len);
    try testing.expectEqual(input.len, parser.totalBytesRead());
}

test "RequestLineParser - variable length chunks" {
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
    var parser = RequestLineParser{};

    var start: usize = 0;
    for (ends) |end| {
        try testing.expect((try parser.parse(input[start..end])) == (end == input.len));
        start = end;
    }
    try testing.expectEqual(method.len, parser.method_len);
    try testing.expectEqual(uri.len, parser.uri_len);
    try testing.expectEqual(version.len, parser.version_len);
    try testing.expectEqual(input.len, parser.totalBytesRead());
}

test "RequestLineParser - method too long" {
    const method = "PURGE_ALL";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    const method_max_len_test = 7;
    var parser = RequestLineParser{ .method_max_len = method_max_len_test };
    try testing.expectError(error.BadRequest, parser.parse(input));
    try testing.expectEqual(@as(usize, method_max_len_test + 1), parser.totalBytesRead());
}

test "RequestLineParser - URI too long" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/1.1";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    const uri_max_len_test = 12;
    var parser = RequestLineParser{ .uri_max_len = uri_max_len_test };
    try testing.expectError(error.UriTooLong, parser.parse(input));
    try testing.expectEqual(@as(usize, method.len + " ".len + uri_max_len_test + 1), parser.totalBytesRead());
}

test "RequestLineParser - version too long" {
    const method = "GET";
    const uri = "http://www.example.org/where?q=now";
    const version = "HTTP/3.14";
    const input = method ++ " " ++ uri ++ " " ++ version ++ "\r\n";

    var parser = RequestLineParser{};
    try testing.expectError(error.BadRequest, parser.parse(input));
    try testing.expectEqual(@as(usize, method.len + " ".len + uri.len + " ".len + version_max_len + 1), parser.totalBytesRead());
}

test "FieldSectionEndFinder - whole in one buf" {
    const input = "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "\r\n";
    var finder = FieldSectionEndFinder{};
    try testing.expect(try finder.reachesToEnd(input));
    try testing.expectEqual(input.len, finder.totalBytesRead());
}

test "FieldSectionEndFinder - splitted case" {
    const input = "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    var pos: usize = 0;
    while (pos < input.len) : (pos += 1) {
        var finder = FieldSectionEndFinder{};
        try testing.expect(!try finder.reachesToEnd(input[0..pos]));
        try testing.expectEqual(pos, finder.totalBytesRead());
        try testing.expect(try finder.reachesToEnd(input[pos..]));
        try testing.expectEqual(input.len, finder.totalBytesRead());
    }
}
