const std = @import("std");

pub const Version = enum {
    http0_9,
    http1_0,
    http1_1,
    http2,
    http3,

    pub fn fromBytes(input: []const u8) !Version {
        if (std.mem.startsWith(u8, input, "HTTP/")) {
            const v: []const u8 = input["HTTP/".len..];
            if (v.len == 1) {
                if (v[0] == '2') return .http2;
                if (v[0] == '3') return .http3;
            } else if (v.len == 3 and v[1] == '.') {
                if (v[0] == '1') {
                    if (v[2] == '1') return .http1_1;
                    if (v[2] == '0') return .http1_0;
                } else if (v[0] == '0' and v[2] == '9') return .http0_9;
            }
        }
        return error.BadVersion;
    }

    pub fn toBytes(self: Version) []const u8 {
        return switch (self) {
            .http0_9 => "HTTP/0.9",
            .http1_0 => "HTTP/1.0",
            .http1_1 => "HTTP/1.1",
            .http2 => "HTTP/2",
            .http3 => "HTTP/3",
        };
    }
};

const testing = std.testing;

test "http.Version" {
    try testing.expectEqual(Version.http0_9, try Version.fromBytes("HTTP/0.9"));
    try testing.expectEqual(Version.http1_0, try Version.fromBytes("HTTP/1.0"));
    try testing.expectEqual(Version.http1_1, try Version.fromBytes("HTTP/1.1"));
    try testing.expectEqual(Version.http2, try Version.fromBytes("HTTP/2"));
    try testing.expectEqual(Version.http3, try Version.fromBytes("HTTP/3"));
    try testing.expectError(error.BadVersion, Version.fromBytes("HTTP/1.1 "));

    try testing.expectEqualStrings("HTTP/0.9", Version.http0_9.toBytes());
    try testing.expectEqualStrings("HTTP/1.0", Version.http1_0.toBytes());
    try testing.expectEqualStrings("HTTP/1.1", Version.http1_1.toBytes());
    try testing.expectEqualStrings("HTTP/2", Version.http2.toBytes());
    try testing.expectEqualStrings("HTTP/3", Version.http3.toBytes());
}
