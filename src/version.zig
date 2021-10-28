const std = @import("std");

pub const Version = enum {
    http0_9,
    http1_0,
    http1_1,
    http2,
    http3,

    pub fn fromText(input: []const u8) !Version {
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

    pub fn toText(self: Version) []const u8 {
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
    try testing.expectEqual(Version.http0_9, try Version.fromText("HTTP/0.9"));
    try testing.expectEqual(Version.http1_0, try Version.fromText("HTTP/1.0"));
    try testing.expectEqual(Version.http1_1, try Version.fromText("HTTP/1.1"));
    try testing.expectEqual(Version.http2, try Version.fromText("HTTP/2"));
    try testing.expectEqual(Version.http3, try Version.fromText("HTTP/3"));
    try testing.expectError(error.BadVersion, Version.fromText("HTTP/1.1 "));
}
