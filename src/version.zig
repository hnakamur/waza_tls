const std = @import("std");

pub const Version = enum {
    http09,
    http10,
    http11,
    http2,
    http3,

    pub fn fromText(input: []const u8) ?Version {
        if (std.mem.startsWith(u8, input, "HTTP/")) {
            const v: []const u8 = input["HTTP/".len..];
            if (v.len == 1) {
                if (v[0] == '2') return .http2;
                if (v[0] == '3') return .http3;
            } else if (v.len == 3 and v[1] == '.') {
                if (v[0] == '1') {
                    if (v[2] == '1') return .http11;
                    if (v[2] == '0') return .http10;
                } else if (v[0] == '0' and v[2] == '9') return .http09;
            }
        }
        return null;
    }

    pub fn toText(self: Version) []const u8 {
        return switch (self) {
            .http09 => "HTTP/0.9",
            .http10 => "HTTP/1.0",
            .http11 => "HTTP/1.1",
            .http2 => "HTTP/2",
            .http3 => "HTTP/3",
        };        
    }
};

const testing = std.testing;

test "http.Version" {
    try testing.expectEqual(Version.http09, Version.fromText("HTTP/0.9").?);
    try testing.expectEqual(Version.http10, Version.fromText("HTTP/1.0").?);
    try testing.expectEqual(Version.http11, Version.fromText("HTTP/1.1").?);
    try testing.expectEqual(Version.http2, Version.fromText("HTTP/2").?);
    try testing.expectEqual(Version.http3, Version.fromText("HTTP/3").?);
    try testing.expect(Version.fromText("HTTP/1.1 ") == null);
}
