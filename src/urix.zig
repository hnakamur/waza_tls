const std = @import("std");
const mem = std.mem;
const uri = @import("uri");

pub const Uri = struct {
    raw: []const u8 = "",
    components: uri.UriComponents,

    pub const ParseError = mem.Allocator.Error || uri.ParseError;

    pub fn parse(allocator: mem.Allocator, input: []const u8) ParseError!Uri {
        const raw = try allocator.dupe(u8, input);
        errdefer allocator.free(raw);
        const components = try uri.parse(raw);
        return Uri{
            .raw = raw,
            .components = components,
        };
    }

    pub fn deinit(self: *Uri, allocator: mem.Allocator) void {
        allocator.free(self.raw);
    }

    pub fn format(
        self: Uri,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        _ = try writer.write(self.raw);
    }
};

const testing = std.testing;

test "Uri.parse" {
    const allocator = testing.allocator;
    var u = try Uri.parse(allocator, "https://[2001:db8::1]:8443/foo");
    defer u.deinit(allocator);
    try testing.expectEqualStrings("https", u.components.scheme.?);
    try testing.expectEqualStrings("[2001:db8::1]", u.components.host.?);
    try testing.expectEqual(@as(u16, 8443), u.components.port.?);
    try testing.expectEqualStrings("/foo", u.components.path);

    const host = u.components.host.?;
    var ip = try std.net.Address.parseIp(mem.trim(u8, host, "[]"), u.components.port.?);
    var want = std.net.Address.initIp6(
        ("\x20\x01\x0d\xb8" ++ "\x00" ** 11 ++ "\x01")[0..16].*,
        8443,
        0,
        0,
    );
    try testing.expectEqual(want.in6, ip.in6);
}
