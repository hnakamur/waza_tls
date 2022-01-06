const std = @import("std");
const mem = std.mem;
const CipherSuite = @import("cipher_suites.zig").CipherSuite;

pub const HalfConn = struct {
    cipher: ?CipherSuite = null,

    pub fn encrypt(
        self: *HalfConn,
        allocator: mem.Allocator,
        record: []u8,
        payload: []const u8,
    ) ![]const u8 {
        if (self.cipher) |_| {} else {
            var ret = try allocator.realloc(record, record.len + payload.len);
            mem.copy(u8, ret[record.len..], payload);
            return ret;
        }

        @panic("not implemented yet");
    }
};

const testing = std.testing;

test "HalfConn.encrypt" {
    const allocator = testing.allocator;

    var record = try allocator.dupe(u8, "hello, ");
    errdefer allocator.free(record);
    var hc = HalfConn{};
    const record2 = try hc.encrypt(allocator, record, "world");
    defer allocator.free(record2);

    try testing.expectEqualStrings("hello, world", record2);
}
