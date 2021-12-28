const std = @import("std");
const Hash = @import("hash.zig").Hash;

const Sha256Hash = struct {
    const Self = @This();
    const Sha256 = std.crypto.hash.sha2.Sha256;
    inner_hash: Sha256,

    pub fn init() Self {
        return .{ .inner_hash = Sha256.init(.{}) };
    }

    pub fn hash(self: *Self) Hash {
        return Hash.init(self, update, writeFinal);
    }

    pub fn update(self: *Self, b: []const u8) void {
        self.inner_hash.update(b);
    }

    pub fn writeFinal(self: *Self, writer: anytype) !usize {
        var d_out: [Sha256.digest_length]u8 = undefined;
        self.inner_hash.final(&d_out);
        try writer.writeAll(&d_out);
        return d_out.len;
    }
};

const testing = std.testing;

test "Hash Sha256" {
    var hh = Sha256Hash.init();
    var h = hh.hash();
    h.update("hello");
    const digest_len = Sha256Hash.Sha256.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(@as(usize, digest_len), bytes_written);
    std.log.debug("hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});
}
