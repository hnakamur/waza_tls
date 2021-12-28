const std = @import("std");
const Hash = @import("Hash.zig");

pub fn HashAdapter(comptime HashImpl: type) type {
    return struct {
        const Self = @This();

        inner_hash: HashImpl,

        pub fn init(inner_hash: HashImpl) Self {
            return .{ .inner_hash = inner_hash };
            // return .{ .inner_hash = HashImpl.init(.{}) };
        }

        pub fn hash(self: *Self) Hash {
            return Hash.init(self, update, writeFinal);
        }

        fn update(self: *Self, b: []const u8) void {
            self.inner_hash.update(b);
        }

        fn writeFinal(self: *Self, writer: anytype) !usize {
            var d_out: [HashImpl.digest_length]u8 = undefined;
            self.inner_hash.final(&d_out);
            try writer.writeAll(&d_out);
            return d_out.len;
        }
    };
}

const testing = std.testing;

test "Hash Sha256" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const Sha256Hash = HashAdapter(Sha256);

    // var hh = Sha256Hash.init();
    var hh = Sha256Hash.init(Sha256.init(.{}));
    var h = hh.hash();
    h.update("hello");
    const digest_len = Sha256Hash.Sha256.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(digest_len, bytes_written);
    std.log.debug("hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});
}
