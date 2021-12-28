const std = @import("std");

const Hash = union(enum) {
    Sha256: Sha256Hash,
    Sha384: Sha384Hash,

    fn update(self: *Hash, b: []const u8) void {
        switch (self.*) {
            .Sha256 => |*s| s.update(b),
            .Sha384 => |*s| s.update(b),
        }
    }

    fn writeFinal(self: *Hash, writer: anytype) !usize {
        return switch (self.*) {
            .Sha256 => |*s| try s.writeFinal(writer),
            .Sha384 => |*s| try s.writeFinal(writer),
        };
    }
};

const Sha256Hash = HashAdapter(std.crypto.hash.sha2.Sha256);
const Sha384Hash = HashAdapter(std.crypto.hash.sha2.Sha384);

fn HashAdapter(comptime HashImpl: type) type {
    return struct {
        const Self = @This();

        pub const digest_length = HashImpl.digest_length;
        inner_hash: HashImpl,

        fn init(options: HashImpl.Options) Self {
            return .{ .inner_hash = HashImpl.init(options) };
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

test "Hash.Sha256" {
    testing.log_level = .debug;

    var h = Hash{ .Sha256 = Sha256Hash.init(.{}) };
    h.update("hello");
    const digest_len = Sha256Hash.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(digest_len, bytes_written);
    std.log.debug("Sha256Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});
}

test "Hash.Sha384" {
    testing.log_level = .debug;

    var h = Hash{ .Sha384 = Sha384Hash.init(.{}) };
    h.update("hello");
    const digest_len = Sha384Hash.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(digest_len, bytes_written);
    std.log.debug("Sha384Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});
}
