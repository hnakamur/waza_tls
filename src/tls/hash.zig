const std = @import("std");

pub const Hash = union(enum) {
    Sha256: Sha256Hash,
    Sha384: Sha384Hash,

    pub fn update(self: *Hash, b: []const u8) void {
        switch (self.*) {
            .Sha256 => |*s| s.update(b),
            .Sha384 => |*s| s.update(b),
        }
    }

    pub fn writeFinal(self: *Hash, writer: anytype) !usize {
        return switch (self.*) {
            .Sha256 => |*s| try s.writeFinal(writer),
            .Sha384 => |*s| try s.writeFinal(writer),
        };
    }

    pub fn finalToSlice(self: *Hash, out: []u8) usize {
        return switch (self.*) {
            .Sha256 => |*s| s.finalToSlice(out),
            .Sha384 => |*s| s.finalToSlice(out),
        };
    }

    pub fn digestLength(self: *const Hash) usize {
        return switch (self.*) {
            .Sha256 => |s| s.digestLength(),
            .Sha384 => |s| s.digestLength(),
        };
    }
};

pub const Sha256Hash = HashAdapter(std.crypto.hash.sha2.Sha256);
pub const Sha384Hash = HashAdapter(std.crypto.hash.sha2.Sha384);

fn HashAdapter(comptime HashImpl: type) type {
    return struct {
        const Self = @This();

        pub const digest_length = HashImpl.digest_length;
        inner_hash: HashImpl,

        pub fn init(options: HashImpl.Options) Self {
            return .{ .inner_hash = HashImpl.init(options) };
        }

        pub fn update(self: *Self, b: []const u8) void {
            self.inner_hash.update(b);
        }

        pub fn writeFinal(self: *Self, writer: anytype) !usize {
            var d_out: [HashImpl.digest_length]u8 = undefined;
            self.inner_hash.final(&d_out);
            try writer.writeAll(&d_out);
            return d_out.len;
        }

        pub fn finalToSlice(self: *Self, out: []u8) usize {
            const len = HashImpl.digest_length;
            std.debug.print("finalToSlice, HashImpl={s}, len={}\n", .{ @typeName(HashImpl), len });
            self.inner_hash.final(out[0..len]);
            return len;
        }

        pub fn digestLength(self: *const Self) usize {
            _ = self;
            return digest_length;
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

    var h2 = Hash{ .Sha256 = Sha256Hash.init(.{}) };
    h2.update("hello");
    var out2 = [_]u8{0} ** (digest_len + 4);
    const bytes_written2 = h2.finalToSlice(&out2);
    try testing.expectEqual(digest_len, bytes_written2);
    std.log.debug("Sha256Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out2)});
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
