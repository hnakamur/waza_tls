const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const HashType = @import("auth.zig").HashType;

pub const Hash = union(HashType) {
    sha256: Sha256Hash,
    sha384: Sha384Hash,
    sha512: Sha512Hash,
    sha1: Sha1Hash,
    direct_signing: void,

    pub fn init(hash_type: HashType) Hash {
        return switch (hash_type) {
            .sha256 => .{ .sha256 = Sha256Hash.init(.{}) },
            .sha384 => .{ .sha384 = Sha384Hash.init(.{}) },
            .sha512 => .{ .sha512 = Sha512Hash.init(.{}) },
            .sha1 => .{ .sha1 = Sha1Hash.init(.{}) },
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn update(self: *Hash, b: []const u8) void {
        switch (self.*) {
            .sha256 => |*s| s.update(b),
            .sha384 => |*s| s.update(b),
            .sha512 => |*s| s.update(b),
            .sha1 => |*s| s.update(b),
            else => @panic("Unsupported HashType"),
        }
    }

    pub fn writeFinal(self: *Hash, writer: anytype) !usize {
        return switch (self.*) {
            .sha256 => |*s| try s.writeFinal(writer),
            .sha384 => |*s| try s.writeFinal(writer),
            .sha512 => |*s| try s.writeFinal(writer),
            .sha1 => |*s| try s.writeFinal(writer),
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn finalToSlice(self: *Hash, out: []u8) usize {
        return switch (self.*) {
            .sha256 => |*s| s.finalToSlice(out),
            .sha384 => |*s| s.finalToSlice(out),
            .sha512 => |*s| s.finalToSlice(out),
            .sha1 => |*s| s.finalToSlice(out),
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn digestLength(self: *const Hash) usize {
        return switch (self.*) {
            .sha256 => |s| s.digestLength(),
            .sha384 => |s| s.digestLength(),
            .sha512 => |s| s.digestLength(),
            .sha1 => |s| s.digestLength(),
            else => @panic("Unsupported HashType"),
        };
    }

    pub fn allocFinal(self: *Hash, allocator: mem.Allocator) ![]const u8 {
        return switch (self.*) {
            .sha256 => |*s| try s.allocFinal(allocator),
            .sha384 => |*s| try s.allocFinal(allocator),
            .sha512 => |*s| try s.allocFinal(allocator),
            .sha1 => |*s| try s.allocFinal(allocator),
            else => @panic("Unsupported HashType"),
        };
    }
};

pub const Sha256Hash = HashAdapter(std.crypto.hash.sha2.Sha256);
pub const Sha384Hash = HashAdapter(std.crypto.hash.sha2.Sha384);
pub const Sha512Hash = HashAdapter(std.crypto.hash.sha2.Sha512);
pub const Sha1Hash = HashAdapter(std.crypto.hash.Sha1);

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
            self.inner_hash.final(out[0..len]);
            return len;
        }

        pub fn digestLength(self: *const Self) usize {
            _ = self;
            return digest_length;
        }

        pub fn allocFinal(self: *Self, allocator: mem.Allocator) ![]const u8 {
            var sum = try allocator.alloc(u8, digest_length);
            const sum_len = self.finalToSlice(sum);
            assert(sum_len == digest_length);
            return sum;
        }
    };
}

const testing = std.testing;

test "Hash.Sha256" {
    var h = Hash{ .sha256 = Sha256Hash.init(.{}) };
    h.update("hello");
    const digest_len = Sha256Hash.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(digest_len, bytes_written);
    std.log.debug("Sha256Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});

    var h2 = Hash{ .sha256 = Sha256Hash.init(.{}) };
    h2.update("hello");
    var out2 = [_]u8{0} ** (digest_len + 4);
    const bytes_written2 = h2.finalToSlice(&out2);
    try testing.expectEqual(digest_len, bytes_written2);
    std.log.debug("Sha256Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out2)});
}

test "Hash.Sha384" {
    var h = Hash{ .sha384 = Sha384Hash.init(.{}) };
    h.update("hello");
    const digest_len = Sha384Hash.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(digest_len, bytes_written);
    std.log.debug("Sha384Hash hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});
}
