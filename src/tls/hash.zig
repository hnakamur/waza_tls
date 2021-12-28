const std = @import("std");
const assert = std.debug.assert;

pub const Hash = struct {
    const Self = @This();

    // The type erased pointer to the allocator implementation
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        update: fn (ptr: *anyopaque, b: []const u8) void,
        writeFinal: fn (ptr: *anyopaque, writer: anytype) anyerror!usize,
    };

    pub fn init(
        pointer: anytype,
        comptime updateFn: fn (ptr: @TypeOf(pointer), b: []const u8) void,
        comptime writeFinalFn: fn (ptr: @TypeOf(pointer), writer: anytype) anyerror!usize,
    ) Hash {
        const Ptr = @TypeOf(pointer);
        const ptr_info = @typeInfo(Ptr);

        assert(ptr_info == .Pointer); // Must be a pointer
        assert(ptr_info.Pointer.size == .One); // Must be a single-item pointer

        const alignment = ptr_info.Pointer.alignment;

        const gen = struct {
            fn updateImpl(ptr: *anyopaque, b: []const u8) void {
                const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                @call(.{ .modifier = .always_inline }, updateFn, .{ self, b });
            }
            fn writeFinalImpl(ptr: *anyopaque, writer: anytype) anyerror!usize {
                const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                return @call(.{ .modifier = .always_inline }, writeFinalFn, .{ self, writer });
            }

            const vtable = VTable{
                .update = updateImpl,
                .writeFinal = writeFinalImpl,
            };
        };

        return .{
            .ptr = pointer,
            .vtable = &gen.vtable,
        };
    }

    pub inline fn update(self: Hash, b: []const u8) void {
        self.vtable.update(self.ptr, b);
    }

    pub inline fn writeFinal(self: Hash, writer: anytype) anyerror!usize {
        return self.vtable.writeFinal(self.ptr, writer);
    }
};

pub fn HashAdapter(comptime HashImpl: type) type {
    return struct {
        const Self = @This();

        inner_hash: HashImpl,

        fn init() Self {
            return .{ .inner_hash = HashImpl.init(.{}) };
        }

        fn hash(self: *Self) Hash {
            return Hash.init(self, update_, writeFinal_);
        }

        fn update_(self: *Self, b: []const u8) void {
            self.inner_hash.update(b);
        }

        fn writeFinal_(self: *Self, writer: anytype) !usize {
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

    var hh = Sha256Hash.init();
    var h = hh.hash();
    h.update("hello");
    const digest_len = Sha256Hash.Sha256.digest_length;
    var out: [digest_len]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&out);
    const bytes_written = try h.writeFinal(fbs.writer());
    try testing.expectEqual(digest_len, bytes_written);
    std.log.debug("hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});
}

// test "Hash Sha256" {
//     const Sha256Hash = struct {
//         const Self = @This();
//         const Sha256 = std.crypto.hash.sha2.Sha256;
//         inner_hash: Sha256,

//         fn init() Self {
//             return .{ .inner_hash = Sha256.init(.{}) };
//         }

//         fn hash(self: *Self) Hash {
//             return Hash.init(self, update_, writeFinal_);
//         }

//         fn update_(self: *Self, b: []const u8) void {
//             self.inner_hash.update(b);
//         }

//         fn writeFinal_(self: *Self, writer: anytype) !usize {
//             var d_out: [Sha256.digest_length]u8 = undefined;
//             self.inner_hash.final(&d_out);
//             try writer.writeAll(&d_out);
//             return d_out.len;
//         }
//     };

//     var hh = Sha256Hash.init();
//     var h = hh.hash();
//     h.update("hello");
//     const digest_len = Sha256Hash.Sha256.digest_length;
//     var out: [digest_len]u8 = undefined;
//     var fbs = std.io.fixedBufferStream(&out);
//     const bytes_written = try h.writeFinal(fbs.writer());
//     try testing.expectEqual(digest_len, bytes_written);
//     std.log.debug("hash={}\n", .{std.fmt.fmtSliceHexLower(&out)});
// }
