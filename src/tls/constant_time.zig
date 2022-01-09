const std = @import("std");

// constantTimeEqlBytes returns 1 if the two slices, x and y, have equal contents
// and 0 otherwise. The time taken is a function of the length of the slices and
// is independent of the contents.
pub fn constantTimeEqlBytes(x: []const u8, y: []const u8) u32 {
    if (x.len != y.len) {
        return 0;
    }

    var i: usize = 0;
    var v: u8 = 0;
    while (i < x.len) : (i += 1) {
        v |= x[i] ^ y[i];
    }
    return constantTimeEqlByte(v, 0);
}

// constantTimeByteEq returns 1 if x == y and 0 otherwise.
fn constantTimeEqlByte(x: u8, y: u8) u32 {
    return (@intCast(u32, x ^ y) -% 1) >> 31;
}

const testing = std.testing;

test "constantTimeEqlBytes" {
    try testing.expectEqual(@as(u32, 1), constantTimeEqlBytes("hello", "hello"));
    try testing.expectEqual(@as(u32, 0), constantTimeEqlBytes("hello", "hell"));
    try testing.expectEqual(@as(u32, 0), constantTimeEqlBytes("hello", "goodbye"));
}

test "constantTimeEqlByte" {
    var x: u8 = 0;
    var y: u8 = 0;
    while (true) : (x += 1) {
        while (true) : (y += 1) {
            try testing.expectEqual(x == y, constantTimeEqlByte(x, y) == 1);
            if (y == 255) break;
        }
        if (x == 255) break;
    }
}
