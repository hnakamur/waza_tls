const constantTimeEqlBytes = @import("constant_time.zig").constantTimeEqlBytes;

// Equal compares two MACs for equality without leaking timing information.
pub fn equal(mac1: []const u8, mac2: []const u8) bool {
    // We don't have to be constant time if the lengths of the MACs are
    // different as that suggests that a completely different hash function
    // was used.
    return constantTimeEqlBytes(mac1, mac2) == 1;
}
