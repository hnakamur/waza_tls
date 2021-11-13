const std = @import("std");

pub const Field = struct {
    line: []const u8,
    colon_pos: usize,

    pub fn name(self: *const Field) []const u8 {
        return self.line[0..self.colon_pos];
    }

    // return a single header line's value.
    // https://www.ietf.org/archive/id/draft-ietf-httpbis-semantics-19.html#appendix-B.2-6
    pub fn lineValue(self: *const Field) []const u8 {
        return std.mem.trim(u8, self.line[self.colon_pos + 1 ..], &[_]u8{ ' ', '\t' });
    }

    pub const ValueCommaIterator = struct {
        buf: []const u8,
        pos: usize = 0,

        pub fn next(self: *ValueCommaIterator) ?[]const u8 {

        }
    };

    pub fn valueCommaIterator(self: *const Field) ValueCommaIterator {
        return .{ .buf = self.lineValue() };
    }
};

