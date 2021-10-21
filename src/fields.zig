const std = @import("std");

pub const Field = struct {
    line: []const u8,
    colonPos: usize,

    pub fn name(self: *const Field) []const u8 {
        return self.line[0..self.colonPos];
    }

    pub fn value(self: *const Field) []const u8 {
        return std.mem.trim(u8, self.line[self.colonPos + 1 ..], " \t");
    }
};
