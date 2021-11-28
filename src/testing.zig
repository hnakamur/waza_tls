const std = @import("std");

pub fn expectNoError(
    var_name: []const u8,
    result: anytype,
) error{TestExpectedError}!void {
    if (result) |_| {} else |err| {
        std.debug.print("{s} should not be an error, but got an error: {s}\n", .{
            var_name,
            @errorName(err),
        });
        return error.TestExpectedError;
    }
}
