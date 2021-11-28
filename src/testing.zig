const std = @import("std");

pub fn expectNoError(result: anytype) error{TestExpectedError}!void {
    if (result) |_| {} else |err| {
        std.debug.print("expected no error, found {s}\n", .{@errorName(err)});
        return error.TestExpectedError;
    }
}
