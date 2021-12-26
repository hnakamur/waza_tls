const std = @import("std");
const BytesView = @import("../BytesView.zig");

test "foo" {
    var v = BytesView.init("hello");
    std.debug.print("v={}\n", .{v});
}
