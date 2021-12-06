pub fn scoped(comptime scope: @Type(.EnumLiteral)) type {
    _ = scope;
    return struct {
        pub fn emerg(
            comptime format: []const u8,
            args: anytype,
        ) void {}

        pub fn alert(
            comptime format: []const u8,
            args: anytype,
        ) void {}

        pub fn crit(
            comptime format: []const u8,
            args: anytype,
        ) void {}

        pub fn err(
            comptime format: []const u8,
            args: anytype,
        ) void {}

        pub fn warn(
            comptime format: []const u8,
            args: anytype,
        ) void {}

        pub fn notice(
            comptime format: []const u8,
            args: anytype,
        ) void {}

        pub fn info(
            comptime format: []const u8,
            args: anytype,
        ) void {}

        pub fn debug(
            comptime format: []const u8,
            args: anytype,
        ) void {}
    };
}
