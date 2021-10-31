const std = @import("std");
const pkgs = @import("deps.zig").pkgs;

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("http", "src/main.zig");
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const example_step = b.step("examples", "Build examples");
    inline for (.{
        "async_http_client",
        "async_http_server",
        "http_client",
        "http_server",
    }) |example_name| {
        const example = b.addExecutable(example_name, "examples/" ++ example_name ++ ".zig");
        example.addPackagePath("http", "src/main.zig");
        example.setBuildMode(mode);
        example.setTarget(target);
        pkgs.addAllTo(example);
        example.install();
        example_step.dependOn(&example.step);
    }
}
