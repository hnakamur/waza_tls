const std = @import("std");

const pkgs = struct {
    const http = std.build.Pkg{
        .name = "http",
        .path = "./src/main.zig",
        .dependencies = &[_]std.build.Pkg{
            @"tigerbeetle-io",
        },
    };

    const @"tigerbeetle-io" = std.build.Pkg{
        .name = "tigerbeetle-io",
        .path = "./lib/tigerbeetle-io/src/main.zig",
    };

    const datetime = std.build.Pkg{
        .name = "datetime",
        .path = "./lib/zig-datetime/src/main.zig",
    };
};

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("http", "src/main.zig");
    lib.addPackage(pkgs.@"tigerbeetle-io");
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    main_tests.addPackage(pkgs.@"tigerbeetle-io");
    main_tests.setBuildMode(mode);
    main_tests.filter = b.option([]const u8, "test-filter", "Skip tests that do not match filter");

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
        example.addPackage(pkgs.http);
        example.addPackage(pkgs.@"tigerbeetle-io");
        example.addPackage(pkgs.datetime);
        example.setBuildMode(mode);
        example.setTarget(target);
        example.install();
        example_step.dependOn(&example.step);
    }
}
