const std = @import("std");

const pkgs = struct {
    const hutaback = std.build.Pkg{
        .name = "hutaback",
        .source = .{ .path = "./src/main.zig" },
        .dependencies = &[_]std.build.Pkg{
            datetime,
            uri,
        },
    };

    const datetime = std.build.Pkg{
        .name = "datetime",
        .source = .{ .path = "./lib/zig-datetime/src/main.zig" },
    };

    const uri = std.build.Pkg{
        .name = "uri",
        .source = .{ .path = "./lib/zig-uri/uri.zig" },
    };
};

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    // const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("hutaback", "src/main.zig");
    lib.addPackage(pkgs.datetime);
    lib.setBuildMode(mode);
    lib.install();

    // test filter
    const test_filter = b.option([]const u8, "test-filter", "Skip tests that do not match filter");

    const coverage = b.option(bool, "test-coverage", "Generate test coverage") orelse false;

    // unit tests
    var unit_tests = b.addTest("src/main.zig");
    unit_tests.addPackage(pkgs.datetime);
    unit_tests.addPackage(pkgs.uri);
    unit_tests.setBuildMode(mode);
    unit_tests.filter = test_filter;
    if (coverage) {
        unit_tests.setExecCmd(&[_]?[]const u8{
            "kcov",
            "--include-path=./src",
            "kcov-output", // output dir for kcov
            null, // to get zig to use the --test-cmd-bin flag
        });
    }

    // test step
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&unit_tests.step);
}
