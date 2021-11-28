const std = @import("std");

const pkgs = struct {
    const http = std.build.Pkg{
        .name = "http",
        .path = "./src/main.zig",
        .dependencies = &[_]std.build.Pkg{
            @"tigerbeetle-io",
            datetime,
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
    std.debug.print("build.zig mode={}\n", .{mode});
    const target = b.standardTargetOptions(.{});

    const lib = b.addStaticLibrary("http", "src/main.zig");
    lib.addPackage(pkgs.@"tigerbeetle-io");
    lib.addPackage(pkgs.datetime);
    lib.setBuildMode(mode);
    lib.install();

    // test filter
    const test_filter = b.option([]const u8, "test-filter", "Skip tests that do not match filter");

    const test_log_level_opt = b.option([]const u8, "test-log-level", "Set log_level for tests");
    if (test_log_level_opt) |opt| {
        std.testing.log_level = logLevelFromText(opt) catch |err| {
            std.debug.print("invalid test-log-level value: {s}\n", .{opt});
            return;
        };
    }

    // unit tests
    var unit_tests = b.addTest("src/main.zig");
    unit_tests.addPackage(pkgs.@"tigerbeetle-io");
    unit_tests.addPackage(pkgs.datetime);
    unit_tests.setBuildMode(mode);
    unit_tests.filter = test_filter;

    // tests with mock IO
    var mock_tests = b.addTest("tests/mock/main.zig");
    mock_tests.addPackage(std.build.Pkg{
        .name = "tigerbeetle-io",
        .path = "tests/mock/mock-io.zig",
    });
    mock_tests.addPackage(pkgs.datetime);
    mock_tests.setBuildMode(mode);
    mock_tests.filter = test_filter;

    // tests with real IO
    var real_tests = b.addTest("tests/real/main.zig");
    real_tests.addPackage(pkgs.http);
    real_tests.addPackage(pkgs.@"tigerbeetle-io");
    real_tests.addPackage(pkgs.datetime);
    real_tests.setBuildMode(mode);
    real_tests.filter = test_filter;

    // test step
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&unit_tests.step);
    test_step.dependOn(&mock_tests.step);
    test_step.dependOn(&real_tests.step);

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

fn logLevelFromText(input: []const u8) error{InvalidInput}!std.log.Level {
    switch (input.len) {
        3 => {
            if (std.mem.eql(u8, input, "err")) return .err;
        },
        4 => {
            if (std.mem.eql(u8, input, "crit")) return .crit;
            if (std.mem.eql(u8, input, "info")) return .info;
            if (std.mem.eql(u8, input, "warn")) return .warn;
        },
        5 => {
            if (std.mem.eql(u8, input, "alert")) return .alert;
            if (std.mem.eql(u8, input, "debug")) return .debug;
            if (std.mem.eql(u8, input, "emerg")) return .emerg;
        },
        6 => {
            if (std.mem.eql(u8, input, "notice")) return .notice;
        },
        else => {},
    }
    return error.InvalidInput;
}
