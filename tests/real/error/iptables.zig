const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;

pub const Target = enum {
    reject,
    drop,
};

pub const RunError = error{
    NonZeroExit,
    Signal,
    Stopped,
    Unknown,
} || error{
    BrokenPipe,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    InputOutput,
    NetworkSubsystemFailed,
    NotOpenForReading,
    OperationAborted,
    StderrStreamTooLong,
    StdoutStreamTooLong,
    WouldBlock,
} || std.ChildProcess.SpawnError;

pub fn appendRule(
    allocator: *mem.Allocator,
    dest_addr: []const u8,
    dest_port: u16,
    target: Target,
) RunError!void {
    try run(allocator, .append, dest_addr, dest_port, target);
}

pub fn deleteRule(
    allocator: *mem.Allocator,
    dest_addr: []const u8,
    dest_port: u16,
    target: Target,
) RunError!void {
    try run(allocator, .delete, dest_addr, dest_port, target);
}

const Operation = enum {
    append,
    delete,
};

fn run(
    allocator: *mem.Allocator,
    operation: Operation,
    dest_addr: []const u8,
    dest_port: u16,
    target: Target,
) RunError!void {
    var port_buf = [_]u8{0} ** 5;
    const port_len = fmt.formatIntBuf(&port_buf, dest_port, 10, false, .{});

    const operation_str = switch (operation) {
        .append => "-A",
        .delete => "-D",
    };

    const argv = switch (target) {
        .reject => &[_][]const u8{
            "sudo",
            "iptables",
            operation_str,
            "INPUT",
            "-p",
            "TCP",
            "-d",
            dest_addr,
            "--dport",
            port_buf[0..port_len],
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        },
        .drop => &[_][]const u8{
            "sudo",
            "iptables",
            operation_str,
            "INPUT",
            "-p",
            "TCP",
            "-d",
            dest_addr,
            "--dport",
            port_buf[0..port_len],
            "-j",
            "DROP",
        },
    };
    const result = try std.ChildProcess.exec(.{
        .allocator = allocator,
        .argv = argv,
    });
    switch (result.term) {
        .Exited => |code| {
            defer allocator.free(result.stdout);
            defer allocator.free(result.stderr);

            if (code != 0) {
                std.debug.print("iptables failed with exit_code={}, stdout={s}, stderr={s}.\n", .{
                    code, result.stdout, result.stderr,
                });
                return error.NonZeroExit;
            }
        },
        .Signal => |signal| {
            std.debug.print("iptables got signal {}\n", .{signal});
            return error.Signal;
        },
        .Stopped => |stopped| {
            std.debug.print("iptables got stopped {}\n", .{stopped});
            return error.Stopped;
        },
        .Unknown => |unknown| {
            std.debug.print("iptables got unknown {}\n", .{unknown});
            return error.Unknown;
        },
    }
}

const testing = std.testing;

test "real / error / addRule" {
    const allocator = testing.allocator;

    try appendRule(allocator, "127.0.0.1", 3131, .reject);
    try deleteRule(allocator, "127.0.0.1", 3131, .reject);
}
