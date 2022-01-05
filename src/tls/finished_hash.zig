const std = @import("std");
const assert = std.debug.assert;
const fifo = std.fifo;
const math = std.math;
const mem = std.mem;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const Hash = @import("hash.zig").Hash;
const Sha256Hash = @import("hash.zig").Sha256Hash;
const Sha384Hash = @import("hash.zig").Sha384Hash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const Prf12 = @import("prf.zig").Prf12;
const finished_verify_length = @import("prf.zig").finished_verify_length;
const client_finished_label = @import("prf.zig").client_finished_label;
const server_finished_label = @import("prf.zig").server_finished_label;

pub const FinishedHash = struct {
    client: Hash,
    server: Hash,

    // Not implemented for prior to TLS 1.2.
    // // Prior to TLS 1.2, an additional MD5 hash is required.
    // client_md5: Hash,
    // server_md5: Hash,

    // In TLS 1.2, a full buffer is sadly required.
    buffer: ?fifo.LinearFifo(u8, .Dynamic) = null,

    version: ProtocolVersion,
    prf: fn (
        allocator: mem.Allocator,
        secret: []const u8,
        label: []const u8,
        seed: []const u8,
        out: []u8,
    ) anyerror!void,
    hash_digest_length: usize,

    pub fn new(
        allocator: mem.Allocator,
        version: ProtocolVersion,
        cipher_suite: *const CipherSuite12,
    ) FinishedHash {
        switch (version) {
            .v1_2 => {
                if (cipher_suite.flags.sha384) {
                    return .{
                        .client = .{ .Sha384 = Sha384Hash.init(.{}) },
                        .server = .{ .Sha384 = Sha384Hash.init(.{}) },
                        .version = version,
                        .buffer = fifo.LinearFifo(u8, .Dynamic).init(allocator),
                        .prf = Prf12(std.crypto.hash.sha2.Sha384).prf12,
                        .hash_digest_length = std.crypto.hash.sha2.Sha384.digest_length,
                    };
                } else {
                    return .{
                        .client = .{ .Sha256 = Sha256Hash.init(.{}) },
                        .server = .{ .Sha256 = Sha256Hash.init(.{}) },
                        .version = version,
                        .buffer = fifo.LinearFifo(u8, .Dynamic).init(allocator),
                        .prf = Prf12(std.crypto.hash.sha2.Sha256).prf12,
                        .hash_digest_length = std.crypto.hash.sha2.Sha256.digest_length,
                    };
                }
            },
            else => @panic("not implemented"),
        }
    }

    pub fn deinit(self: *FinishedHash) void {
        self.discardHandshakeBuffer();
    }

    pub fn discardHandshakeBuffer(self: *FinishedHash) void {
        if (self.buffer) |*buffer| {
            buffer.deinit();
            self.buffer = null;
        }
    }

    pub fn write(self: *FinishedHash, msg: []const u8) !void {
        self.client.update(msg);
        self.server.update(msg);
        if (self.buffer) |*buffer| {
            try buffer.write(msg);
        }
    }

    pub fn allocSum(self: *FinishedHash, allocator: mem.Allocator) ![]const u8{
        return switch (self.version) {
            .v1_2 => try self.client.allocFinal(allocator),
            else => @panic("not implemented"),
        };
    }

    // clientSum returns to the contents of the verify_data member of a client's
    // Finished message.
    pub fn clientSum(self: *FinishedHash, allocator: mem.Allocator, master_secret: []const u8) ![finished_verify_length]u8 {
        var seed = try self.allocSum(allocator);
        defer allocator.free(seed);
        var out: [finished_verify_length]u8 = undefined;
        try self.prf(allocator, master_secret, client_finished_label, seed, &out);
        return out;
    }

    // serverSum returns to the contents of the verify_data member of a server's
    // Finished message.
    pub fn serverSum(self: *FinishedHash, allocator: mem.Allocator, master_secret: []const u8) ![finished_verify_length]u8 {
        var seed = try self.allocSum(allocator);
        defer allocator.free(seed);
        var out: [finished_verify_length]u8 = undefined;
        try self.prf(allocator, master_secret, server_finished_label, seed, &out);
        return out;
    }
};

const testing = std.testing;
const cipher_suites12 = @import("cipher_suites.zig").cipher_suites12;

test "FinishedHash" {
    const allocator = testing.allocator;

    {
        var fh = FinishedHash.new(allocator, .v1_2, &cipher_suites12[0]);
        defer fh.deinit();

        try fh.write("hello");
        try fh.write("world");
        const out = try fh.allocSum(allocator);
        defer allocator.free(out);
        std.debug.print("out#1={}\n", .{ std.fmt.fmtSliceHexLower(out) });
        const server_sum = try fh.serverSum(allocator, "my master secret");
        std.debug.print("server_sum={}\n", .{std.fmt.fmtSliceHexLower(&server_sum)});
    }

    {
        var fh = FinishedHash.new(allocator, .v1_2, &cipher_suites12[1]);
        defer fh.deinit();

        try fh.write("hello");
        try fh.write("world");
        const out = try fh.allocSum(allocator);
        defer allocator.free(out);
        std.debug.print(" out#2={}\n", .{ std.fmt.fmtSliceHexLower(out) });
        const client_sum = try fh.clientSum(allocator, "my master secret");
        std.debug.print("client_sum={}\n", .{std.fmt.fmtSliceHexLower(&client_sum)});
    }
}
