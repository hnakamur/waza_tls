const std = @import("std");
const assert = std.debug.assert;
const fifo = std.fifo;
const math = std.math;
const mem = std.mem;
const HashType = @import("auth.zig").HashType;
const SignatureType = @import("auth.zig").SignatureType;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const crypto = @import("crypto.zig");
const Sha256Hash = @import("crypto.zig").Sha256Hash;
const Sha384Hash = @import("crypto.zig").Sha384Hash;
const CipherSuiteTls12 = @import("cipher_suites.zig").CipherSuiteTls12;
const Prf12 = @import("prf.zig").Prf12;
const finished_verify_length = @import("prf.zig").finished_verify_length;
const client_finished_label = @import("prf.zig").client_finished_label;
const server_finished_label = @import("prf.zig").server_finished_label;

pub const FinishedHash = struct {
    client: crypto.Hash,
    server: crypto.Hash,

    // Not implemented for prior to TLS 1.2.
    // // Prior to TLS 1.2, an additional MD5 hash is required.
    // client_md5: crypto.Hash,
    // server_md5: crypto.Hash,

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
        cipher_suite: *const CipherSuiteTls12,
    ) FinishedHash {
        std.log.debug("FinishedHash.new, version={}, suite={}", .{ version, cipher_suite });
        switch (version) {
            .v1_2 => {
                if (cipher_suite.flags.sha384) {
                    return .{
                        .client = .{ .sha384 = Sha384Hash.init(.{}) },
                        .server = .{ .sha384 = Sha384Hash.init(.{}) },
                        .version = version,
                        .buffer = fifo.LinearFifo(u8, .Dynamic).init(allocator),
                        .prf = Prf12(std.crypto.hash.sha2.Sha384).prf12,
                        .hash_digest_length = std.crypto.hash.sha2.Sha384.digest_length,
                    };
                } else {
                    return .{
                        .client = .{ .sha256 = Sha256Hash.init(.{}) },
                        .server = .{ .sha256 = Sha256Hash.init(.{}) },
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

    pub fn allocSum(self: *FinishedHash, allocator: mem.Allocator) ![]const u8 {
        return switch (self.version) {
            .v1_2 => try self.client.allocFinal(allocator),
            else => @panic("not implemented"),
        };
    }

    pub fn debugLogClientHash(
        self: *FinishedHash,
        allocator: mem.Allocator,
        label: []const u8,
    ) !void {
        var sum = try self.client.allocFinal(allocator);
        defer allocator.free(sum);
        std.log.debug("{s}: client hash={}", .{ label, std.fmt.fmtSliceHexLower(sum) });
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

    // hashForClientCertificate returns the handshake messages so far, pre-hashed if
    // necessary, suitable for signing by a TLS client certificate.
    pub fn hashForClientCertificate(
        self: *const FinishedHash,
        allocator: mem.Allocator,
        sig_type: SignatureType,
        sig_hash: HashType,
    ) ![]const u8 {
        if (sig_type == .ed25519 and self.buffer == null) {
            @panic("tls: handshake hash for a client certificate requested after discarding the handshake buffer");
        }

        const buf = self.buffer.?.readableSlice(0);
        if (sig_type == .ed25519) {
            return try allocator.dupe(u8, buf);
        }

        var h = crypto.Hash.init(sig_hash);
        h.update(buf);
        return try h.allocFinal(allocator);
    }
};
