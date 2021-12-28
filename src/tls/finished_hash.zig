const std = @import("std");
const fifo = std.fifo;
const math = std.math;
const mem = std.mem;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const Hash = @import("hash.zig").Hash;
const Sha256Hash = @import("hash.zig").Sha256Hash;
const Sha384Hash = @import("hash.zig").Sha384Hash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;

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
    prf: fn (secret: []const u8, label: []const u8, seed: []const u8, out: []u8) void,
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

    pub fn sum(self: *FinishedHash, out: []u8) usize {
        return switch (self.version) {
            .v1_2 => self.client.finalToSlice(out),
            else => @panic("not implemented"),
        };
    }

    // clientSum returns to the contents of the verify_data member of a client's
    // Finished message.
    pub fn clientSum(self: *FinishedHash, master_secret: []const u8) [finished_verify_length]u8 {
        var seed: [seed_max_len]u8 = undefined;
        const seed_len = self.sum(&seed);
        var out: [finished_verify_length]u8 = undefined;
        self.prf(master_secret, client_finished_label, seed[0..seed_len], &out);
        return out;
    }

    // serverSum returns to the contents of the verify_data member of a server's
    // Finished message.
    pub fn serverSum(self: *FinishedHash, master_secret: []const u8) [finished_verify_length]u8 {
        var seed: [seed_max_len]u8 = undefined;
        const seed_len = self.sum(&seed);
        var out: [finished_verify_length]u8 = undefined;
        self.prf(master_secret, server_finished_label, seed[0..seed_len], &out);
        return out;
    }
};

const seed_max_len = std.crypto.hash.sha2.Sha384.digest_length;

pub const finished_verify_length = 12;

const master_secret_label = "master secret";
const key_expansion_label = "key expansion";
const client_finished_label = "client finished";
const server_finished_label = "server finished";
const label_max_len = math.max(
    master_secret_label.len,
    math.max(
        key_expansion_label.len,
        math.max(
            client_finished_label.len,
            server_finished_label.len,
        ),
    ),
);

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, Section 5.
fn Prf12(comptime HashType: type) type {
    return struct {
        fn prf12(
            secret: []const u8,
            label: []const u8,
            seed: []const u8,
            out: []u8,
        ) void {
            var label_and_seed: [label_max_len + seed_max_len]u8 = undefined;
            mem.copy(u8, label_and_seed[0..label.len], label);
            mem.copy(u8, label_and_seed[label.len .. label.len + seed.len], seed);
            pHash(HashType, secret, label_and_seed[0 .. label.len + seed.len], out);
        }
    };
}

fn pHash(comptime HashType: type, secret: []const u8, seed: []const u8, out: []u8) void {
    const Hmac = std.crypto.auth.hmac.Hmac(HashType);
    var h = Hmac.init(secret);
    h.update(seed);
    var a: [Hmac.mac_length]u8 = undefined;
    h.final(&a);

    var j: usize = 0;
    while (j < out.len) {
        h = Hmac.init(secret);
        h.update(&a);
        h.update(seed);
        var b: [Hmac.mac_length]u8 = undefined;
        h.final(&b);
        const copy_len = math.min(out[j..].len, b.len);
        mem.copy(u8, out[j..], b[0..copy_len]);
        j += b.len;

        h = Hmac.init(secret);
        h.update(&a);
        h.final(&a);
    }
}

const cipher_suites12 = @import("cipher_suites.zig").cipher_suites12;
const testing = std.testing;

test "FinishedHash" {
    const allocator = testing.allocator;

    {
        var fh = FinishedHash.new(allocator, .v1_2, &cipher_suites12[0]);
        defer fh.deinit();

        try fh.write("hello");
        try fh.write("world");
        std.debug.print("FinishedHash#1={}\n", .{fh});
        var out = [_]u8{0} ** std.crypto.hash.sha2.Sha256.digest_length;
        const bytes_written = fh.sum(&out);
        std.debug.print("bytes_written={}, out#1={}\n", .{ bytes_written, std.fmt.fmtSliceHexLower(&out) });
        const server_sum = fh.serverSum("my master secret");
        std.debug.print("server_sum={}\n", .{std.fmt.fmtSliceHexLower(&server_sum)});
    }

    {
        var fh = FinishedHash.new(allocator, .v1_2, &cipher_suites12[1]);
        defer fh.deinit();

        try fh.write("hello");
        try fh.write("world");
        std.debug.print("FinishedHash#2={}\n", .{fh});
        var out = [_]u8{0} ** std.crypto.hash.sha2.Sha384.digest_length;
        const bytes_written = fh.sum(&out);
        std.debug.print("bytes_written={}, out#2={}\n", .{ bytes_written, std.fmt.fmtSliceHexLower(&out) });
    }
}

test "Prf12" {
    const prf12Sha256 = Prf12(std.crypto.hash.sha2.Sha256).prf12;
    const seed = [_]u8{0} ** std.crypto.hash.sha2.Sha256.digest_length;
    var result: [12]u8 = undefined;
    const secret = "my secret" ** 100;
    prf12Sha256(secret, "master secret", &seed, &result);
    std.debug.print("prf12 result={}\n", .{std.fmt.fmtSliceHexLower(&result)});
}

test "pHash" {
    var result: [12]u8 = undefined;
    const secret = "my secret" ** 100;
    pHash(std.crypto.hash.sha2.Sha256, secret, "master secret" ++ "\x00" ** 32, &result);
    std.debug.print("pHash result={}\n", .{std.fmt.fmtSliceHexLower(&result)});
}
