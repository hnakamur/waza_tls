const std = @import("std");
const math = std.math;
const mem = std.mem;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const fmtx = @import("../fmtx.zig");

pub const master_secret_length = 48; // Length of a master secret in TLS 1.1.
pub const finished_verify_length = 12; // Length of verify_data in a Finished message.

pub const master_secret_label = "master secret";
pub const key_expansion_label = "key expansion";
pub const client_finished_label = "client finished";
pub const server_finished_label = "server finished";

pub fn prfForVersion(version: ProtocolVersion, suite: *const CipherSuite12) fn (
    allocator: mem.Allocator,
    secret: []const u8,
    label: []const u8,
    seed: []const u8,
    out: []u8,
) anyerror!void {
    switch (version) {
        .v1_2 => {
            if (suite.flags.sha384) {
                return Prf12(std.crypto.hash.sha2.Sha384).prf12;
            }
            return Prf12(std.crypto.hash.sha2.Sha256).prf12;
        },
        else => @panic("not implemented yet"),
    }
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, Section 5.
pub fn Prf12(comptime HashType: type) type {
    return struct {
        pub fn prf12(
            allocator: mem.Allocator,
            secret: []const u8,
            label: []const u8,
            seed: []const u8,
            out: []u8,
        ) !void {
            var label_and_seed = try allocator.alloc(u8, label.len + seed.len);
            defer allocator.free(label_and_seed);
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

pub fn masterFromPreMasterSecret(
    allocator: mem.Allocator,
    version: ProtocolVersion,
    suite: *const CipherSuite12,
    pre_master_secret: []const u8,
    client_random: []const u8,
    server_random: []const u8,
) ![]const u8 {
    var seed = try allocator.alloc(u8, client_random.len + server_random.len);
    defer allocator.free(seed);
    mem.copy(u8, seed, client_random);
    mem.copy(u8, seed[client_random.len..], server_random);

    var master_secret = try allocator.alloc(u8, master_secret_length);
    const prf = prfForVersion(version, suite);
    try prf(allocator, pre_master_secret, master_secret_label, seed, master_secret);
    return master_secret;
}

pub const ConnectionKeys = struct {
    key_material: []const u8,
    client_mac: []const u8,
    server_mac: []const u8,
    client_key: []const u8,
    server_key: []const u8,
    client_iv: []const u8,
    server_iv: []const u8,

    pub fn fromMasterSecret(
        allocator: mem.Allocator,
        version: ProtocolVersion,
        suite: *const CipherSuite12,
        master_secret: []const u8,
        client_random: []const u8,
        server_random: []const u8,
        mac_len: usize,
        key_len: usize,
        iv_len: usize,
    ) !ConnectionKeys {
        var seed = try allocator.alloc(u8, client_random.len + server_random.len);
        defer allocator.free(seed);
        mem.copy(u8, seed, server_random);
        mem.copy(u8, seed[server_random.len..], client_random);

        const n = 2 * mac_len + 2 * key_len + 2 * iv_len;
        var key_material = try allocator.alloc(u8, n);

        const prf = prfForVersion(version, suite);
        try prf(allocator, master_secret, key_expansion_label, seed, key_material);

        var rest = key_material;
        const client_mac = rest[0..mac_len];
        rest = rest[mac_len..];
        const server_mac = rest[0..mac_len];
        rest = rest[mac_len..];

        const client_key = rest[0..key_len];
        rest = rest[key_len..];
        const server_key = rest[0..key_len];
        rest = rest[key_len..];

        const client_iv = rest[0..iv_len];
        rest = rest[iv_len..];
        const server_iv = rest[0..iv_len];
        rest = rest[iv_len..];

        return ConnectionKeys{
            .key_material = key_material,
            .client_mac = client_mac,
            .server_mac = server_mac,
            .client_key = client_key,
            .server_key = server_key,
            .client_iv = client_iv,
            .server_iv = server_iv,
        };
    }

    pub fn deinit(self: *ConnectionKeys, allocator: mem.Allocator) void {
        allocator.free(self.key_material);
    }
};

const testing = std.testing;
const cipherSuite12ById = @import("cipher_suites.zig").cipherSuite12ById;

test "prfForVersion" {
    const allocator = testing.allocator;
    const suite = cipherSuite12ById(.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256).?;
    const prf = prfForVersion(.v1_2, suite);
    const seed = [_]u8{0} ** std.crypto.hash.sha2.Sha256.digest_length;
    var result: [12]u8 = undefined;
    const secret = "my secret" ** 100;
    try prf(allocator, secret, "master secret", &seed, &result);
    std.debug.print("prf12 result={}\n", .{std.fmt.fmtSliceHexLower(&result)});
}

test "Prf12" {
    const allocator = testing.allocator;
    const prf12Sha256 = Prf12(std.crypto.hash.sha2.Sha256).prf12;
    const seed = [_]u8{0} ** std.crypto.hash.sha2.Sha256.digest_length;
    var result: [12]u8 = undefined;
    const secret = "my secret" ** 100;
    try prf12Sha256(allocator, secret, "master secret", &seed, &result);
    std.debug.print("prf12 result={}\n", .{std.fmt.fmtSliceHexLower(&result)});
}

test "pHash" {
    var result: [12]u8 = undefined;
    const secret = "my secret" ** 100;
    pHash(std.crypto.hash.sha2.Sha256, secret, "master secret" ++ "\x00" ** 32, &result);
    std.debug.print("pHash result={}\n", .{std.fmt.fmtSliceHexLower(&result)});
}
