const std = @import("std");
const mem = std.mem;
const datetime = @import("datetime");
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const BytesView = @import("../BytesView.zig");
const constantTimeEqlBytes = @import("constant_time.zig").constantTimeEqlBytes;
const AesBlock = @import("aes.zig").AesBlock;
const Ctr = @import("ctr.zig").Ctr;
const u24_size = @import("handshake_msg.zig").u24_size;
const u16_size = @import("handshake_msg.zig").u16_size;
const u8_size = @import("handshake_msg.zig").u8_size;
const writeInt = @import("handshake_msg.zig").writeInt;
const writeBytes = @import("handshake_msg.zig").writeBytes;
const writeLenAndBytes = @import("handshake_msg.zig").writeLenAndBytes;

const u64_size = @divExact(@typeInfo(u64).Int.bits, @bitSizeOf(u8));

// SessionStateTls12 contains the information that is serialized into a session
// ticket in order to later resume a connection.
pub const SessionStateTls12 = struct {
    vers: ?ProtocolVersion = null,
    cipher_suite: ?CipherSuiteId = null,
    created_at: ?u16 = null,
    master_secret: ?[]const u8 = null, // opaque master_secret<1..2^16-1>;

    // struct { opaque certificate<1..2^24-1> } Certificate;
    certificates: ?[]const []const u8 = null, // Certificate certificate_list<0..2^24-1>;

    // usedOldKey is true if the ticket from which this session came from
    // was encrypted with an older key and thus should be refreshed.
    used_old_key: bool = false,
};

// SessionStateTls13 is the content of a TLS 1.3 session ticket. Its first
// version (revision = 0) doesn't carry any of the information needed for 0-RTT
// validation and the nonce is always empty.
pub const SessionStateTls13 = struct {
    // version: u8 = 0x0304;
    // revision: u8 = 0;
    cipher_suite: CipherSuiteId,
    created_at: u64,
    resumption_secret: []const u8 = "", // opaque resumption_master_secret<1..2^8-1>;
    certificate: CertificateChain, // CertificateEntry certificate_list<0..2^24-1>;

    pub fn deinit(self: *SessionStateTls13, allocator: mem.Allocator) void {
        if (self.resumption_secret.len > 0) allocator.free(self.resumption_secret);
        self.certificate.deinit(allocator);
    }

    pub fn unmarshal(allocator: mem.Allocator, data: []const u8) !SessionStateTls13 {
        var bv = BytesView.init(data);
        const version = try bv.readEnum(ProtocolVersion, .Big);
        if (version != .v1_3) {
            return error.InvalidSessionStateTls13;
        }
        const revision = try bv.readByte();
        if (revision != 0) {
            return error.InvalidSessionStateTls13;
        }
        const cipher_suite = try bv.readEnum(CipherSuiteId, .Big);
        const created_at = try bv.readIntBig(u64);
        const resumption_secret = try allocator.dupe(u8, try bv.readLenPrefixedBytes(u8, .Big));
        errdefer allocator.free(resumption_secret);
        var certificate = try CertificateChain.unmarshal(allocator, bv.rest());
        errdefer certificate.deinit(allocator);
        return SessionStateTls13{
            .cipher_suite = cipher_suite,
            .created_at = created_at,
            .resumption_secret = resumption_secret,
            .certificate = certificate,
        };
    }

    pub fn marshal(self: *const SessionStateTls13, allocator: mem.Allocator) ![]const u8 {
        const msg_len = u16_size + u8_size + u16_size + u64_size +
            u8_size + self.resumption_secret.len + self.certificate.marshaledLen();

        var raw = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(raw);
        var fbs = std.io.fixedBufferStream(raw);
        var writer = fbs.writer();

        try writeInt(u16, ProtocolVersion.v1_3, writer);
        try writeInt(u8, 0, writer); // revision
        try writeInt(u16, self.cipher_suite, writer);
        try writeInt(u64, self.created_at, writer);
        try writeLenAndBytes(u8, self.resumption_secret, writer);
        try self.certificate.writeTo(writer);
        return raw;
    }
};

pub const ticket_key_rotation_seconds = 24 * std.time.s_per_hour;

// TicketKey is the internal representation of a session ticket key.
pub const TicketKey = struct {
    pub const name_len = 16;

    // key_name is an opaque byte string that serves to identify the session
    // ticket key. It's exposed as plaintext in every session ticket.
    key_name: [name_len]u8,
    aes_key: [16]u8,
    hmac_key: [16]u8,
    // created is the time at which this ticket key was created. See Config.ticketKeys.
    created: datetime.datetime.Datetime,
};

const aes_block_len = std.crypto.core.aes.Block.block_length;
const sha256_len = std.crypto.hash.sha2.Sha256.digest_length;

pub fn encryptTicket(
    allocator: mem.Allocator,
    ticket_keys: []const TicketKey,
    state: []const u8,
    random: std.rand.Random,
) ![]const u8 {
    if (ticket_keys.len == 0) {
        return error.TlsNoSessionTicketKeys;
    }

    const encrypted_len = TicketKey.name_len + aes_block_len + state.len + sha256_len;
    var encrypted = try allocator.alloc(u8, encrypted_len);
    errdefer allocator.free(encrypted);

    var key_name = encrypted[0..TicketKey.name_len];
    var iv = encrypted[TicketKey.name_len .. TicketKey.name_len + aes_block_len];
    var mac_bytes = encrypted[encrypted.len - sha256_len ..];

    random.bytes(iv);

    const key = ticket_keys[0];
    mem.copy(u8, key_name, &key.key_name);

    var block = try AesBlock.init(&key.aes_key);
    var ctr = try Ctr.init(allocator, block, iv);
    defer ctr.deinit(allocator);
    ctr.xorKeyStream(encrypted[TicketKey.name_len + aes_block_len ..], state);

    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac = HmacSha256.init(&key.hmac_key);
    mac.update(encrypted[0 .. encrypted.len - sha256_len]);
    mac.final(mac_bytes[0..HmacSha256.mac_length]);

    return encrypted;
}

pub fn decryptTicket(
    allocator: mem.Allocator,
    ticket_keys: []const TicketKey,
    encrypted: []const u8,
    out_used_old_key: *bool,
) ![]const u8 {
    if (encrypted.len < TicketKey.name_len + aes_block_len + sha256_len) {
        return "";
    }

    const key_name = encrypted[0..TicketKey.name_len];
    const iv = encrypted[TicketKey.name_len .. TicketKey.name_len + aes_block_len];
    const mac_bytes = encrypted[encrypted.len - sha256_len ..];
    const ciphertext = encrypted[TicketKey.name_len + aes_block_len .. encrypted.len - sha256_len];

    var key_index: ?usize = null;
    for (ticket_keys) |key, i| {
        if (mem.eql(u8, key_name, &key.key_name)) {
            key_index = i;
            break;
        }
    }
    if (key_index == null) {
        return "";
    }
    const key = ticket_keys[key_index.?];
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac = HmacSha256.init(&key.hmac_key);
    mac.update(encrypted[0 .. encrypted.len - sha256_len]);
    var expected: [HmacSha256.mac_length]u8 = undefined;
    mac.final(&expected);
    if (constantTimeEqlBytes(mac_bytes, &expected) != 1) {
        return "";
    }

    var block = try AesBlock.init(&key.aes_key);
    var ctr = try Ctr.init(allocator, block, iv);
    defer ctr.deinit(allocator);

    var plaintext = try allocator.alloc(u8, ciphertext.len);
    ctr.xorKeyStream(plaintext, ciphertext);

    out_used_old_key.* = key_index != null and key_index.? > 0;
    return plaintext;
}

const testing = std.testing;

test "SessionStateTls13.unmarshal" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const plaintext = "\x03\x04\x00\x13\x01\x00\x00\x00\x00\x62\x2c\x8f\xe0\x20\x45\x1f\x6c\x6e\xaf\xe7\xd0\x59\x41\x17\xeb\xdc\x50\x3f\xed\x57\x01\xec\xc9\xab\xd5\xed\x63\xa1\xea\xdb\xa6\x79\xd0\x63\xa9\x01\x00\x00\x00";
    var state = try SessionStateTls13.unmarshal(allocator, plaintext);
    defer state.deinit(allocator);
    // std.log.debug("state={}", .{state});

    const got = try state.marshal(allocator);
    defer allocator.free(got);
    try testing.expectEqualSlices(u8, plaintext, got);
}

test "encryptTicket" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const RandomForTest = @import("random_for_test.zig").RandomForTest;
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);

    const ticket_keys = &[_]TicketKey{.{
        .key_name = [_]u8{ 0xd0, 0x0b, 0xd9, 0x39, 0x5f, 0x7e, 0x64, 0x7d, 0xc7, 0x42, 0xb3, 0x30, 0xba, 0xfc, 0xc2, 0x93 },
        .aes_key = [_]u8{ 0xe6, 0x17, 0xba, 0x9f, 0x47, 0x2f, 0xe8, 0x8d, 0xf8, 0x56, 0xdb, 0xcf, 0xa0, 0x99, 0x43, 0x3c },
        .hmac_key = [_]u8{ 0xee, 0xd9, 0x2a, 0x4b, 0xdb, 0xd5, 0x77, 0x05, 0x0e, 0x10, 0xc3, 0x9f, 0xf9, 0xd4, 0x2d, 0xb2 },
        .created = datetime.datetime.Datetime.now(),
    }};
    const state = "\x03\x04\x00\x13\x01\x00\x00\x00\x00\x62\x2d\xfc\x89\x20\x1a\xc5\xa7\x82\x7d\x4e\xfe\x06\xb1\x9c\x8f\x32\xf4\xdc\x1f\x90\x67\xc8\xf5\x2c\xb4\x7f\x52\x7e\x15\xd6\x65\xbb\x3d\x45\x9b\x4f\x00\x00\x00";
    const got = try encryptTicket(allocator, ticket_keys, state, rand.random());
    defer allocator.free(got);

    const want = "\xd0\x0b\xd9\x39\x5f\x7e\x64\x7d\xc7\x42\xb3\x30\xba\xfc\xc2\x93\xc4\xd8\x67\x64\x3b\xf8\xdc\x07\xd4\xb0\x0b\x3b\x4c\x36\x21\x1b\x2b\x05\xe6\xbb\x5e\xa2\xaf\x7e\xaa\x8c\xec\xe0\xd7\xab\xbc\xeb\xfd\x00\x25\x57\xe6\x0e\xcc\x0a\x0a\xe4\x34\x20\xf8\x0f\x94\x0a\x36\xf5\x4b\x39\x00\x3a\x3f\xff\x76\x30\x67\xf3\xd3\xe0\x08\x8c\x49\x91\x1c\xb5\xaf\xf6\x28\x69\x67\x3d\x84\x82\x9c\xa0\xfb\x78\xe2\x82\x90\x27\x3d\x8d\xcb\xb2\x71\x9b\x80\x68\x63\xce\x2f\x7c\x50";
    try testing.expectEqualSlices(u8, want, got);
}

test "decryptTicket" {
    testing.log_level = .debug;
    const allocator = testing.allocator;

    const ticket_keys = &[_]TicketKey{.{
        .key_name = [_]u8{ 0xb6, 0x8e, 0x55, 0x74, 0xb1, 0x2d, 0x8d, 0x6a, 0x97, 0x6f, 0x68, 0x50, 0x82, 0x1c, 0x04, 0x4a },
        .aes_key = [_]u8{ 0x63, 0x6f, 0x5b, 0x6f, 0x0c, 0x0e, 0xda, 0xff, 0xae, 0xae, 0x17, 0x7a, 0x16, 0xba, 0xb1, 0x6a },
        .hmac_key = [_]u8{ 0x3d, 0x75, 0x4e, 0x57, 0xb3, 0xac, 0x0f, 0xc8, 0x7b, 0x1c, 0x10, 0x27, 0xda, 0x15, 0xe4, 0xb2 },
        .created = datetime.datetime.Datetime{
            .date = datetime.datetime.Date.create(2022, 3, 12) catch unreachable,
            .time = datetime.datetime.Time.create(21, 19, 44, 698849475) catch unreachable,
            .zone = &datetime.timezones.Asia.Tokyo,
        },
    }};
    const encrypted = "\xb6\x8e\x55\x74\xb1\x2d\x8d\x6a\x97\x6f\x68\x50\x82\x1c\x04\x4a\x79\x68\x0e\x18\xd8\x8a\x5f\xa9\x64\xae\xeb\x48\xf7\x7c\x80\xbf\x60\x58\x61\x14\x0d\xfc\xcd\x2c\xae\x65\x0c\x06\x06\xff\xeb\x87\x44\x4e\x18\x4e\x39\x41\x2e\x76\xca\x3a\x1c\xb2\xe3\x7f\x28\xa9\x8c\xb0\x34\x92\x91\xcf\x92\xdf\xcf\xc6\x72\xdb\x22\x59\xd2\xbd\xd8\x9b\xa4\x30\xf5\x6d\xe5\x39\x7d\xb5\x19\xb3\xc1\xb9\xf8\x13\x80\x95\xe3\x17\xe0\xf6\xe1\xcf\xaf\x67\xa5\xf7\xce\xa5\x09\x31\x7a";

    var used_old_key: bool = undefined;
    const plaintext = try decryptTicket(allocator, ticket_keys, encrypted, &used_old_key);
    defer allocator.free(plaintext);
    const want_plaintext = "\x03\x04\x00\x13\x01\x00\x00\x00\x00\x62\x2c\x8f\xe0\x20\x45\x1f\x6c\x6e\xaf\xe7\xd0\x59\x41\x17\xeb\xdc\x50\x3f\xed\x57\x01\xec\xc9\xab\xd5\xed\x63\xa1\xea\xdb\xa6\x79\xd0\x63\xa9\x01\x00\x00\x00";
    const want_used_old_key = false;

    try testing.expectEqualSlices(u8, want_plaintext, plaintext);
    try testing.expectEqual(want_used_old_key, used_old_key);
}
