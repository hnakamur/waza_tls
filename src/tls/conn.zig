const std = @import("std");
const fifo = std.fifo;
const io = std.io;
const math = std.math;
const mem = std.mem;
const net = std.net;
const CipherSuite = @import("cipher_suites.zig").CipherSuite;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const HandshakeMsg = @import("handshake_msg.zig").HandshakeMsg;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const generateRandom = @import("handshake_msg.zig").generateRandom;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const handshake_msg_header_len = @import("handshake_msg.zig").handshake_msg_header_len;
const RecordType = @import("record.zig").RecordType;
const ServerHandshake = @import("handshake_server.zig").ServerHandshake;
const ClientHandshake = @import("handshake_client.zig").ClientHandshake;
const Handshake = @import("handshake.zig").Handshake;
const fmtx = @import("../fmtx.zig");

const max_plain_text = 16384; // maximum plaintext payload length
const max_ciphertext_tls13 = 16640;
const max_ciphertext = 18432;
const record_header_len = 5;

// Currently Conn is not thread-safe.
pub const Conn = struct {
    const Config = struct {
        min_version: ProtocolVersion = .v1_2,
        max_version: ProtocolVersion = .v1_3,

        fn maxSupportedVersion(self: *const Config) ?ProtocolVersion {
            const sup_vers = self.supportedVersions();
            if (sup_vers.len == 0) {
                return null;
            }
            return sup_vers[0];
        }

        fn supportedVersion(self: *const Config) []const ProtocolVersion {
            var start: usize = 0;
            var end: usize = supported_versions.len;
            var i: usize = 0;
            while (i < supported_versions.len) : (i += 1) {
                if (@enumToInt(supported_versions[i]) <= @enumToInt(self.max_version)) {
                    start = i;
                    break;
                }
            }
            while (i < supported_versions.len) : (i += 1) {
                if (@enumToInt(supported_versions[i]) <= @enumToInt(self.min_version)) {
                    end = i + 1;
                    break;
                }
            }
            return supported_versions[start..end];
        }

        // mutualVersion returns the protocol version to use given the advertised
        // versions of the peer. Priority is given to the peer preference order.
        fn mutualVersion(
            self: *const Config,
            peer_versions: []const ProtocolVersion,
        ) ?ProtocolVersion {
            const sup_vers = self.supportedVersion();
            for (peer_versions) |peer_ver| {
                for (sup_vers) |sup_ver| {
                    if (sup_ver == peer_ver) {
                        return sup_ver;
                    }
                }
            }
            return null;
        }
    };

    stream: net.Stream,
    in: HalfConn,
    out: HalfConn,
    version: ?ProtocolVersion = null,
    buffering: bool = false,
    send_buf: std.ArrayListUnmanaged(u8) = .{},
    bytes_sent: usize = 0,
    handshake_complete: bool = false,
    raw_input: io.BufferedReader(4096, net.Stream.Reader),
    input: std.ArrayListUnmanaged(u8) = .{},
    retry_count: usize = 0,
    handshake_bytes: []const u8 = &[_]u8{},
    config: Config,
    handshake: ?Handshake = null,

    pub fn init(stream: net.Stream, in: HalfConn, out: HalfConn, config: Config) Conn {
        return .{
            .stream = stream,
            .in = in,
            .out = out,
            .raw_input = io.bufferedReader(stream.reader()),
            .config = config,
        };
    }

    pub fn deinit(self: *Conn, allocator: mem.Allocator) void {
        self.send_buf.deinit(allocator);
        if (self.handshake_bytes.len > 0) allocator.free(self.handshake_bytes);
        if (self.handshake) |*hs| hs.deinit(allocator);
    }

    pub fn clientHandshake(self: *Conn, allocator: mem.Allocator) !void {
        const client_hello = try self.makeClientHello(allocator);
        _ = client_hello;
        // self.handshake = Handshake{
        //     .client = ClientHandshake.init(self.version.?, self, client_hello),
        // };
        // try self.handshake.?.client.handshake(allocator);
    }

    pub fn serverHandshake(self: *Conn, allocator: mem.Allocator) !void {
        const client_hello = try self.readClientHello(allocator);
        self.handshake = Handshake{
            .server = ServerHandshake.init(self.version.?, self, client_hello),
        };
        try self.handshake.?.server.handshake(allocator);
    }

    fn makeClientHello(self: *Conn, allocator: mem.Allocator) !ClientHelloMsg {
        const sup_vers = self.supportedVersion();
        if (sup_vers.len == 0) {
            return error.NoSupportedVersion;
        }

        var cli_hello_ver = self.config.maxSupportedVersion().?;
        if (@enumToInt(cli_hello_ver) > @enumToInt(.v1_2)) {
            cli_hello_ver = .v1_2;
        }

        var client_hello: ClientHelloMsg = blk: {
            const random = try generateRandom(allocator);
            errdefer allocator.free(random);

            const cipher_suites = try allocator.dupe(
                CipherSuiteId,
                &[_]CipherSuiteId{.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
            );
            errdefer allocator.free(cipher_suites);

            const compression_methods = try allocator.dupe(
                CompressionMethod,
                &[_]CompressionMethod{.none},
            );
            errdefer allocator.free(compression_methods);

            break :blk ClientHelloMsg{
                .vers = cli_hello_ver,
                .random = random,
                .session_id = &[_]u8{0} ** 32,
                .cipher_suites = cipher_suites,
                .compression_methods = compression_methods,
            };
        };

        return client_hello;
    }

    pub fn writeRecord(
        self: *Conn,
        allocator: mem.Allocator,
        rec_type: RecordType,
        data: []const u8,
    ) !void {
        var out_buf = try std.ArrayListUnmanaged(u8).initCapacity(allocator, record_header_len);
        defer out_buf.deinit(allocator);

        var n: usize = 0;
        var rest = data;
        while (rest.len > 0) {
            out_buf.clearRetainingCapacity();
            var writer = out_buf.writer(allocator);
            try writer.writeByte(@enumToInt(rec_type));

            const vers = if (self.version) |vers| blk: {
                // TLS 1.3 froze the record layer version to 1.2.
                // See RFC 8446, Section 5.1.
                break :blk if (vers == .v1_3) .v1_2 else vers;
            } else blk: {
                // Some TLS servers fail if the record version is
                // greater than TLS 1.0 for the initial ClientHello.
                break :blk .v1_0;
            };
            try writer.writeIntBig(u16, @enumToInt(vers));

            const m = math.min(rest.len, self.maxPayloadSizeForWrite(rec_type));
            try writer.writeIntBig(u16, @intCast(u16, m));

            try self.out.encrypt(allocator, &out_buf, rest[0..m]);
            try self.write(allocator, out_buf.items);
            n += m;
            rest = rest[m..];
        }

        if (rec_type == .change_cipher_spec) {
            if (self.version) |con_ver| {
                if (con_ver == .v1_3) {
                    // TODO: implement
                }
            }
        }
    }

    fn maxPayloadSizeForWrite(self: *Conn, rec_type: RecordType) usize {
        if (rec_type != .application_data) {
            return max_plain_text;
        }
        _ = self;
        @panic("not implemented yet");
    }

    fn write(self: *Conn, allocator: mem.Allocator, data: []const u8) !void {
        if (self.buffering) {
            try self.send_buf.appendSlice(allocator, data);
            return;
        }

        try self.stream.writer().writeAll(data);
        self.bytes_sent += data.len;
    }

    pub fn flush(self: *Conn) !void {
        if (self.send_buf.items.len == 0) {
            return;
        }

        try self.stream.writer().writeAll(self.send_buf.items);
        self.bytes_sent += self.send_buf.items.len;
        self.send_buf.clearRetainingCapacity();
        self.buffering = false;
    }

    fn readClientHello(self: *Conn, allocator: mem.Allocator) !ClientHelloMsg {
        var hs_msg = try self.readHandshake(allocator);
        const client_hello = switch (hs_msg) {
            .ClientHello => |msg| msg,
            else => {
                // TODO: send alert
                return error.UnexpectedMessage;
            },
        };

        const client_versions = blk: {
            if (client_hello.supported_versions) |cli_sup_vers| {
                if (cli_sup_vers.len > 0) {
                    break :blk cli_sup_vers;
                }
            }
            break :blk supportedVersionsFromMax(client_hello.vers);
        };
        self.version = self.config.mutualVersion(client_versions);
        if (self.version) |ver| {
            self.in.ver = ver;
            self.out.ver = ver;
        } else {
            // TODO: send alert
            return error.ProtocolVersionMismatch;
        }

        return client_hello;
    }

    pub fn readHandshake(self: *Conn, allocator: mem.Allocator) !HandshakeMsg {
        if (self.handshake_bytes.len < handshake_msg_header_len) {
            try self.readRecord(allocator);
        }
        var msg = try HandshakeMsg.unmarshal(allocator, self.handshake_bytes);
        allocator.free(self.handshake_bytes);
        self.handshake_bytes = &[_]u8{};
        return msg;
    }

    pub fn readRecord(self: *Conn, allocator: mem.Allocator) !void {
        try self.readRecordOrChangeCipherSpec(allocator, false);
    }

    pub fn readChangeCipherSpec(self: *Conn, allocator: mem.Allocator) !void {
        try self.readRecordOrChangeCipherSpec(allocator, true);
    }

    pub fn readRecordOrChangeCipherSpec(
        self: *Conn,
        allocator: mem.Allocator,
        expect_change_cipher_spec: bool,
    ) !void {
        _ = expect_change_cipher_spec;

        if (self.input.items.len != 0) {
            return error.InternalError;
        }
        var hdr: [record_header_len]u8 = undefined;
        const header_bytes_read = try self.raw_input.reader().readAll(&hdr);
        if (header_bytes_read == 0) {
            // RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
            // is an error, but popular web sites seem to do this, so we accept it
            // if and only if at the record boundary.
            return error.EndOfStream;
        } else if (header_bytes_read < record_header_len) {
            return error.UnexpectedEof;
        }

        var fbs = io.fixedBufferStream(&hdr);
        var r = fbs.reader();
        const rec_type = try r.readEnum(RecordType, .Big);
        const rec_ver = try r.readEnum(ProtocolVersion, .Big);
        const payload_len = try r.readIntBig(u16);
        std.log.debug(
            "Conn.readRecordOrCCS rec_type={}, rec_ver={}, payload_len={}",
            .{ rec_type, rec_ver, payload_len },
        );
        if (self.version) |con_ver| {
            if (con_ver != .v1_3 and con_ver != rec_ver) {
                // TODO: sendAlert
                return error.InvalidRecordHeader;
            }
        } else {
            // First message, be extra suspicious: this might not be a TLS
            // client. Bail out before reading a full 'body', if possible.
            // The current max version is 3.3 so if the version is >= 16.0,
            // it's probably not real.
            if ((rec_type != .alert and rec_type != .handshake) or
                @enumToInt(rec_ver) >= 0x1000)
            {
                return error.InvalidRecordHeader;
            }
        }
        if (self.version) |con_ver| {
            if (con_ver == .v1_3 and
                payload_len > max_ciphertext_tls13 or payload_len > max_ciphertext)
            {
                // TODO: sendAlert
                return error.InvalidRecordHeader;
            }
        }

        const data = blk: {
            var payload = try allocator.alloc(u8, payload_len);
            errdefer allocator.free(payload);
            const payload_bytes_read = try self.raw_input.reader().readAll(payload);
            if (payload_bytes_read < payload_len) {
                return error.UnexpectedEof;
            }
            break :blk try self.in.decrypt(allocator, rec_type, rec_ver, payload);
        };
        errdefer allocator.free(data);

        if (rec_type != .alert and rec_type != .change_cipher_spec and data.len > 0) {
            // This is a state-advancing message: reset the retry count.
            self.retry_count = 0;
        }

        std.log.debug("data.len={}, data={}", .{ data.len, fmtx.fmtSliceHexEscapeLower(data) });

        switch (rec_type) {
            .handshake => {
                self.handshake_bytes = data;
            },
            else => {
                // TODO: send alert
                return error.UnexpectedMessage;
            },
        }
    }
};

const HalfConn = struct {
    cipher: ?CipherSuite = null,
    ver: ?ProtocolVersion = null,
    seq: [8]u8 = [_]u8{0} ** 8, // 64-bit sequence number

    fn encrypt(
        self: *HalfConn,
        allocator: mem.Allocator,
        record: *std.ArrayListUnmanaged(u8),
        payload: []const u8,
    ) !void {
        if (self.cipher) |_| {} else {
            try record.appendSlice(allocator, payload);
            return;
        }

        @panic("not implemented yet");
    }

    fn decrypt(
        self: *HalfConn,
        allocator: mem.Allocator,
        rec_type: RecordType,
        rec_ver: ProtocolVersion,
        payload: []const u8,
    ) ![]const u8 {
        _ = rec_ver;
        _ = allocator;
        var plaintext: []const u8 = undefined;
        // In TLS 1.3, change_cipher_spec messages are to be ignored without being
        // decrypted. See RFC 8446, Appendix D.4.
        if (self.ver) |con_ver| {
            if (con_ver == .v1_3 and rec_type == .change_cipher_spec) {
                return payload;
            }
        }

        if (self.cipher) |cipher| {
            // TODO: implement
            _ = cipher;
        } else {
            plaintext = payload;
        }

        self.incSeq();
        return plaintext;
    }

    fn incSeq(self: *HalfConn) void {
        var i: usize = 7;
        while (i > 0) : (i -= 1) {
            self.seq[i] +%= 1;
            if (self.seq[i] != 0) {
                return;
            }
        }

        // Not allowed to let sequence number wrap.
        // Instead, must renegotiate before it does.
        // Not likely enough to bother.
        @panic("TLS: sequence number wraparound");
    }
};

const supported_versions = [_]ProtocolVersion{ .v1_3, .v1_2 };

// supportedVersionsFromMax returns a list of supported versions derived from a
// legacy maximum version value. Note that only versions supported by this
// library are returned. Any newer peer will use supportedVersions anyway.
fn supportedVersionsFromMax(max_version: ProtocolVersion) []const ProtocolVersion {
    var i: usize = 0;
    while (i < supported_versions.len) : (i += 1) {
        if (@enumToInt(supported_versions[i]) <= @enumToInt(max_version)) {
            break;
        }
    }
    return supported_versions[i..];
}

pub fn AtLeastReader(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,
        bytes_left: u64,

        pub const Error = error{UnexpectedEof} || ReaderType.Error;
        pub const Reader = io.Reader(*Self, Error, read);

        const Self = @This();

        /// Returns the number of bytes read. It may be less than dest.len.
        /// If the number of bytes read is 0, it means end of stream.
        /// End of stream is not an error condition.
        /// If the number of bytes read from inner_reader is 0 and bytes_left
        /// is greater than 0, it returns error.UnexpectedEof.
        pub fn read(self: *Self, dest: []u8) Error!usize {
            const max_read = std.math.min(self.bytes_left, dest.len);
            const n = try self.inner_reader.read(dest[0..max_read]);
            self.bytes_left -= n;
            if (n == 0 and self.bytes_left > 0) {
                return error.UnexpectedEof;
            }
            return n;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

/// Returns an initialised `AtLeastReader`
/// `bytes_left` is a `u64` to be able to take 64 bit file offsets
pub fn atLeastReader(inner_reader: anytype, bytes_left: u64) AtLeastReader(@TypeOf(inner_reader)) {
    return .{ .inner_reader = inner_reader, .bytes_left = bytes_left };
}

const testing = std.testing;

test "atLeastReader" {
    {
        const input = "hello";
        var fbs = io.fixedBufferStream(input);
        var reader = atLeastReader(fbs.reader(), input.len);
        var buf = [_]u8{0} ** input.len;
        try testing.expectEqual(input.len, try reader.read(&buf));
        try testing.expectEqual(@as(usize, 0), try reader.read(&buf));
    }
    {
        const input = "hello";
        var fbs = io.fixedBufferStream(input);
        var reader = atLeastReader(fbs.reader(), input.len + 1);
        var buf = [_]u8{0} ** input.len;
        try testing.expectEqual(input.len, try reader.read(&buf));
        try testing.expectError(error.UnexpectedEof, reader.read(&buf));
    }
    {
        const input = "hello";
        var fbs = io.fixedBufferStream(input);
        var reader = atLeastReader(fbs.reader(), input.len + 1);
        var buf = [_]u8{0} ** (input.len - 1);
        try testing.expectEqual(buf.len, try reader.read(&buf));
        try testing.expectEqual(input.len - buf.len, try reader.read(&buf));
        try testing.expectError(error.UnexpectedEof, reader.read(&buf));
    }
}

test "HalfConn.encrypt" {
    const allocator = testing.allocator;

    var record = std.ArrayListUnmanaged(u8){};
    defer record.deinit(allocator);

    try record.appendSlice(allocator, "hello, ");

    var hc = HalfConn{};
    try hc.encrypt(allocator, &record, "world");
    try testing.expectEqualStrings("hello, world", record.items);
}

test "blk" {
    const f = struct {
        fn f(versions: ?[]const ProtocolVersion) bool {
            return blk: {
                if (versions) |vers| {
                    if (vers.len > 0) {
                        break :blk true;
                    }
                }
                break :blk false;
            };
        }
    }.f;

    try testing.expect(f(&[_]ProtocolVersion{.v1_3}));
    try testing.expect(!f(&[_]ProtocolVersion{}));
    try testing.expect(!f(null));
}

test "supportedVersionsFromMax" {
    const f = struct {
        fn f(max_version: ProtocolVersion, want_versions: []const ProtocolVersion) !void {
            const got_versions = supportedVersionsFromMax(max_version);
            try testing.expectEqualSlices(ProtocolVersion, want_versions, got_versions);
        }
    }.f;

    try f(.v1_3, &supported_versions);
    try f(.v1_2, supported_versions[1..]);
}

test "Config.supportedVersion" {
    // testing.log_level = .debug;
    const f = struct {
        fn f(config: Conn.Config, want_versions: []const ProtocolVersion) !void {
            const got_versions = config.supportedVersion();
            try testing.expectEqualSlices(ProtocolVersion, want_versions, got_versions);
        }
    }.f;

    try f(.{ .max_version = .v1_3, .min_version = .v1_2 }, &supported_versions);
    try f(.{ .max_version = .v1_3, .min_version = .v1_3 }, supported_versions[0..1]);
    try f(.{ .max_version = .v1_2, .min_version = .v1_2 }, supported_versions[1..]);
}
