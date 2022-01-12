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
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const generateRandom = @import("handshake_msg.zig").generateRandom;
const random_length = @import("handshake_msg.zig").random_length;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const handshake_msg_header_len = @import("handshake_msg.zig").handshake_msg_header_len;
const finished_verify_length = @import("prf.zig").finished_verify_length;
const RecordType = @import("record.zig").RecordType;
const ServerHandshake = @import("handshake_server.zig").ServerHandshake;
const ClientHandshake = @import("handshake_client.zig").ClientHandshake;
const Handshake = @import("handshake.zig").Handshake;
const Aead = @import("cipher_suites.zig").Aead;
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

        fn supportedVersions(self: *const Config) []const ProtocolVersion {
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
            const sup_vers = self.supportedVersions();
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

    // clientFinished and serverFinished contain the Finished message sent
    // by the client or server in the most recent handshake. This is
    // retained to support the renegotiation extension and tls-unique
    // channel-binding.
    client_finished: [finished_verify_length]u8 = undefined,
    server_finished: [finished_verify_length]u8 = undefined,

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
        var client_hello = try self.makeClientHello(allocator);

        const client_hello_bytes = try client_hello.marshal(allocator);
        try self.writeRecord(allocator, .handshake, client_hello_bytes);

        var hs_msg = try self.readHandshake(allocator);
        var server_hello = switch (hs_msg) {
            .ServerHello => |sh| sh,
            else => {
                // TODO: send alert
                return error.UnexpectedMessage;
            },
        };

        try self.pickTlsVersion(&server_hello);

        self.handshake = Handshake{
            .client = ClientHandshake.init(self.version.?, self, client_hello, server_hello),
        };
        try self.handshake.?.client.handshake(allocator);
    }

    pub fn serverHandshake(self: *Conn, allocator: mem.Allocator) !void {
        const client_hello = try self.readClientHello(allocator);
        self.handshake = Handshake{
            .server = ServerHandshake.init(self.version.?, self, client_hello),
        };
        try self.handshake.?.server.handshake(allocator);
    }

    fn makeClientHello(self: *Conn, allocator: mem.Allocator) !ClientHelloMsg {
        const sup_vers = self.config.supportedVersions();
        if (sup_vers.len == 0) {
            return error.NoSupportedVersion;
        }

        var cli_hello_ver = self.config.maxSupportedVersion().?;
        // The version at the beginning of the ClientHello was capped at TLS 1.2
        // for compatibility reasons. The supported_versions extension is used
        // to negotiate versions now. See RFC 8446, Section 4.2.1.
        if (@enumToInt(cli_hello_ver) > @enumToInt(ProtocolVersion.v1_2)) {
            cli_hello_ver = .v1_2;
        }

        var client_hello: ClientHelloMsg = blk: {
            const random = try generateRandom(allocator);
            errdefer allocator.free(random);
            const session_id = try generateRandom(allocator);
            errdefer allocator.free(session_id);

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
                .random = random[0..random_length],
                .session_id = session_id[0..random_length],
                .cipher_suites = cipher_suites,
                .compression_methods = compression_methods,
            };
        };

        return client_hello;
    }

    fn pickTlsVersion(self: *Conn, server_hello: *const ServerHelloMsg) !void {
        const peer_ver = if (server_hello.supported_version) |sup_ver|
            sup_ver
        else
            server_hello.vers;

        const ver = self.config.mutualVersion(&[_]ProtocolVersion{peer_ver});
        if (ver) |_| {} else {
            // TODO: send alert
            return error.UnsupportedVersion;
        }
        self.version = ver;
        self.in.ver = ver;
        self.out.ver = ver;
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
                if (con_ver != .v1_3) {
                    self.out.changeCipherSpec() catch @panic("send alert not implemented");
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
        if (self.input.items.len != 0) {
            return error.InternalError;
        }
        var record = try std.ArrayListUnmanaged(u8).initCapacity(allocator, record_header_len);
        defer record.deinit(allocator);

        record.expandToCapacity();
        const header_bytes_read = try self.raw_input.reader().readAll(record.items);
        if (header_bytes_read == 0) {
            // RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
            // is an error, but popular web sites seem to do this, so we accept it
            // if and only if at the record boundary.
            return error.EndOfStream;
        } else if (header_bytes_read < record_header_len) {
            return error.UnexpectedEof;
        }

        var fbs = io.fixedBufferStream(record.items);
        var r = fbs.reader();
        const rec_type = try r.readEnum(RecordType, .Big);
        const rec_ver = try r.readEnum(ProtocolVersion, .Big);
        const payload_len = try r.readIntBig(u16);
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
            try record.resize(allocator, record_header_len + payload_len);
            const payload_bytes_read = try self.raw_input.reader().readAll(
                record.items[record_header_len..],
            );
            if (payload_bytes_read < payload_len) {
                return error.UnexpectedEof;
            }
            break :blk try self.in.decrypt(allocator, record);
        };
        errdefer allocator.free(data);

        if (rec_type != .alert and rec_type != .change_cipher_spec and data.len > 0) {
            // This is a state-advancing message: reset the retry count.
            self.retry_count = 0;
        }

        switch (rec_type) {
            .handshake => {
                self.handshake_bytes = data;
            },
            .change_cipher_spec => {
                defer allocator.free(data);
                if (data.len != 1 or data[0] != 1) {
                    // TODO: send alert
                    return error.AlertDecodeError;
                }
                // Handshake messages are not allowed to fragment across the CCS.
                if (self.handshake_bytes.len > 0) {
                    // TODO: send alert
                    return error.UnexpectedMessage;
                }
                // In TLS 1.3, change_cipher_spec records are ignored until the
                // Finished. See RFC 8446, Appendix D.4. Note that according to Section
                // 5, a server can send a ChangeCipherSpec before its ServerHello, when
                // c.vers is still unset. That's not useful though and suspicious if the
                // server then selects a lower protocol version, so don't allow that.
                if (self.version.? == .v1_3) {
                    // TODO: implement
                    @panic("not implemented yet");
                }

                if (!expect_change_cipher_spec) {
                    // TODO: send alert
                    return error.UnexpectedMessage;
                }
                try self.in.changeCipherSpec();
            },
            else => {
                // TODO: send alert
                return error.UnexpectedMessage;
            },
        }
    }
};

const HalfConn = struct {
    ver: ?ProtocolVersion = null,
    cipher: ?Aead = null,

    seq: [8]u8 = [_]u8{0} ** 8, // 64-bit sequence number
    scratch_buf: [13]u8 = [_]u8{0} ** 13, // to avoid allocs; interface method args escape

    next_cipher: ?Aead = null,

    fn encrypt(
        self: *HalfConn,
        allocator: mem.Allocator,
        record: *std.ArrayListUnmanaged(u8),
        payload: []const u8,
    ) !void {
        std.log.debug(
            "HalfConn.encrypt start record.ptr=0x{x}, record.items.len={}",
            .{ @ptrToInt(record.items.ptr), record.items.len },
        );
        if (self.cipher) |*cipher| {
            var explicit_nonce: ?[]u8 = null;
            const explicit_nonce_len = self.explicitNonceLen();
            if (explicit_nonce_len > 0) {
                const rec_old_len = record.items.len;
                try record.resize(allocator, rec_old_len + explicit_nonce_len);
                std.log.debug(
                    "HalfConn.encrypt after resize for explicit_nonce record.ptr=0x{x}, record.items.len={}",
                    .{ @ptrToInt(record.items.ptr), record.items.len },
                );
                explicit_nonce = record.items[rec_old_len..];
                std.log.debug(
                    "HalfConn.encrypt after resize for explicit_nonce[0]#1={x}",
                    .{explicit_nonce.?[0]},
                );
                explicit_nonce.?[0] = '\x01';
                std.log.debug(
                    "HalfConn.encrypt after resize for explicit_nonce[0]#2={x}",
                    .{explicit_nonce.?[0]},
                );

                // TODO: implement if (isCBC) {
                // } else {
                std.crypto.random.bytes(explicit_nonce.?);
                std.log.debug(
                    "HalfConn.encrypt after random.bytes record={}",
                    .{fmtx.fmtSliceHexEscapeLower(record.items)},
                );
                // }
            }
            const nonce: []const u8 = if (explicit_nonce_len > 0) explicit_nonce.? else &self.seq;
            if (self.ver.? == .v1_3) {
                @panic("not implemented yet");
            } else {
                mem.copy(u8, self.scratch_buf[0..], &self.seq);
                mem.copy(u8, self.scratch_buf[self.seq.len..], record.items[0..record_header_len]);
                const additional_data = self.scratch_buf[0 .. self.seq.len + record_header_len];
                std.log.debug(
                    "HalfConn.encrypt before cipher.encrypt, record.ptr=0x{x}, record.len={}, nonce.ptr=0x{x}, nonce.len={}",
                    .{ @ptrToInt(record.items.ptr), record.items.len, @ptrToInt(nonce.ptr), nonce.len },
                );
                try cipher.encrypt(allocator, record, nonce, payload, additional_data);
            }

            // Update length to include nonce, MAC and any block padding needed.
            std.log.debug("HalfConn.encrypt updated record.items.len={}", .{record.items.len});
            const n = record.items.len - record_header_len;
            mem.writeIntBig(u16, record.items[3..5], @intCast(u16, n));
            self.incSeq();
        } else {
            try record.appendSlice(allocator, payload);
        }
    }

    fn decrypt(
        self: *HalfConn,
        allocator: mem.Allocator,
        record: []const u8,
    ) ![]const u8 {
        var plaintext: []const u8 = undefined;
        const rec_type = @intToEnum(RecordType, record[0]);
        var payload = record[record_header_len..];

        // In TLS 1.3, change_cipher_spec messages are to be ignored without being
        // decrypted. See RFC 8446, Appendix D.4.
        if (self.ver) |con_ver| {
            if (con_ver == .v1_3 and rec_type == .change_cipher_spec) {
                return try allocator.dupe(u8, payload);
            }
        }

        const explicit_nonce_len = self.explicitNonceLen();

        if (self.cipher) |*cipher| {
            if (payload.len < explicit_nonce_len) {
                return error.BadRecordMac;
            }
            const nonce = if (explicit_nonce_len == 0)
                &self.seq
            else
                payload[0..explicit_nonce_len];
            const ciphertext_and_tag = payload[explicit_nonce_len..];
            std.log.debug(
                "HalfConn.decrypt nonce={}, ciphertext_and_tag={}",
                .{
                    fmtx.fmtSliceHexEscapeLower(nonce),
                    fmtx.fmtSliceHexEscapeLower(ciphertext_and_tag),
                },
            );
            var additional_data: []const u8 = undefined;
            if (self.ver.? == .v1_3) {
                @panic("not implemented yet");
            } else {
                mem.copy(u8, &self.scratch_buf, &self.seq);
                mem.copy(u8, self.scratch_buf[self.seq.len..], record[0..3]);
                const n = ciphertext_and_tag.len - cipher.overhead();
                std.log.debug("ciphertext_and_tag.len={}, cipher.overhead={}", .{
                    ciphertext_and_tag.len, cipher.overhead(),
                });
                mem.writeIntBig(u16, self.scratch_buf[self.seq.len + 3 .. self.seq.len + 5], @intCast(u16, n));
                additional_data = self.scratch_buf[0 .. self.seq.len + 5];
            }
            std.log.debug(
                "HalfConn.decrypt additional_data={}",
                .{fmtx.fmtSliceHexEscapeLower(additional_data)},
            );

            var dest = std.ArrayListUnmanaged(u8){};
            errdefer dest.deinit(allocator);
            try cipher.decrypt(allocator, &dest, nonce, ciphertext_and_tag, additional_data);
            plaintext = dest.items;
        } else {
            plaintext = try allocator.dupe(u8, payload);
        }

        self.incSeq();
        return plaintext;
    }

    // explicitNonceLen returns the number of bytes of explicit nonce or IV included
    // in each record. Explicit nonces are present only in CBC modes after TLS 1.0
    // and in certain AEAD modes in TLS 1.2.
    pub fn explicitNonceLen(self: *HalfConn) usize {
        return if (self.cipher) |cipher| cipher.explicitNonceLen() else 0;
    }

    // prepareCipherSpec sets the encryption and MAC states
    // that a subsequent changeCipherSpec will use.
    pub fn prepareCipherSpec(self: *HalfConn, ver: ProtocolVersion, cipher: Aead) void {
        self.ver = ver;
        self.next_cipher = cipher;
    }

    // changeCipherSpec changes the encryption and MAC states
    // to the ones previously passed to prepareCipherSpec.
    pub fn changeCipherSpec(self: *HalfConn) !void {
        if (self.next_cipher) |_| {} else {
            if (self.ver.? == .v1_3) {
                return error.AlertInternal;
            }
        }
        self.cipher = self.next_cipher;
        self.next_cipher = null;
        mem.set(u8, &self.seq, 0);
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

test "halfConn encrypt decrypt" {
    const PrefixNonceAeadAes128Gcm = @import("cipher_suites.zig").PrefixNonceAeadAes128Gcm;
    const nonce_prefix_length = @import("cipher_suites.zig").nonce_prefix_length;

    testing.log_level = .debug;

    const allocator = testing.allocator;

    var out_buf = try std.ArrayListUnmanaged(u8).initCapacity(allocator, record_header_len);
    defer out_buf.deinit(allocator);

    const key = [_]u8{'k'} ** PrefixNonceAeadAes128Gcm.key_length;
    const nonce_prefix = [_]u8{'p'} ** nonce_prefix_length;
    var cipher = Aead.initPrefixNonceAeadAes128Gcm(&key, &nonce_prefix);
    var hc = HalfConn{ .ver = .v1_2, .cipher = cipher };

    const plaintext = "exampleplaintext";

    const rec_type: RecordType = .application_data;
    const rec_ver: ProtocolVersion = .v1_2;
    var writer = out_buf.writer(allocator);
    try writer.writeByte(@enumToInt(rec_type));
    try writer.writeIntBig(u16, @enumToInt(rec_ver));
    try writer.writeIntBig(u16, @intCast(u16, plaintext.len));

    try hc.encrypt(allocator, &out_buf, plaintext);
    std.log.debug(
        "out_buf={}, len={}",
        .{ fmtx.fmtSliceHexEscapeLower(out_buf.items), out_buf.items.len },
    );

    mem.set(u8, &hc.seq, 0);
    const decrypted = try hc.decrypt(allocator, out_buf.items);
    defer allocator.free(decrypted);
    std.log.debug("decrypted={s}", .{decrypted});
}

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

test "Config.supportedVersions" {
    // testing.log_level = .debug;
    const f = struct {
        fn f(config: Conn.Config, want_versions: []const ProtocolVersion) !void {
            const got_versions = config.supportedVersions();
            try testing.expectEqualSlices(ProtocolVersion, want_versions, got_versions);
        }
    }.f;

    try f(.{ .max_version = .v1_3, .min_version = .v1_2 }, &supported_versions);
    try f(.{ .max_version = .v1_3, .min_version = .v1_3 }, supported_versions[0..1]);
    try f(.{ .max_version = .v1_2, .min_version = .v1_2 }, supported_versions[1..]);
}
