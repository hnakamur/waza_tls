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
const HandshakeState = @import("handshake_state.zig").HandshakeState;
const ClientHandshakeState = @import("handshake_client.zig").ClientHandshakeState;
const ServerHandshakeState = @import("handshake_server.zig").ServerHandshakeState;
const Role = @import("handshake_state.zig").Role;
const Aead = @import("cipher_suites.zig").Aead;
const fmtx = @import("../fmtx.zig");
const AlertError = @import("alert.zig").AlertError;
const AlertLevel = @import("alert.zig").AlertLevel;
const AlertDescription = @import("alert.zig").AlertDescription;

const max_plain_text = 16384; // maximum plaintext payload length
const max_ciphertext = 18432;
const max_ciphertext_tls13 = 16640;
const max_useless_records = 16; // maximum number of consecutive non-advancing records

const record_header_len = 5;

// tcp_mss_estimate is a conservative estimate of the TCP maximum segment
// size (MSS). A constant is used, rather than querying the kernel for
// the actual MSS, to avoid complexity. The value here is the IPv6
// minimum MTU (1280 bytes) minus the overhead of an IPv6 header (40
// bytes) and a TCP header with timestamps (32 bytes).
const tcp_mss_estimate = 1208;

// record_size_boost_threshold is the number of bytes of application data
// sent after which the TLS record size will be increased to the
// maximum.
const record_size_boost_threshold = 128 * 1024;

// Currently Conn is not thread-safe.
pub const Conn = struct {
    pub const Config = struct {
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

    const FifoType = fifo.LinearFifo(u8, .{ .Static = max_plain_text });
    config: Config,
    role: Role,
    allocator: mem.Allocator,
    stream: net.Stream,
    in: HalfConn,
    out: HalfConn,
    version: ?ProtocolVersion = null,
    buffering: bool = false,
    send_buf: std.ArrayListUnmanaged(u8) = .{},
    packets_sent: usize = 0,
    bytes_sent: usize = 0,
    handshake_complete: bool = false,
    raw_input: io.BufferedReader(4096, net.Stream.Reader),
    input: FifoType = FifoType.init(),
    retry_count: usize = 0,
    handshake_bytes: []const u8 = &[_]u8{},
    handshake_state: ?HandshakeState = null,
    close_notify_sent: bool = false,
    close_notify_err: ?anyerror = null,

    // clientFinished and serverFinished contain the Finished message sent
    // by the client or server in the most recent handshake. This is
    // retained to support the renegotiation extension and tls-unique
    // channel-binding.
    client_finished: [finished_verify_length]u8 = undefined,
    server_finished: [finished_verify_length]u8 = undefined,

    pub fn init(
        allocator: mem.Allocator,
        role: Role,
        stream: net.Stream,
        in: HalfConn,
        out: HalfConn,
        config: Config,
    ) Conn {
        return .{
            .allocator = allocator,
            .role = role,
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
        if (self.handshake_state) |*hs| hs.deinit(allocator);
    }

    pub fn write(self: *Conn, bytes: []const u8) !usize {
        if (self.out.err) |err| {
            return err;
        }
        try self.handshake(self.allocator);
        try self.writeRecord(self.allocator, .application_data, bytes);
        return 0; // TODO: return number of bytes written
    }

    pub fn read(self: *Conn, buffer: []u8) !usize {
        try self.handshake(self.allocator);
        if (buffer.len == 0) {
            // Put this after Handshake, in case people were calling
            // Read(nil) for the side effect of the Handshake.
            return 0;
        }

        while (self.input.readableLength() == 0) {
            try self.readRecord(self.allocator);
            if (self.handshake_bytes.len > 0) {
                @panic("not implemented yet");
            }
        }

        const n = self.input.read(buffer);

        // If a close-notify alert is waiting, read it so that we can return (n,
        // EOF) instead of (n, nil), to signal to the HTTP response reading
        // goroutine that the connection is now closed. This eliminates a race
        // where the HTTP response reading goroutine would otherwise not observe
        // the EOF until its next read, by which time a client goroutine might
        // have already tried to reuse the HTTP connection for a new request.
        // See https://golang.org/cl/76400046 and https://golang.org/issue/3514
        if (n > 0 and self.input.readableLength() == 0 and
            self.raw_input.fifo.readableLength() > 0 and
            @intToEnum(RecordType, self.raw_input.fifo.readableSlice(0)[0]) == .alert)
        {
            try self.readRecord(self.allocator);
        }
        return n;
    }

    pub fn close(self: *Conn) !void {
        var alert_err: ?anyerror = null;
        if (self.handshake_complete) {
            if (self.closeNotify()) |_| {} else |err| alert_err = err;
        }
        self.stream.close();
        if (alert_err) |err| {
            return err;
        }
    }

    fn closeNotify(self: *Conn) !void {
        if (!self.close_notify_sent) {
            // TODO: set write timeout
            self.sendAlert(.close_notify) catch |err| {
                self.close_notify_err = err;
            };
            self.close_notify_sent = true;
        }
        if (self.close_notify_err) |err| {
            return err;
        }
    }

    fn sendAlert(self: *Conn, desc: AlertDescription) !void {
        const level = desc.level();
        std.log.debug("Conn.sendAlert, level={}, desc={}", .{ level, desc });
        const data = [_]u8{ @enumToInt(level), @enumToInt(desc) };
        self.writeRecord(self.allocator, .alert, &data) catch |w_err| {
            std.log.err("Conn.sendAlert, w_err={s}", .{@errorName(w_err)});
            if (desc == .close_notify) {
                std.log.err("Conn.sendAlert, return w_err={s}", .{@errorName(w_err)});
                return w_err;
            }
        };
        const err = desc.toError();
        std.log.debug("Conn.sendAlert, return err={s}", .{@errorName(err)});
        return self.out.setError(err);
    }

    pub fn handshake(self: *Conn, allocator: mem.Allocator) !void {
        if (!self.handshake_complete) {
            const handshake_fn = switch (self.role) {
                .client => clientHandshake,
                .server => serverHandshake,
            };
            try handshake_fn(self, allocator);
        }
    }

    pub fn clientHandshake(self: *Conn, allocator: mem.Allocator) !void {
        var client_hello = try self.makeClientHello(allocator);

        const client_hello_bytes = try client_hello.marshal(allocator);
        errdefer client_hello.deinit(allocator);
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

        self.handshake_state = HandshakeState{
            .client = ClientHandshakeState.init(self.version.?, self, client_hello, server_hello),
        };
        try self.handshake_state.?.client.handshake(allocator);
    }

    pub fn serverHandshake(self: *Conn, allocator: mem.Allocator) !void {
        const client_hello = try self.readClientHello(allocator);
        self.handshake_state = HandshakeState{
            .server = ServerHandshakeState.init(self.version.?, self, client_hello),
        };
        try self.handshake_state.?.server.handshake(allocator);
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
            self.sendAlert(.protocol_version) catch {};
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
            try self.doWrite(allocator, out_buf.items);
            n += m;
            rest = rest[m..];
        }

        if (rec_type == .change_cipher_spec) {
            if (self.version) |con_ver| {
                if (con_ver != .v1_3) {
                    std.log.debug(
                        "Conn.writeRecord calling changeCipherSpec, self=0x{x}, &self.out=0x{x}",
                        .{ @ptrToInt(self), @ptrToInt(&self.out) },
                    );
                    self.out.changeCipherSpec() catch @panic("send alert not implemented");
                }
            }
        }
    }

    fn maxPayloadSizeForWrite(self: *Conn, rec_type: RecordType) usize {
        if (rec_type != .application_data) {
            return max_plain_text;
        }

        if (self.bytes_sent >= record_size_boost_threshold) {
            return max_plain_text;
        }

        // Subtract TLS overheads to get the maximum payload size.
        var payload_bytes = tcp_mss_estimate - record_header_len - self.out.explicitNonceLen();
        if (self.out.cipher) |cipher| {
            payload_bytes -= cipher.overhead();
        }
        if (self.version) |ver| {
            if (ver == .v1_3) {
                payload_bytes -= 1; // encrypted ContentType
            }
        }

        // Allow packet growth in arithmetic progression up to max.
        const pkt = self.packets_sent;
        self.packets_sent += 1;
        if (pkt > 1000) {
            return max_plain_text; // avoid overflow in multiply below
        }

        return math.min(payload_bytes * (pkt + 1), max_plain_text);
    }

    fn doWrite(self: *Conn, allocator: mem.Allocator, data: []const u8) !void {
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
        errdefer hs_msg.deinit(allocator);
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
            self.sendAlert(.protocol_version) catch {};
            return error.ProtocolVersionMismatch;
        }

        return client_hello;
    }

    pub fn readHandshake(self: *Conn, allocator: mem.Allocator) !HandshakeMsg {
        if (self.handshake_bytes.len < handshake_msg_header_len) {
            try self.readRecord(allocator);
        }
        var msg = try HandshakeMsg.unmarshal(allocator, self.handshake_bytes);
        errdefer msg.deinit(allocator);
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
    ) anyerror!void {
        if (self.in.err) |err| {
            return err;
        }
        if (self.input.readableLength() != 0) {
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
        std.log.debug(
            "Conn.readRecordOrChangeCipherSpec self=0x{x}, rec_type={}, rec_ver={}, payload_len={}",
            .{ @ptrToInt(self), rec_type, rec_ver, payload_len },
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

        std.log.debug(
            "Conn.readRecordOrChangeCipherSpec self=0x{x}, before get data",
            .{@ptrToInt(self)},
        );
        const data = blk: {
            try record.resize(allocator, record_header_len + payload_len);
            const payload_bytes_read = try self.raw_input.reader().readAll(
                record.items[record_header_len..],
            );
            if (payload_bytes_read < payload_len) {
                return error.UnexpectedEof;
            }
            break :blk try self.in.decrypt(allocator, record.items);
        };
        errdefer allocator.free(data);
        std.log.debug(
            "Conn.readRecordOrChangeCipherSpec self=0x{x}, data={}",
            .{ @ptrToInt(self), fmtx.fmtSliceHexEscapeLower(data) },
        );

        if (rec_type != .alert and rec_type != .change_cipher_spec and data.len > 0) {
            // This is a state-advancing message: reset the retry count.
            self.retry_count = 0;
        }

        switch (rec_type) {
            .alert => {
                if (data.len != 2) {
                    self.sendAlert(.unexpected_message) catch |err| {
                        return self.in.setError(err);
                    };
                }
                const desc = @intToEnum(AlertDescription, data[1]);
                if (desc != .close_notify) {
                    return self.in.setError(error.Eof);
                }
                if (self.version) |ver| {
                    if (ver == .v1_3) {
                        return self.in.setError(error.RemoteError);
                    }
                }
                switch (@intToEnum(AlertLevel, data[0])) {
                    .warning => {
                        // Drop the record on the floor and retry.
                        return self.retryReadRecord(expect_change_cipher_spec);
                    },
                    .fatal => {
                        std.log.err("tls.Conn remote fatal error {}", .{desc});
                        return self.in.setError(error.RemoteError);
                    },
                    else => {
                        self.sendAlert(.unexpected_message) catch |err| {
                            return self.in.setError(err);
                        };
                    },
                }
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
                std.log.debug(
                    "Conn.readRecordOrChangeCipherSpec calling changeCipherSpec, self=0x{x}, &self.in=0x{x}",
                    .{ @ptrToInt(self), @ptrToInt(&self.in) },
                );
                try self.in.changeCipherSpec();
            },
            .application_data => {
                try self.input.write(data);
                allocator.free(data);
            },
            .handshake => {
                if (data.len == 0 or expect_change_cipher_spec) {
                    if (self.sendAlert(.unexpected_message)) |_| {} else |err| {
                        return self.in.setError(err);
                    }
                }
                self.handshake_bytes = data;
            },
        }
    }

    fn retryReadRecord(
        self: *Conn,
        expect_change_cipher_spec: bool,
    ) anyerror!void {
        self.retry_count += 1;
        if (self.retry_count > max_useless_records) {
            self.sendAlert(.unexpected_message) catch {};
            return self.in.setError(error.TooManyIgnoredRecords);
        }
        try self.readRecordOrChangeCipherSpec(self.allocator, expect_change_cipher_spec);
    }
};

const HalfConn = struct {
    ver: ?ProtocolVersion = null,
    cipher: ?Aead = null,

    seq: [8]u8 = [_]u8{0} ** 8, // 64-bit sequence number
    scratch_buf: [13]u8 = [_]u8{0} ** 13, // to avoid allocs; interface method args escape

    next_cipher: ?Aead = null,
    err: ?anyerror = null,

    fn encrypt(
        self: *HalfConn,
        allocator: mem.Allocator,
        record: *std.ArrayListUnmanaged(u8),
        payload: []const u8,
    ) !void {
        std.log.debug(
            "HalfConn.encrypt start, self=0x{x}, self.cipher={}",
            .{ @ptrToInt(self), self.cipher },
        );
        if (self.cipher) |*cipher| {
            var explicit_nonce: ?[]u8 = null;
            const explicit_nonce_len = self.explicitNonceLen();
            if (explicit_nonce_len > 0) {
                const rec_old_len = record.items.len;
                try record.resize(allocator, rec_old_len + explicit_nonce_len);
                explicit_nonce = record.items[rec_old_len..];

                // TODO: implement if (isCBC) {
                // } else {
                std.crypto.random.bytes(explicit_nonce.?);
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
                    "HalfConn.encrypt, self=0x{x}, record.items={}, nonce={}, payload={}, additional_data={}",
                    .{
                        @ptrToInt(self),
                        fmtx.fmtSliceHexEscapeLower(record.items),
                        fmtx.fmtSliceHexEscapeLower(nonce),
                        fmtx.fmtSliceHexEscapeLower(payload),
                        fmtx.fmtSliceHexEscapeLower(additional_data),
                    },
                );
                try cipher.encrypt(allocator, record, nonce, payload, additional_data);
                std.log.debug(
                    "HalfConn.encrypt, self=0x{x}, encrypted record.items={}",
                    .{
                        @ptrToInt(self),
                        fmtx.fmtSliceHexEscapeLower(record.items),
                    },
                );
            }

            // Update length to include nonce, MAC and any block padding needed.
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
        std.log.debug(
            "HalfConn.decrypt, self=0x{x}, rec_type={}, record.len={}, self.cipher={}",
            .{
                @ptrToInt(self),
                rec_type,
                record.len,
                self.cipher,
            },
        );
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
            var additional_data: []const u8 = undefined;
            if (self.ver.? == .v1_3) {
                @panic("not implemented yet");
            } else {
                mem.copy(u8, &self.scratch_buf, &self.seq);
                mem.copy(u8, self.scratch_buf[self.seq.len..], record[0..3]);
                const n = ciphertext_and_tag.len - cipher.overhead();
                mem.writeIntBig(u16, self.scratch_buf[self.seq.len + 3 .. self.seq.len + 5], @intCast(u16, n));
                additional_data = self.scratch_buf[0 .. self.seq.len + 5];
            }

            var dest = std.ArrayListUnmanaged(u8){};
            errdefer dest.deinit(allocator);
            std.log.debug(
                "HalfConn.decrypt, before decrypt self=0x{x}, nonce={}, ciphertext_and_tag={}, additional_data={}",
                .{
                    @ptrToInt(self),
                    fmtx.fmtSliceHexEscapeLower(nonce),
                    fmtx.fmtSliceHexEscapeLower(ciphertext_and_tag),
                    fmtx.fmtSliceHexEscapeLower(additional_data),
                },
            );
            cipher.decrypt(allocator, &dest, nonce, ciphertext_and_tag, additional_data) catch |err| {
                std.log.debug(
                    "HalfConn.decrypt, self=0x{x}, decrpyt err: {s}",
                    .{ @ptrToInt(self), @errorName(err) },
                );
                return err;
            };
            plaintext = dest.items;
            std.log.debug(
                "HalfConn.decrypt, exit self=0x{x}, plaintext={}",
                .{ @ptrToInt(self), fmtx.fmtSliceHexEscapeLower(plaintext) },
            );
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
        std.log.debug(
            "HalfConn.prepareCipherSpec start, self=0x{x}, self.cipher={}",
            .{ @ptrToInt(self), self.cipher },
        );
    }

    // changeCipherSpec changes the encryption and MAC states
    // to the ones previously passed to prepareCipherSpec.
    pub fn changeCipherSpec(self: *HalfConn) !void {
        std.log.debug("HalfConn.changeCipherSpec start, self=0x{x}", .{@ptrToInt(self)});
        if (self.next_cipher) |_| {} else {
            if (self.ver.? == .v1_3) {
                return error.AlertInternal;
            }
        }
        self.cipher = self.next_cipher;
        std.log.debug(
            "HalfConn.changeCipherSpec set cipher, self=0x{x}, self.cipher={}",
            .{ @ptrToInt(self), self.cipher },
        );
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

    fn setError(self: *HalfConn, err: anyerror) !void {
        self.err = err;
        return err;
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

    mem.set(u8, &hc.seq, 0);
    const decrypted = try hc.decrypt(allocator, out_buf.items);
    defer allocator.free(decrypted);

    try testing.expectEqualStrings(plaintext, decrypted);
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
