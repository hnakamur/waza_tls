const std = @import("std");
const assert = std.debug.assert;
const fifo = std.fifo;
const io = std.io;
const math = std.math;
const mem = std.mem;
const net = std.net;
const datetime = @import("datetime");
const memx = @import("../memx.zig");
const ClientAuthType = @import("client_auth.zig").ClientAuthType;
const CertPool = @import("cert_pool.zig").CertPool;
const CipherSuite = @import("cipher_suites.zig").CipherSuite;
const default_cipher_suites = @import("cipher_suites.zig").default_cipher_suites;
const makeCipherPreferenceList = @import("cipher_suites.zig").makeCipherPreferenceList;
const CipherSuiteTls13 = @import("cipher_suites.zig").CipherSuiteTls13;
const cipherSuiteTls13ById = @import("cipher_suites.zig").cipherSuiteTls13ById;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const CurveId = @import("handshake_msg.zig").CurveId;
const EcPointFormat = @import("handshake_msg.zig").EcPointFormat;
const HandshakeMsg = @import("handshake_msg.zig").HandshakeMsg;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const KeyUpdateMsg = @import("handshake_msg.zig").KeyUpdateMsg;
const KeyShare = @import("handshake_msg.zig").KeyShare;
const PskMode = @import("handshake_msg.zig").PskMode;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const NewSessionTicketMsgTls13 = @import("handshake_msg.zig").NewSessionTicketMsgTls13;
const generateRandom = @import("handshake_msg.zig").generateRandom;
const random_length = @import("handshake_msg.zig").random_length;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const PskIdentity = @import("handshake_msg.zig").PskIdentity;
const handshake_msg_header_len = @import("handshake_msg.zig").handshake_msg_header_len;
const finished_verify_length = @import("prf.zig").finished_verify_length;
const RecordType = @import("record.zig").RecordType;
const HandshakeState = @import("handshake_state.zig").HandshakeState;
const ClientHandshakeState = @import("handshake_client.zig").ClientHandshakeState;
const ServerHandshakeState = @import("handshake_server.zig").ServerHandshakeState;
const ClientHandshakeStateTls12 = @import("handshake_client.zig").ClientHandshakeStateTls12;
const ClientHandshakeStateTls13 = @import("handshake_client_tls13.zig").ClientHandshakeStateTls13;
const Role = @import("handshake_state.zig").Role;
const Aead = @import("cipher_suites.zig").Aead;
const fmtx = @import("../fmtx.zig");
const AlertError = @import("alert.zig").AlertError;
const AlertLevel = @import("alert.zig").AlertLevel;
const AlertDescription = @import("alert.zig").AlertDescription;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const mutualCipherSuiteTls12 = @import("cipher_suites.zig").mutualCipherSuiteTls12;
const x509 = @import("x509.zig");
const VerifyOptions = @import("verify.zig").VerifyOptions;
const supported_signature_algorithms = @import("common.zig").supported_signature_algorithms;
const EcdheParameters = @import("key_schedule.zig").EcdheParameters;
const selectSignatureScheme = @import("auth.zig").selectSignatureScheme;
const LoadSessionResult = @import("session.zig").LoadSessionResult;
const LruSessionCache = @import("session.zig").LruSessionCache;
const resumption_label = @import("key_schedule.zig").resumption_label;
const resumption_binder_label = @import("key_schedule.zig").resumption_binder_label;
const crypto = @import("crypto.zig");
const ClientSessionState = @import("session.zig").ClientSessionState;
const TicketKey = @import("ticket.zig").TicketKey;
const tiket_key_lifetime_seconds = @import("ticket.zig").tiket_key_lifetime_seconds;
const ticket_key_rotation_seconds = @import("ticket.zig").ticket_key_rotation_seconds;
const max_session_ticket_lifetime_seconds = @import("common.zig").max_session_ticket_lifetime_seconds;
const common = @import("common.zig");

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

const default_curve_preferences = [_]CurveId{
    .x25519,
    .secp256r1,
    .secp384r1,
    .secp521r1,
};

// downgrade_canary_tls12 or downgrade_canary_tls11 is embedded in the server
// random as a downgrade protection if the server would be capable of
// negotiating a higher version. See RFC 8446, Section 4.1.3.
pub const downgrade_canary_tls12 = "DOWNGRD\x01";
const downgrade_canary_tls11 = "DOWNGRD\x00";

pub const KeyLog = struct {
    pub const label_tls12 = "CLIENT_RANDOM";
    pub const label_client_handshake = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    pub const label_server_handshake = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
    pub const label_client_traffic = "CLIENT_TRAFFIC_SECRET_0";
    pub const label_server_traffic = "SERVER_TRAFFIC_SECRET_0";

    // key_log_writer_mutex protects all KeyLogWriters globally. It is rarely enabled,
    // and is only for debugging, so a global mutex saves space.
    var writer_mutex = std.Thread.Mutex{};
};

pub const KeyLogger = struct {
    ptr: *anyopaque,
    writeFn: fn (ptr: *anyopaque, buf: []const u8) anyerror!usize,

    pub fn init(
        pointer: anytype,
        comptime writeFn: fn (ptr: @TypeOf(pointer), buf: []const u8) anyerror!usize,
    ) KeyLogger {
        const Ptr = @TypeOf(pointer);
        assert(@typeInfo(Ptr) == .Pointer); // Must be a pointer
        assert(@typeInfo(Ptr).Pointer.size == .One); // Must be a single-item pointer
        assert(@typeInfo(@typeInfo(Ptr).Pointer.child) == .Struct); // Must point to a struct
        const gen = struct {
            fn write(ptr: *anyopaque, buf: []const u8) !usize {
                const alignment = @typeInfo(Ptr).Pointer.alignment;
                const self = @ptrCast(Ptr, @alignCast(alignment, ptr));
                return writeFn(self, buf);
            }
        };

        return .{
            .ptr = pointer,
            .writeFn = gen.write,
        };
    }

    pub fn write(l: KeyLogger, buf: []const u8) !usize {
        return try l.writeFn(l.ptr, buf);
    }
};

pub const FileKeyLogger = struct {
    const Self = @This();
    file: std.fs.File,

    pub fn init(file: std.fs.File) Self {
        return .{ .file = file };
    }

    pub fn keyLogger(self: *Self) KeyLogger {
        return KeyLogger.init(self, write);
    }

    pub fn write(self: *Self, buf: []const u8) !usize {
        return self.file.write(buf);
    }
};

// RenegotiationSupport enumerates the different levels of support for TLS
// renegotiation. TLS renegotiation is the act of performing subsequent
// handshakes on a connection after the first. This significantly complicates
// the state machine and has been the source of numerous, subtle security
// issues. Initiating a renegotiation is not supported, but support for
// accepting renegotiation requests may be enabled.
//
// Even when enabled, the server may not change its identity between handshakes
// (i.e. the leaf certificate must be the same). Additionally, concurrent
// handshake and application data flow is not permitted so renegotiation can
// only be used with protocols that synchronise with the renegotiation, such as
// HTTPS.
//
// Renegotiation is not defined in TLS 1.3.
pub const RenegotiationSupport = enum {
    // RenegotiateNever disables renegotiation.
    never,

    // RenegotiateOnceAsClient allows a remote server to request
    // renegotiation once per connection.
    once_as_client,

    // RenegotiateFreelyAsClient allows a remote server to repeatedly
    // request renegotiation.
    freely_as_client,
};

// Currently Conn is not thread-safe.
pub const Conn = struct {
    pub const Config = struct {
        // random provides the source of entropy for nonces and RSA blinding.
        // If Rand is nil, TLS uses the cryptographic random reader in package
        // crypto/rand.
        // The Reader must be safe for use by multiple goroutines.
        random: std.rand.Random = std.crypto.random,

        timestamp_seconds_fn: fn () i64 = std.time.timestamp,

        // certificates contains one or more certificate chains to present to the
        // other side of the connection. The first certificate compatible with the
        // peer's requirements is selected automatically.
        //
        // Server configurations must set one of certificates, GetCertificate or
        // GetConfigForClient. Clients doing client-authentication may set either
        // certificates or GetClientCertificate.
        //
        // Note: if there are multiple certificates, and they don't have the
        // optional field Leaf set, certificate selection will incur a significant
        // per-handshake performance cost.
        certificates: []CertificateChain = &[_]CertificateChain{},

        // next_protos is a list of supported application level protocols, in
        // order of preference. If both peers support ALPN, the selected
        // protocol will be one from this list, and the connection will fail
        // if there is no mutually supported protocol. If NextProtos is empty
        // or the peer doesn't support ALPN, the connection will succeed and
        // ConnectionState.NegotiatedProtocol will be empty.
        next_protos: []const []const u8 = &[_][]u8{},

        // server_name is used to verify the hostname on the returned
        // certificates unless InsecureSkipVerify is given. It is also included
        // in the client's handshake to support virtual hosting unless it is
        // an IP address.
        server_name: []const u8 = "",

        // client_auth determines the server's policy for
        // TLS Client Authentication. The default is NoClientCert.
        client_auth: ClientAuthType = .no_client_cert,

        // client_cas defines the set of root certificate authorities
        // that servers use if required to verify a client certificate
        // by the policy in ClientAuth.
        client_cas: ?CertPool = null,

        // insecure_skip_verify controls whether a client verifies the server's
        // certificate chain and host name. If insecure_skip_verify is true, crypto/tls
        // accepts any certificate presented by the server and any host name in that
        // certificate. In this mode, TLS is susceptible to machine-in-the-middle
        // attacks unless custom verification is used. This should be used only for
        // testing or in combination with VerifyConnection or VerifyPeerCertificate.
        insecure_skip_verify: bool = false,

        // cipher_suites is a list of enabled TLS 1.0–1.2 cipher suites. The order of
        // the list is ignored. Note that TLS 1.3 ciphersuites are not configurable.
        //
        // If CipherSuites is nil, a safe default list is used. The default cipher
        // suites might change over time.
        cipher_suites: []const CipherSuiteId = &default_cipher_suites,

        // session_tickets_disabled may be set to true to disable session ticket and
        // PSK (resumption) support. Note that on clients, session ticket support is
        // also disabled if ClientSessionCache is nil.
        session_tickets_disabled: bool = false,

        // client_session_cache is a cache of ClientSessionState entries for TLS
        // session resumption. It is only used by clients.
        client_session_cache: ?LruSessionCache = null,

        // min_version contains the minimum TLS version that is acceptable.
        //
        // By default, TLS 1.2 is currently used as the minimum when acting as a
        // client, and TLS 1.0 when acting as a server. TLS 1.0 is the minimum
        // supported by this package, both as a client and as a server.
        //
        // The client-side default can temporarily be reverted to TLS 1.0 by
        // including the value "x509sha1=1" in the GODEBUG environment variable.
        // Note that this option will be removed in Go 1.19 (but it will still be
        // possible to set this field to VersionTLS10 explicitly).
        min_version: ProtocolVersion = .v1_2,

        // max_version contains the maximum TLS version that is acceptable.
        //
        // By default, the maximum version supported by this package is used,
        // which is currently TLS 1.3.
        max_version: ProtocolVersion = .v1_3,

        // curve_preferences contains the elliptic curves that will be used in
        // an ECDHE handshake, in preference order. If empty, the default will
        // be used. The client will use the first preference as the type for
        // its key share in TLS 1.3. This may change in the future.
        curve_preferences: []const CurveId = &default_curve_preferences,

        // Renegotiation controls what types of renegotiation are supported.
        // The default, none, is correct for the vast majority of applications.
        renegotiation: RenegotiationSupport = .never,

        // session_ticket_keys contains zero or more ticket keys. If set, it means the
        // the keys were set with SessionTicketKey or SetSessionTicketKeys. The
        // first key is used for new tickets and any subsequent keys can be used to
        // decrypt old tickets. The slice contents are not protected by the mutex
        // and are immutable.
        session_ticket_keys: []TicketKey = &.{},
        // auto_session_ticket_keys is like sessionTicketKeys but is owned by the
        // auto-rotation logic. See Config.ticketKeys.
        auto_session_ticket_keys: []TicketKey = &.{},

        key_logger: ?KeyLogger = null,

        pub fn deinit(self: *Config, allocator: mem.Allocator) void {
            memx.deinitSliceAndElems(CertificateChain, self.certificates, allocator);
            if (self.client_cas) |*cas| cas.deinit();
            if (self.client_session_cache) |*cache| cache.deinit();
            allocator.free(self.session_ticket_keys);
            allocator.free(self.auto_session_ticket_keys);
        }

        pub fn maxSupportedVersion(self: *const Config) ProtocolVersion {
            const sup_vers = self.supportedVersions();
            assert(sup_vers.len > 0);
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

        pub fn supportsCurve(self: *const Config, curve: CurveId) bool {
            return memx.containsScalar(CurveId, self.curve_preferences, curve);
        }

        pub fn getCertificate(self: *const Config) *CertificateChain {
            std.log.info("Config.getCertificate, self.certificates.len={}", .{self.certificates.len});
            return &self.certificates[0];
        }

        pub fn ticketKeys(
            self: *Config,
            allocator: mem.Allocator,
            config_for_client: ?*const Config,
        ) ![]TicketKey {
            // TODO: lock self

            if (config_for_client) |cli_conf| {
                _ = cli_conf;
                @panic("not implemented yet");
            }

            if (self.session_tickets_disabled) {
                return &[_]TicketKey{};
            }
            if (self.session_ticket_keys.len > 0) {
                return try allocator.dupe(TicketKey, self.session_ticket_keys);
            }
            // Fast path for the common case where the key is fresh enough.
            if (self.auto_session_ticket_keys.len > 0 and
                ((datetime.datetime.Datetime.now().toTimestamp() -
                self.auto_session_ticket_keys[0].created.toTimestamp()) <
                ticket_key_rotation_seconds * std.time.ms_per_s))
            {
                return try allocator.dupe(TicketKey, self.auto_session_ticket_keys);
            }

            // auto_session_ticket_keys are managed by auto-rotation.

            // Re-check the condition in case it changed since obtaining the new lock.
            if (self.auto_session_ticket_keys.len == 0 or
                ((datetime.datetime.Datetime.now().toTimestamp() -
                self.auto_session_ticket_keys[0].created.toTimestamp()) >=
                ticket_key_rotation_seconds * std.time.ms_per_s))
            {
                var new_key: [32]u8 = undefined;
                self.random.bytes(&new_key);

                var valid_keys = try std.ArrayList(TicketKey).initCapacity(
                    allocator,
                    self.auto_session_ticket_keys.len + 1,
                );
                std.log.info("Config.ticketKeys initialized valid_keys, ptr=0x{x}", .{@ptrToInt(valid_keys.items.ptr)});
                errdefer valid_keys.deinit();
                try valid_keys.append(self.ticketKeyFromBytes(new_key));
                for (self.auto_session_ticket_keys) |key| {
                    // While rotating the current key, also remove any expired ones.
                    if ((datetime.datetime.Datetime.now().toTimestamp() -
                        key.created.toTimestamp()) <
                        tiket_key_lifetime_seconds * std.time.ms_per_s)
                    {
                        try valid_keys.append(key);
                    }
                }
                allocator.free(self.auto_session_ticket_keys);
                self.auto_session_ticket_keys = valid_keys.toOwnedSlice();
                std.log.info(
                    "Config.ticketKeys updated self.auto_session_ticket_keys, len={}, ptr=0x{x}",
                    .{ self.auto_session_ticket_keys.len, @ptrToInt(self.auto_session_ticket_keys.ptr) },
                );
            }

            return try allocator.dupe(TicketKey, self.auto_session_ticket_keys);
        }

        // ticketKeyFromBytes converts from the external representation of a session
        // ticket key to a ticketKey. Externally, session ticket keys are 32 random
        // bytes and this function expands that into sufficient name and key material.
        fn ticketKeyFromBytes(
            self: *Config,
            b: [32]u8,
        ) TicketKey {
            _ = self;
            const Sha512 = std.crypto.hash.sha2.Sha512;
            var hashed: [Sha512.digest_length]u8 = undefined;
            Sha512.hash(&b, &hashed, .{});
            return .{
                .key_name = hashed[0..TicketKey.name_len].*,
                .aes_key = hashed[TicketKey.name_len .. TicketKey.name_len + 16].*,
                .hmac_key = hashed[TicketKey.name_len + 16 .. TicketKey.name_len + 32].*,
                .created = datetime.datetime.Datetime.now(),
            };
        }

        pub fn currentTimestampSeconds(self: *Config) i64 {
            return self.timestamp_seconds_fn();
        }

        pub fn writeKeyLog(
            self: *const Config,
            allocator: mem.Allocator,
            label: []const u8,
            client_random: []const u8,
            secret: []const u8,
        ) !void {
            if (self.key_logger == null) {
                return;
            }

            const log_line = try std.fmt.allocPrint(allocator, "{s} {} {}\n", .{
                label,
                std.fmt.fmtSliceHexLower(client_random),
                std.fmt.fmtSliceHexLower(secret),
            });
            defer allocator.free(log_line);

            KeyLog.writer_mutex.lock();
            defer KeyLog.writer_mutex.unlock();
            _ = try self.key_logger.?.write(log_line);
        }
    };

    const FifoType = fifo.LinearFifo(u8, .{ .Static = max_plain_text });

    role: Role,
    allocator: mem.Allocator,
    remote_address: net.Address,
    stream: net.Stream,
    in: HalfConn,
    out: HalfConn,

    version: ?ProtocolVersion = null,
    config: *Config,

    // handshakes counts the number of handshakes performed on the
    // connection so far. If renegotiation is disabled then this is either
    // zero or one.
    handshakes: usize = 0,
    handshake_err: ?anyerror = null, // error resulting from handshake
    cipher_suite_id: ?CipherSuiteId = null,
    ocsp_response: []const u8 = "", // stapled OCSP response
    scts: []const []const u8 = &.{}, // signed certificate timestamps from server
    server_name: []const u8 = "",
    // secure_renegotiation is true if the server echoed the secure
    // renegotiation extension. (This is meaningless as a server because
    // renegotiation is not supported in that case.)
    secure_renegotiation: bool = false,

    buffering: bool = false,
    send_buf: std.ArrayListUnmanaged(u8) = .{},
    packets_sent: usize = 0,
    bytes_sent: usize = 0,
    handshake_complete: bool = false,
    raw_input: std.ArrayListUnmanaged(u8) = .{},
    input: FifoType = FifoType.init(),
    retry_count: usize = 0,
    handshake_bytes: []const u8 = "",
    client_protocol: []const u8 = "",
    close_notify_sent: bool = false,
    close_notify_err: ?anyerror = null,

    // clientFinished and serverFinished contain the Finished message sent
    // by the client or server in the most recent handshake. This is
    // retained to support the renegotiation extension and tls-unique
    // channel-binding.
    client_finished: [finished_verify_length]u8 = undefined,
    server_finished: [finished_verify_length]u8 = undefined,

    peer_certificates: []x509.Certificate = &.{},
    verified_chains: [][]x509.Certificate = &.{},

    resumption_secret: []const u8 = "",
    ticket_keys: []TicketKey = &.{},
    did_resume: bool = false,

    client_finished_is_first: bool = false,

    pub fn init(
        allocator: mem.Allocator,
        role: Role,
        remote_address: net.Address,
        stream: net.Stream,
        in: HalfConn,
        out: HalfConn,
        config: *Config,
    ) Conn {
        return .{
            .allocator = allocator,
            .role = role,
            .remote_address = remote_address,
            .stream = stream,
            .in = in,
            .out = out,
            .config = config,
        };
    }

    pub fn deinit(self: *Conn, allocator: mem.Allocator) void {
        self.send_buf.deinit(allocator);
        allocator.free(self.ocsp_response);
        memx.freeElemsAndFreeSlice([]const u8, self.scts, allocator);
        allocator.free(self.server_name);
        allocator.free(self.handshake_bytes);
        allocator.free(self.client_protocol);
        memx.deinitSliceAndElems(x509.Certificate, self.peer_certificates, allocator);
        x509.Certificate.deinitChains(self.verified_chains, allocator);
        allocator.free(self.resumption_secret);

        allocator.free(self.ticket_keys);
        self.in.deinit(allocator);
        self.out.deinit(allocator);
        self.raw_input.deinit(allocator);
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
            self.readRecord(self.allocator) catch |err| {
                if (err == error.EndOfStream) return 0;
                return err;
            };
            while (self.handshake_bytes.len > 0) {
                try self.handlePostHandshakeMessage(self.allocator);
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
            self.raw_input.items.len > 0 and
            @intToEnum(RecordType, self.raw_input.items[0]) == .alert)
        {
            self.readRecord(self.allocator) catch |err| {
                if (err == error.EndOfStream) return 0;
                return err;
            };
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
        return self.close_notify_err.?;
    }

    // handleRenegotiation processes a HelloRequest handshake message.
    fn handleRenegotiation(self: *Conn, allocator: mem.Allocator) !void {
        if (self.version.? == .v1_3) {
            return error.TlsInternalErrorUnexpectedRenegotiation;
        }

        var hello_req = blk_hello_req: {
            var hs_msg = try self.readHandshake(allocator);
            switch (hs_msg) {
                .hello_request => |msg| break :blk_hello_req msg,
                else => return self.sendAlert(.unexpected_message),
            }
        };
        defer hello_req.deinit(allocator);

        if (self.role != .client) {
            return self.sendAlert(.no_renegotiation);
        }

        switch (self.config.renegotiation) {
            .never => return self.sendAlert(.no_renegotiation),
            .once_as_client => if (self.handshakes > 1) {
                return self.sendAlert(.no_renegotiation);
            },
            .freely_as_client => {
                // Ok.
            },
        }

        // TODO: lock handshakeMutex

        // TODO: set handshakeStatus
        self.clientHandshake(allocator) catch |err| {
            self.handshake_err = err;
            return err;
        };
        self.handshakes += 1;
    }

    fn handlePostHandshakeMessage(self: *Conn, allocator: mem.Allocator) !void {
        if (self.version.? != .v1_3) {
            return self.handleRenegotiation(allocator);
        }

        var hs_msg = try self.readHandshake(allocator);
        defer hs_msg.deinit(allocator);
        self.retry_count += 1;
        if (self.retry_count > max_useless_records) {
            self.sendAlert(.unexpected_message) catch return error.TlsTooManyNonAdvancingRecords;
        }

        switch (hs_msg) {
            .new_session_ticket => |*m| {
                switch (m.*) {
                    .v1_3 => |*msg| try self.handleNewSessionTicket(allocator, msg),
                    else => @panic("unsupported tls version"),
                }
            },
            .key_update => |*msg| try self.handleKeyUpdate(allocator, msg),
            else => {
                self.sendAlert(.unexpected_message) catch
                    return error.TlsUnexpectedHandshakeMessageType;
            },
        }
    }

    fn handleKeyUpdate(
        self: *Conn,
        allocator: mem.Allocator,
        key_update: *KeyUpdateMsg,
    ) !void {
        std.log.info("handleKeyUpdate.start, updated_requested={}", .{key_update.update_requested});
        const cipher_suite = cipherSuiteTls13ById(self.cipher_suite_id.?);
        if (cipher_suite == null) {
            std.log.info("handleKeyUpdate no cipher_suite found for id", .{});
            self.sendAlert(.internal_error) catch |err| return self.in.setError(err);
        }

        const new_in_secret = try cipher_suite.?.nextTrafficSecret(
            allocator,
            self.in.traffic_secret,
        );
        try self.in.moveSetTrafficSecret(allocator, cipher_suite.?, new_in_secret);
        std.log.info("handleKeyUpdate updated self.in.traffic_secret", .{});

        if (key_update.update_requested) {
            // TODO: lock self.out

            var msg = KeyUpdateMsg{};
            defer msg.deinit(allocator);
            self.writeRecord(allocator, .handshake, try msg.marshal(allocator)) catch |err| {
                std.log.info("handleKeyUpdate failed to write KeyUpdateMsg", .{});
                // Surface the error at the next write.
                self.out.setError(err) catch {};
                return;
            };

            const new_out_secret = try cipher_suite.?.nextTrafficSecret(
                allocator,
                self.out.traffic_secret,
            );
            try self.out.moveSetTrafficSecret(allocator, cipher_suite.?, new_out_secret);
            std.log.info("handleKeyUpdate updated self.out.traffic_secret", .{});
        }
    }

    fn handleNewSessionTicket(
        self: *Conn,
        allocator: mem.Allocator,
        msg: *NewSessionTicketMsgTls13,
    ) !void {
        if (self.role != .client) {
            self.sendAlert(.unexpected_message) catch
                return error.TlsReceivedNewSessionTicketFromClient;
        }

        if (self.config.session_tickets_disabled or self.config.client_session_cache == null) {
            return;
        }

        // See RFC 8446, Section 4.6.1.
        if (msg.lifetime == 0) {
            return;
        }
        if (msg.lifetime > max_session_ticket_lifetime_seconds) {
            self.sendAlert(.illegal_parameter) catch
                return error.TlsReceivedNewSessionTicketWithInvalidLifetime;
        }

        const cipher_suite = cipherSuiteTls13ById(self.cipher_suite_id.?);
        if (cipher_suite == null or self.resumption_secret.len == 0) {
            std.log.err(
                "Conn.handleNewSessionTicket internal_error cipher_suite={}, self.resumption_secret={s}",
                .{ cipher_suite, self.resumption_secret },
            );
            return self.sendAlert(.internal_error);
        }

        // Save the resumption_master_secret and nonce instead of deriving the PSK
        // to do the least amount of work on NewSessionTicket messages before we
        // know if the ticket will be used. Forward secrecy of resumed connections
        // is guaranteed by the requirement for pskModeDHE.
        var session = blk: {
            const session_ticket = msg.label;
            msg.label = "";
            // const session_ticket = try allocator.dupe(u8, msg.label);
            // errdefer allocator.free(session_ticket);

            const master_secret = try allocator.dupe(u8, self.resumption_secret);
            errdefer allocator.free(master_secret);

            const nonce = msg.nonce;
            msg.nonce = "";

            var server_certificates = try x509.Certificate.cloneSlice(self.peer_certificates, allocator);
            errdefer memx.deinitSliceAndElems(x509.Certificate, server_certificates, allocator);

            var verified_chains = try x509.Certificate.cloneChains(self.verified_chains, allocator);
            errdefer x509.Certificate.deinitChains(verified_chains, allocator);

            const ocsp_response = try allocator.dupe(u8, self.ocsp_response);
            errdefer allocator.free(ocsp_response);

            const scts = try memx.dupeStringList(allocator, self.scts);
            errdefer memx.freeElemsAndFreeSlice([]const u8, scts, allocator);

            const now = datetime.datetime.Datetime.now();

            var s = try allocator.create(ClientSessionState);
            s.* = .{
                .session_ticket = session_ticket,
                .ver = self.version.?,
                .cipher_suite = self.cipher_suite_id.?,
                .master_secret = master_secret,
                .server_certificates = server_certificates,
                .verified_chains = verified_chains,
                .received_at = now,
                .ocsp_response = ocsp_response,
                .scts = scts,
                .nonce = nonce,
                .use_by = now.shiftSeconds(msg.lifetime),
                .age_add = msg.age_add,
            };
            break :blk s;
        };
        errdefer {
            session.deinit(allocator);
            allocator.destroy(session);
        }

        const cache_key = try clientSessionCacheKey(allocator, self.remote_address, self.config);
        defer allocator.free(cache_key);
        try self.config.client_session_cache.?.put(cache_key, session);
        std.log.info("Conn.handleNewSessionTicket put client_session_cache, cache_key={s}", .{cache_key});
    }

    // sendAlert always returns an error.
    pub fn sendAlert(self: *Conn, desc: AlertDescription) !void {
        const level = desc.level();
        std.log.debug("Conn.sendAlert, level={}, desc={}", .{ level, desc });
        const data = [_]u8{ @enumToInt(level), @enumToInt(desc) };
        self.writeRecord(self.allocator, .alert, &data) catch |w_err| {
            std.log.err("Conn.sendAlert, w_err={s}", .{@errorName(w_err)});
            if (desc == .close_notify) {
                // closeNotify is a special case in that it isn't an error.
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
        // This may be a renegotiation handshake, in which case some fields
        // need to be reset.
        self.did_resume = false;

        var load_result: ?LoadSessionResult = null;
        defer if (load_result) |*res| res.deinit(allocator);
        var handshake_state = blk: {
            var ecdhe_params: ?EcdheParameters = null;
            errdefer if (ecdhe_params) |*params| params.deinit(allocator);
            var client_hello = try self.makeClientHello(allocator, &ecdhe_params);
            errdefer client_hello.deinit(allocator);

            load_result = try self.loadSession(allocator, &client_hello);
            errdefer if (load_result.?.cache_key.len > 0 and load_result.?.session != null) {
                // If we got a handshake failure when resuming a session, throw away
                // the session ticket. See RFC 5077, Section 3.2.
                //
                // RFC 8446 makes no mention of dropping tickets on failure, but it
                // does require servers to abort on invalid binders, so we need to
                // delete tickets to recover from a corrupted PSK.
                self.config.client_session_cache.?.remove(load_result.?.cache_key);
            };

            const client_hello_bytes = try client_hello.marshal(allocator);
            try self.writeRecord(allocator, .handshake, client_hello_bytes);

            var server_hello = blk_server_hello: {
                var hs_msg = try self.readHandshake(allocator);
                switch (hs_msg) {
                    .server_hello => |sh| break :blk_server_hello sh,
                    else => return self.sendAlert(.unexpected_message),
                }
            };
            errdefer server_hello.deinit(allocator);

            try self.pickTlsVersion(&server_hello);

            // If we are negotiating a protocol version that's lower than what we
            // support, check for the server downgrade canaries.
            // See RFC 8446, Section 4.1.3.
            const max_ver = self.config.maxSupportedVersion();
            const tls12_downgrade = mem.eql(u8, server_hello.random[24..], downgrade_canary_tls12);
            const tls11_downgrade = mem.eql(u8, server_hello.random[24..], downgrade_canary_tls11);
            if ((max_ver == .v1_3 and
                @enumToInt(self.version.?) <= @enumToInt(ProtocolVersion.v1_2) and
                (tls12_downgrade or tls11_downgrade)) or
                (max_ver == .v1_2 and
                @enumToInt(self.version.?) <= @enumToInt(ProtocolVersion.v1_1) and
                tls11_downgrade))
            {
                self.sendAlert(.illegal_parameter) catch return error.DowngradeAttemptDetected;
            }

            if (self.version.? == .v1_3) {
                const early_secret = try allocator.dupe(u8, load_result.?.early_secret);
                errdefer allocator.free(early_secret);

                const binder_key = try allocator.dupe(u8, load_result.?.binder_key);
                errdefer allocator.free(binder_key);

                if (load_result.?.session) |session| session.addRef();
                break :blk ClientHandshakeState{
                    .v1_3 = ClientHandshakeStateTls13{
                        .hello = client_hello,
                        .server_hello = server_hello,
                        .conn = self,
                        .ecdhe_params = ecdhe_params.?,
                        .session = load_result.?.session,
                        .early_secret = early_secret,
                        .binder_key = binder_key,
                    },
                };
            }

            if (load_result.?.session) |session| session.addRef();
            break :blk ClientHandshakeState{
                .v1_2 = ClientHandshakeStateTls12{
                    .hello = client_hello,
                    .server_hello = server_hello,
                    .conn = self,
                    .session = load_result.?.session,
                },
            };
        };
        defer handshake_state.deinit(allocator);

        std.log.info("clientHandshake, state=0x{x}, session=0x{x}", .{
            @ptrToInt(&handshake_state),
            @ptrToInt(handshake_state.getSession()),
        });
        try handshake_state.handshake(allocator);
        if (self.version.? == .v1_3) {
            return;
        }

        // If we had a successful handshake and hs.session is different from
        // the one already cached - cache a new one.
        std.log.info("Conn.clientHandshake before checking load_result", .{});
        if (load_result) |res| {
            std.log.info("Conn.clientHandshake load_result is not null, cache_key={s}", .{res.cache_key});
            var hs_session = handshake_state.getSession();
            std.log.info("Conn.clientHandshake hs_session={any}", .{hs_session});
            if (res.cache_key.len > 0 and hs_session != null and
                (res.session == null or res.session.? != hs_session.?))
            {
                try self.config.client_session_cache.?.put(res.cache_key, hs_session.?);
                std.log.info("Conn.clientHandshake put session, cache_key={s}", .{res.cache_key});
            }
        }
    }

    pub fn serverHandshake(self: *Conn, allocator: mem.Allocator) !void {
        const client_hello = try self.readClientHello(allocator);
        var handshake_state = ServerHandshakeState.init(self.version.?, self, client_hello);
        defer handshake_state.deinit(allocator);
        try handshake_state.handshake(allocator);
    }

    fn makeClientHello(
        self: *Conn,
        allocator: mem.Allocator,
        ecdhe_params: *?EcdheParameters,
    ) !ClientHelloMsg {
        const config = self.config;
        if (config.server_name.len == 0 and !config.insecure_skip_verify) {
            return error.EitherServerNameOrInsecureSkipVerifyMustBeSpecified;
        }

        var next_protos_length: usize = 0;
        for (config.next_protos) |proto| {
            const l = proto.len;
            if (l == 0 or l > 255) {
                return error.InvalidNextProto;
            }
            next_protos_length += 1;
        }
        if (next_protos_length > 0xffff) {
            return error.TooLargeNextProtos;
        }

        const sup_vers = self.config.supportedVersions();
        if (sup_vers.len == 0) {
            return error.NoSupportedVersion;
        }

        var cli_hello_ver = self.config.maxSupportedVersion();
        std.log.debug("makeClientHello cli_hello_ver#1={}", .{cli_hello_ver});
        // The version at the beginning of the ClientHello was capped at TLS 1.2
        // for compatibility reasons. The supported_versions extension is used
        // to negotiate versions now. See RFC 8446, Section 4.2.1.
        if (@enumToInt(cli_hello_ver) > @enumToInt(ProtocolVersion.v1_2)) {
            cli_hello_ver = .v1_2;
            std.log.debug("makeClientHello cli_hello_ver#2={}", .{cli_hello_ver});
        }

        var client_hello: ClientHelloMsg = blk: {
            const random = try generateRandom(allocator, self.config.random);
            errdefer allocator.free(random);
            const session_id = try generateRandom(allocator, self.config.random);
            errdefer allocator.free(session_id);

            const cipher_suites = try makeCipherPreferenceList(
                allocator,
                sup_vers[0],
                self.config.cipher_suites,
            );

            const compression_methods = try allocator.dupe(
                CompressionMethod,
                &[_]CompressionMethod{.none},
            );
            errdefer allocator.free(compression_methods);

            const supported_curves = try allocator.dupe(
                CurveId,
                self.config.curve_preferences,
            );
            errdefer allocator.free(supported_curves);

            const supported_points = try allocator.dupe(
                EcPointFormat,
                &[_]EcPointFormat{.uncompressed},
            );
            errdefer allocator.free(supported_points);

            var sig_algs = if (@enumToInt(cli_hello_ver) >= @enumToInt(ProtocolVersion.v1_2))
                try allocator.dupe(SignatureScheme, supported_signature_algorithms)
            else
                &[_]SignatureScheme{};

            var server_name = try allocator.dupe(u8, hostnameInSni(self.config.server_name));
            errdefer allocator.free(server_name);

            break :blk ClientHelloMsg{
                .vers = cli_hello_ver,
                .random = random[0..random_length],
                .session_id = session_id[0..random_length],
                .server_name = server_name,
                .cipher_suites = cipher_suites,
                .compression_methods = compression_methods,
                .supported_curves = supported_curves,
                .supported_points = supported_points,
                .supported_signature_algorithms = sig_algs,
                .supported_versions = try allocator.dupe(ProtocolVersion, sup_vers),
            };
        };

        if (self.handshakes > 0) {
            client_hello.secure_renegotiation = try allocator.dupe(u8, &self.client_finished);
        }

        if (client_hello.supported_versions[0] == .v1_3) {
            const curve_id = self.config.curve_preferences[0];
            if (!curve_id.isSupported()) {
                return error.UnsupportedCurveInPreferences;
            }

            ecdhe_params.* = try EcdheParameters.generate(allocator, curve_id, self.config.random);

            var key_share_data = try allocator.dupe(u8, ecdhe_params.*.?.publicKey());
            errdefer allocator.free(key_share_data);
            client_hello.key_shares = try allocator.dupe(KeyShare, &[_]KeyShare{.{
                .group = curve_id,
                .data = key_share_data,
            }});
        }

        return client_hello;
    }

    fn pickTlsVersion(self: *Conn, server_hello: *const ServerHelloMsg) !void {
        const peer_ver = if (server_hello.supported_version) |sup_ver|
            sup_ver
        else
            server_hello.vers;

        const ver = self.config.mutualVersion(&[_]ProtocolVersion{peer_ver});
        if (ver == null) {
            self.sendAlert(.protocol_version) catch return error.UnsupportedVersion;
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
        switch (hs_msg) {
            .client_hello => {},
            else => try self.sendAlert(.unexpected_message),
        }
        const client_hello = hs_msg.client_hello;

        // TODO: implement for case when Config.getConfigForClient is not null.

        const ticket_keys = try self.config.ticketKeys(allocator, null);
        allocator.free(self.ticket_keys);
        self.ticket_keys = ticket_keys;
        std.log.info("Conn.readClientHello updated ticket_keys.len={}", .{self.ticket_keys.len});

        const client_versions = if (client_hello.supported_versions.len > 0)
            client_hello.supported_versions
        else
            supportedVersionsFromMax(client_hello.vers);
        self.version = self.config.mutualVersion(client_versions);
        if (self.version) |ver| {
            self.in.ver = ver;
            self.out.ver = ver;
        } else {
            self.sendAlert(.protocol_version) catch return error.ProtocolVersionMismatch;
        }

        return client_hello;
    }

    pub fn readHandshake(self: *Conn, allocator: mem.Allocator) !HandshakeMsg {
        if (self.handshake_bytes.len < handshake_msg_header_len) {
            try self.readRecord(allocator);
        }
        var msg = try HandshakeMsg.unmarshal(allocator, self.handshake_bytes, self.version);
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

    // readFromUntil reads from r into self.raw_input until self.raw_input contains
    // at least n bytes or else returns an error.
    fn readFromUntil(
        self: *Conn,
        allocator: mem.Allocator,
        reader: anytype,
        n: usize,
    ) !void {
        if (self.raw_input.items.len >= n) {
            return;
        }
        const needs = n - self.raw_input.items.len;
        std.log.debug("readFromUntil conn=0x{x}, needs={}", .{ @ptrToInt(self), needs });
        // There might be extra input waiting on the wire. Make a best effort
        // attempt to fetch it so that it can be used in (*Conn).Read to
        // "predict" closeNotify alerts.
        try self.raw_input.ensureUnusedCapacity(allocator, needs + min_read);
        var at_least_reader = atLeastReader(reader, needs);
        std.log.debug(
            "readFromUntil conn=0x{x}, raw_input=0x{x}",
            .{ @ptrToInt(self), @ptrToInt(&self.raw_input) },
        );
        try readAllToArrayList(allocator, &at_least_reader, &self.raw_input);
    }

    pub fn readRecordOrChangeCipherSpec(
        self: *Conn,
        allocator: mem.Allocator,
        expect_change_cipher_spec: bool,
    ) anyerror!void {
        std.log.debug(
            "Conn.readRecordOrChangeCipherSpec start, self=0x{x}, self.raw_input.items.len={}",
            .{ @ptrToInt(self), self.raw_input.items.len },
        );
        defer std.log.debug(
            "Conn.readRecordOrChangeCipherSpec exit, self=0x{x}, self.raw_input.items.len={}",
            .{ @ptrToInt(self), self.raw_input.items.len },
        );
        if (self.in.err) |err| {
            std.log.debug(
                "Conn.readRecordOrChangeCipherSpec early exit#1, self=0x{x}, err={s}",
                .{ @ptrToInt(self), @errorName(err) },
            );
            return err;
        }
        const handshake_complete = self.handshake_complete;
        if (self.input.readableLength() != 0) {
            std.log.debug(
                "Conn.readRecordOrChangeCipherSpec early exit#2, self=0x{x}",
                .{@ptrToInt(self)},
            );
            return error.InternalError;
        }

        self.readFromUntil(
            allocator,
            self.stream.reader(),
            record_header_len,
        ) catch |err| {
            // RFC 8446, Section 6.1 suggests that EOF without an alertCloseNotify
            // is an error, but popular web sites seem to do this, so we accept it
            // if and only if at the record boundary.
            if (err == error.UnexpectedEof and self.raw_input.items.len == 0) {
                std.log.debug(
                    "Conn.readRecordOrChangeCipherSpec early exit#3, self=0x{x}",
                    .{@ptrToInt(self)},
                );
                return error.EndOfStream;
            }

            // TODO: only set error to self.in if needed
            self.in.setError(err) catch {};
            std.log.debug(
                "Conn.readRecordOrChangeCipherSpec early exit#4, self=0x{x}, err={s}",
                .{ @ptrToInt(self), @errorName(err) },
            );
            return err;
        };
        std.log.debug(
            "Conn.readRecordOrChangeCipherSpec after readFromUntil reader_header_len, self=0x{x}, self.raw_input.items.len={}",
            .{ @ptrToInt(self), self.raw_input.items.len },
        );

        var fbs = io.fixedBufferStream(self.raw_input.items);
        var r = fbs.reader();
        var rec_type = try r.readEnum(RecordType, .Big);

        // No valid TLS record has a type of 0x80, however SSLv2 handshakes
        // start with a uint16 length where the MSB is set and the first record
        // is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
        // an SSLv2 client.
        if (!handshake_complete and @enumToInt(rec_type) == 0x80) {
            self.sendAlert(.protocol_version) catch {
                std.log.debug(
                    "Conn.readRecordOrChangeCipherSpec early exit#5, self=0x{x}",
                    .{@ptrToInt(self)},
                );
                return self.in.setError(error.UnsupportedSslV2HandshakeReceived);
            };
        }

        const rec_ver = try r.readEnum(ProtocolVersion, .Big);
        const payload_len = try r.readIntBig(u16);
        std.log.info(
            "Conn.readRecordOrChangeCipherSpec self=0x{x}, rec_type={}, rec_ver={}, payload_len={}",
            .{ @ptrToInt(self), rec_type, rec_ver, payload_len },
        );
        if (self.version) |con_ver| {
            if (con_ver != .v1_3 and rec_ver != con_ver) {
                self.sendAlert(.protocol_version) catch {
                    std.log.debug(
                        "Conn.readRecordOrChangeCipherSpec early exit#6, self=0x{x}",
                        .{@ptrToInt(self)},
                    );
                    return self.in.setError(error.InvalidRecordHeader);
                };
            }
        } else {
            // First message, be extra suspicious: this might not be a TLS
            // client. Bail out before reading a full 'body', if possible.
            // The current max version is 3.3 so if the version is >= 16.0,
            // it's probably not real.
            if ((rec_type != .alert and rec_type != .handshake) or
                @enumToInt(rec_ver) >= 0x1000)
            {
                std.log.debug(
                    "Conn.readRecordOrChangeCipherSpec early exit#7, self=0x{x}",
                    .{@ptrToInt(self)},
                );
                return self.in.setError(error.InvalidRecordHeader);
            }
        }

        const max_payload_len: u16 = if (self.version != null and self.version.? == .v1_3)
            max_ciphertext_tls13
        else
            max_ciphertext;
        if (payload_len > max_payload_len) {
            self.sendAlert(.record_overflow) catch {};
            const err = error.OversizedRecord;
            self.in.setError(err) catch {};
            return err;
        }

        const record_len = record_header_len + payload_len;
        self.readFromUntil(allocator, self.stream.reader(), record_len) catch |err| {
            // TODO: only set error to self.in if needed
            return self.in.setError(err);
        };
        std.log.debug(
            "Conn.readRecordOrChangeCipherSpec self=0x{x}, after readFromUntil record_len={}, self.raw_input.items.len={}",
            .{ @ptrToInt(self), record_len, self.raw_input.items.len },
        );
        var data = blk: {
            defer discardBytesOfArrayList(&self.raw_input, record_len);
            const record = self.raw_input.items[0..record_len];
            std.log.debug(
                "Conn.readRecordOrChangeCipherSpec self=0x{x}, record={}",
                .{ @ptrToInt(self), std.fmt.fmtSliceHexLower(record) },
            );
            if (self.in.decrypt(allocator, record, &rec_type)) |decrypted|
                break :blk decrypted
            else |err| {
                self.sendAlert(AlertDescription.fromError(err)) catch |err2|
                    return self.in.setError(err2);
                return err; // needed for compilation, but sendAlert always return an error.
            }
        };
        defer allocator.free(data);
        std.log.info(
            "Conn.readRecordOrChangeCipherSpec self=0x{x}, data={}, rec_type={}",
            .{ @ptrToInt(self), fmtx.fmtSliceHexEscapeLower(data), rec_type },
        );
        if (data.len > max_plain_text) {
            self.sendAlert(.record_overflow) catch |err| return self.in.setError(err);
        }

        // Application Data messages are always protected.
        if (self.in.cipher == null and rec_type == .application_data) {
            self.sendAlert(.unexpected_message) catch |err| return self.in.setError(err);
        }

        if (rec_type != .alert and rec_type != .change_cipher_spec and data.len > 0) {
            // This is a state-advancing message: reset the retry count.
            self.retry_count = 0;
        }

        if (self.version != null and self.version.? == .v1_3 and rec_type == .handshake and
            self.handshake_bytes.len > 0)
        {
            self.sendAlert(.unexpected_message) catch |err| return self.in.setError(err);
        }

        switch (rec_type) {
            .alert => {
                if (data.len != 2) {
                    std.log.warn("Conn.readRecordOrChangeCipherSpec unexpected alert data length={}", .{data.len});
                    self.sendAlert(.unexpected_message) catch |err| return self.in.setError(err);
                }
                const desc = @intToEnum(AlertDescription, data[1]);
                if (desc != .close_notify) {
                    return self.in.setError(error.Eof);
                }
                if (self.version != null and self.version.? == .v1_3) {
                    return self.in.setError(error.RemoteError);
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
                        self.sendAlert(.unexpected_message) catch |err|
                            return self.in.setError(err);
                    },
                }
            },
            .change_cipher_spec => {
                if (data.len != 1 or data[0] != 1) {
                    self.sendAlert(.decode_error) catch |err| return self.in.setError(err);
                }
                // Handshake messages are not allowed to fragment across the CCS.
                if (self.handshake_bytes.len > 0) {
                    self.sendAlert(.unexpected_message) catch |err| return self.in.setError(err);
                }
                // In TLS 1.3, change_cipher_spec records are ignored until the
                // Finished. See RFC 8446, Appendix D.4. Note that according to Section
                // 5, a server can send a ChangeCipherSpec before its ServerHello, when
                // c.vers is still unset. That's not useful though and suspicious if the
                // server then selects a lower protocol version, so don't allow that.
                if (self.version.? == .v1_3) {
                    return self.retryReadRecord(expect_change_cipher_spec);
                }

                if (!expect_change_cipher_spec) {
                    self.sendAlert(.unexpected_message) catch |err| return self.in.setError(err);
                }
                std.log.debug(
                    "Conn.readRecordOrChangeCipherSpec calling changeCipherSpec, self=0x{x}, &self.in=0x{x}",
                    .{ @ptrToInt(self), @ptrToInt(&self.in) },
                );
                self.in.changeCipherSpec() catch {
                    // TODO: convert error to desc
                    self.sendAlert(.internal_error) catch |err| {
                        return self.in.setError(err);
                    };
                };
            },
            .application_data => {
                if (!handshake_complete or expect_change_cipher_spec) {
                    self.sendAlert(.unexpected_message) catch |err| return self.in.setError(err);
                }
                // Some OpenSSL servers send empty records in order to randomize the
                // CBC IV. Ignore a limited number of empty records.
                if (data.len == 0) {
                    return try self.retryReadRecord(expect_change_cipher_spec);
                }
                try self.input.write(data);
            },
            .handshake => {
                if (data.len == 0 or expect_change_cipher_spec) {
                    self.sendAlert(.unexpected_message) catch |err| return self.in.setError(err);
                }
                self.handshake_bytes = data;
                data = "";
            },
            else => self.sendAlert(.unexpected_message) catch |err| return self.in.setError(err),
        }
    }

    fn retryReadRecord(
        self: *Conn,
        expect_change_cipher_spec: bool,
    ) !void {
        self.retry_count += 1;
        if (self.retry_count > max_useless_records) {
            self.sendAlert(.unexpected_message) catch {};
            return self.in.setError(error.TooManyIgnoredRecords);
        }
        try self.readRecordOrChangeCipherSpec(self.allocator, expect_change_cipher_spec);
    }

    // verifyServerCertificate parses and verifies the provided chain, setting
    // c.verifiedChains and c.peerCertificates or sending the appropriate alert.
    pub fn verifyServerCertificate(self: *Conn, certificates: []const []const u8) !void {
        const allocator = self.allocator;
        var certs = try allocator.alloc(x509.Certificate, certificates.len);
        errdefer {
            for (certs) |*cert| cert.deinit(allocator);
            allocator.free(certs);
        }
        for (certificates) |cert_der, i| {
            std.log.info("i={}, cert_der.ptr=0x{x}", .{ i, @ptrToInt(cert_der.ptr) });
            // std.log.info("i={}, cert_der={}", .{ i, fmtx.fmtSliceHexEscapeLower(cert_der) });
            var cert = x509.Certificate.parse(allocator, cert_der) catch {
                std.log.err("bad_certificate i={}", .{i});
                self.sendAlert(.bad_certificate) catch {};
                return error.BadServerCertificate;
            };
            certs[i] = cert;
            std.log.debug("set certs i={}, certs[i]=0x{x}", .{ i, @ptrToInt(&certs[i]) });
        }

        if (!self.config.insecure_skip_verify) {
            var root_pool = try CertPool.init(allocator, true);
            defer root_pool.deinit();

            const max_bytes = 1024 * 1024 * 1024;
            // TODO: read pem file for OS distribution.
            const pem_certs = try std.fs.cwd().readFileAlloc(
                allocator,
                "/etc/ssl/certs/ca-certificates.crt",
                max_bytes,
            );
            defer allocator.free(pem_certs);

            try root_pool.appendCertsFromPem(pem_certs);

            var intermediate_pool = try CertPool.init(allocator, true);
            defer intermediate_pool.deinit();
            for (certs[1..]) |*cert| {
                var cert_copy = x509.Certificate.parse(allocator, cert.raw) catch unreachable;
                try intermediate_pool.addCert(&cert_copy);
            }

            const opts = VerifyOptions{
                .roots = &root_pool,
                .current_time = datetime.datetime.Datetime.now(),
                .dns_name = self.config.server_name,
                .intermediates = &intermediate_pool,
            };
            if (certs[0].verify(allocator, &opts)) |*chains| {
                chains.deinit(allocator);
            } else |_| {
                std.log.debug("verifyServerCertificate verify error, certs[0]=0x{x}", .{@ptrToInt(&certs[0])});
                self.sendAlert(.bad_certificate) catch {};
                return error.BadServerCertificate;
            }
        }

        self.peer_certificates = certs;
    }

    pub fn getClientCertificate(
        self: *const Conn,
        allocator: mem.Allocator,
        available_authorities: []const []const u8,
        signature_schemes: []const SignatureScheme,
        version: ProtocolVersion,
    ) ?*const CertificateChain {
        for (self.config.certificates) |*cert_chain| {
            _ = selectSignatureScheme(
                allocator,
                version,
                cert_chain,
                signature_schemes,
            ) catch continue;

            if (available_authorities.len == 0) {
                return cert_chain;
            }

            for (cert_chain.certificate_chain) |cert, j| {
                std.log.info(
                    "getClientCertificate j={}, cert={}",
                    .{ j, std.fmt.fmtSliceHexLower(cert) },
                );
                var x509_cert = if (j == 0 and cert_chain.leaf != null)
                    cert_chain.leaf.?.*
                else
                    x509.Certificate.parse(allocator, cert) catch |err| {
                        std.log.err("getClientCertificate parse error: {s}", .{@errorName(err)});
                        continue;
                    };
                defer if (j != 0 or cert_chain.leaf == null) {
                    std.log.info("getClientCertificate j={}", .{j});
                    x509_cert.deinit(allocator);
                };
                for (available_authorities) |auth| {
                    if (mem.eql(u8, x509_cert.raw_issuer, auth)) {
                        return cert_chain;
                    }
                }
            }
        }
        return null;
    }

    // processCertsFromClient takes a chain of client certificates either from a
    // Certificates message or from a sessionState and verifies them. It returns
    // the public key of the leaf certificate.
    pub fn processCertsFromClient(
        self: *Conn,
        allocator: mem.Allocator,
        cert_chain: *const CertificateChain,
    ) !void {
        const has_certs = cert_chain.certificate_chain.len > 0;
        if (!has_certs and self.config.client_auth.requiresClientCert()) {
            self.sendAlert(.bad_certificate) catch {};
            return error.NoClientCertificate;
        }

        var certs = blk: {
            var certs2 = try allocator.alloc(x509.Certificate, cert_chain.certificate_chain.len);
            var i: usize = 0;
            errdefer memx.deinitElemsAndFreeSliceInError(x509.Certificate, certs2, allocator, i);
            while (i < cert_chain.certificate_chain.len) : (i += 1) {
                certs2[i] = x509.Certificate.parse(
                    allocator,
                    cert_chain.certificate_chain[i],
                ) catch {
                    self.sendAlert(.bad_certificate) catch {};
                    return error.InvalidClientCertificate;
                };
            }
            break :blk certs2;
        };
        errdefer memx.deinitSliceAndElems(x509.Certificate, certs, allocator);

        if ((@enumToInt(self.config.client_auth) >
            @enumToInt(ClientAuthType.verify_client_cert_if_given)) and
            has_certs)
        {
            var intermediate_pool = try CertPool.init(allocator, false);
            defer intermediate_pool.deinit();
            for (certs[1..]) |*cert| {
                var cert_copy = x509.Certificate.parse(allocator, cert.raw) catch unreachable;
                try intermediate_pool.addCert(&cert_copy);
            }

            const opts = VerifyOptions{
                .roots = &self.config.client_cas.?,
                .current_time = datetime.datetime.Datetime.now(),
                .intermediates = &intermediate_pool,
                .key_usages = &[_]x509.ExtKeyUsage{.client_auth},
            };
            if (certs[0].verify(allocator, &opts)) |*chains| {
                // TODO: implement setting verified_chains
                chains.deinit(allocator);
            } else |_| {
                std.log.debug(
                    "getClientCertificate verify error, certs[0]=0x{x}",
                    .{@ptrToInt(&certs[0])},
                );
                self.sendAlert(.bad_certificate) catch {};
                return error.BadServerCertificate;
            }
        }

        self.peer_certificates = certs;
        self.ocsp_response = try allocator.dupe(u8, cert_chain.ocsp_staple);
        self.scts = try memx.dupeStringList(allocator, cert_chain.signed_certificate_timestamps);

        // TODO: implement
        std.log.info("Conn.processCertsFromClient ok", .{});
    }

    pub fn loadSession(
        self: *Conn,
        allocator: mem.Allocator,
        hello: *ClientHelloMsg,
    ) !LoadSessionResult {
        std.log.info("Conn.loadSession start", .{});
        if (self.config.session_tickets_disabled or self.config.client_session_cache == null) {
            std.log.info("Conn.loadSession early exit#1", .{});
            return LoadSessionResult{};
        }

        hello.ticket_supported = true;

        std.log.info("Conn.loadSession clientHello.supported_versions={any}", .{hello.supported_versions});
        if (hello.supported_versions[0] == .v1_3) {
            // Require DHE on resumption as it guarantees forward secrecy against
            // compromise of the session ticket key. See RFC 8446, Section 4.2.9.
            if (hello.psk_modes.len > 0) {
                allocator.free(hello.psk_modes);
            }
            hello.psk_modes = try allocator.dupe(PskMode, &[_]PskMode{.dhe});
            std.log.info("Conn.loadSession set clientHello.psk_modes to dhe", .{});
        }

        // Session resumption is not allowed if renegotiating because
        // renegotiation is primarily used to allow a client to send a client
        // certificate, which would be skipped if session resumption occurred.
        if (self.handshakes != 0) {
            std.log.info("Conn.loadSession early exit#2", .{});
            return LoadSessionResult{};
        }

        // Try to resume a previously negotiated TLS session, if available.
        const cache_key = try clientSessionCacheKey(allocator, self.remote_address, self.config);
        std.log.info("Conn.loadSession cache_key={s}", .{cache_key});
        var ret = LoadSessionResult{ .cache_key = cache_key };
        errdefer ret.deinit(allocator);

        var session = self.config.client_session_cache.?.getPtr(cache_key);
        if (session == null) {
            std.log.info("Conn.loadSession early exit#3", .{});
            return ret;
        }
        ret.session = session;

        // Check that version used for the previous session is still valid.
        if (!memx.containsScalar(ProtocolVersion, hello.supported_versions, session.?.ver)) {
            std.log.info("Conn.loadSession early exit#4", .{});
            return ret;
        }

        // Check that the cached server certificate is not expired, and that it's
        // valid for the ServerName. This should be ensured by the cache key, but
        // protect the application from a faulty ClientSessionCache implementation.
        if (!self.config.insecure_skip_verify) {
            if (session.?.verified_chains.len == 0) {
                // The original connection had InsecureSkipVerify, while this doesn't.
                std.log.info("Conn.loadSession early exit#5", .{});
                return ret;
            }

            const server_cert = session.?.server_certificates[0];
            const now = datetime.datetime.Datetime.now();
            if (now.gt(server_cert.not_after)) {
                // Expired certificate, delete the entry.
                self.config.client_session_cache.?.remove(cache_key);
                std.log.info("Conn.loadSession early exit#6", .{});
                return ret;
            }
            server_cert.verifyHostname(self.config.server_name) catch {
                std.log.info("Conn.loadSession early exit#7", .{});
                return ret;
            };
        }

        if (session.?.ver != .v1_3) {
            // In TLS 1.2 the cipher suite must match the resumed session. Ensure we
            // are still offering it.
            if (mutualCipherSuiteTls12(hello.cipher_suites, session.?.cipher_suite) == null) {
                std.log.info("Conn.loadSession early exit#8", .{});
                return ret;
            }

            allocator.free(hello.session_ticket);
            hello.session_ticket = try allocator.dupe(u8, session.?.session_ticket);
            std.log.info("Conn.loadSession TLS 1.2, updated hello.session_ticket", .{});
            return ret;
        }

        // Check that the session ticket is not expired.
        const now = datetime.datetime.Datetime.now();
        if (session.?.use_by != null and now.gt(session.?.use_by.?)) {
            self.config.client_session_cache.?.remove(cache_key);
            std.log.info("Conn.loadSession early exit#10", .{});
            return ret;
        }

        // In TLS 1.3 the KDF hash must match the resumed session. Ensure we
        // offer at least one cipher suite with that hash.
        const cipher_suite = cipherSuiteTls13ById(session.?.cipher_suite);
        if (cipher_suite == null) {
            std.log.info("Conn.loadSession early exit#11", .{});
            return ret;
        }
        var cipher_suite_ok = false;
        for (hello.cipher_suites) |offered_id| {
            const offered_suite = cipherSuiteTls13ById(offered_id);
            if (offered_suite != null and offered_suite.?.hash_type == cipher_suite.?.hash_type) {
                cipher_suite_ok = true;
                break;
            }
        }
        if (!cipher_suite_ok) {
            std.log.info("Conn.loadSession early exit#12", .{});
            return ret;
        }

        // Set the pre_shared_key extension. See RFC 8446, Section 4.2.11.1.
        const ticket_age = @intCast(
            u32,
            @divTrunc(now.toTimestamp() - session.?.received_at.toTimestamp(), std.time.ms_per_s),
        );
        memx.deinitSliceAndElems(PskIdentity, hello.psk_identities, allocator);
        hello.psk_identities = blk: {
            const label = try allocator.dupe(u8, session.?.session_ticket);
            errdefer allocator.free(label);
            break :blk try allocator.dupe(PskIdentity, &[_]PskIdentity{
                .{
                    .label = label,
                    .obfuscated_ticket_age = ticket_age + session.?.age_add,
                },
            });
        };
        memx.freeElemsAndFreeSlice([]const u8, hello.psk_binders, allocator);
        hello.psk_binders = blk_binders: {
            const binder = try allocator.alloc(u8, cipher_suite.?.hash_type.digestLength());
            errdefer allocator.free(binder);
            break :blk_binders try allocator.dupe([]const u8, &[_][]const u8{binder});
        };

        const psk = try cipher_suite.?.expandLabel(
            allocator,
            session.?.master_secret,
            resumption_label,
            session.?.nonce,
            @intCast(u16, cipher_suite.?.hash_type.digestLength()),
        );
        defer allocator.free(psk);
        std.log.info("Conn.loadSession psk={}", .{std.fmt.fmtSliceHexLower(psk)});

        const early_secret = try cipher_suite.?.extract(allocator, psk, null);
        ret.early_secret = early_secret;
        std.log.info("Conn.loadSession early_secret={}", .{std.fmt.fmtSliceHexLower(early_secret)});

        const binder_key = try cipher_suite.?.deriveSecret(
            allocator,
            early_secret,
            resumption_binder_label,
            null,
        );
        ret.binder_key = binder_key;
        std.log.info("Conn.loadSession binder_key={}", .{std.fmt.fmtSliceHexLower(binder_key)});

        var transcript = crypto.Hash.init(cipher_suite.?.hash_type);
        const hello_bytes_without_binders = try hello.marshalWithoutBinders(allocator);
        std.log.info("Conn.loadSession hello_bytes_without_binders={}", .{std.fmt.fmtSliceHexLower(hello_bytes_without_binders)});
        transcript.update(hello_bytes_without_binders);

        // Compute the PSK binders. See RFC 8446, Section 4.2.11.2.
        var psk_binders = blk: {
            var binder = try cipher_suite.?.finishedHash(allocator, binder_key, transcript);
            errdefer allocator.free(binder);
            std.log.info("Conn.loadSession binder={}", .{std.fmt.fmtSliceHexLower(binder)});
            break :blk try allocator.dupe([]const u8, &[_][]const u8{binder});
        };
        errdefer memx.freeElemsAndFreeSlice(psk_binders);

        try hello.updateBinders(allocator, psk_binders);

        std.log.info("Conn.loadSession exit with session found", .{});
        return ret;
    }
};

const min_read = 512;

fn readAllToArrayList(
    allocator: mem.Allocator,
    src_reader: anytype,
    dest: *std.ArrayListUnmanaged(u8),
) !void {
    while (true) {
        try dest.ensureUnusedCapacity(allocator, min_read);
        const old_len = dest.items.len;
        var buf: []u8 = undefined;
        buf.ptr = dest.items.ptr;
        buf.len = dest.capacity;
        const bytes_read = try src_reader.read(buf[old_len..]);
        dest.items.len += bytes_read;
        if (bytes_read == 0) {
            return;
        }
    }
}

fn discardBytesOfArrayList(list: *std.ArrayListUnmanaged(u8), n: usize) void {
    const rest_len = list.items.len - n;
    std.mem.copy(u8, list.items, list.items[n..]);
    list.items.len = rest_len;
}

fn clientSessionCacheKey(
    allocator: mem.Allocator,
    server_address: net.Address,
    config: *const Conn.Config,
) ![]const u8 {
    if (config.server_name.len > 0) {
        return try allocator.dupe(u8, config.server_name);
    }
    return try std.fmt.allocPrint(allocator, "{s}", .{server_address});
}

test "clientSessionCacheKey" {
    const allocator = testing.allocator;
    const addr = try net.Address.parseIp("127.0.0.1", 8443);

    const key1 = try clientSessionCacheKey(allocator, addr, &Conn.Config{});
    defer allocator.free(key1);
    try testing.expectEqualStrings("127.0.0.1:8443", key1);

    const key2 = try clientSessionCacheKey(allocator, addr, &Conn.Config{ .server_name = "www.example.com" });
    defer allocator.free(key2);
    try testing.expectEqualStrings("www.example.com", key2);
}

const HalfConn = struct {
    ver: ?ProtocolVersion = null,
    cipher: ?Aead = null,

    seq: [8]u8 = [_]u8{0} ** 8, // 64-bit sequence number
    scratch_buf: [13]u8 = [_]u8{0} ** 13, // to avoid allocs; interface method args escape

    next_cipher: ?Aead = null,
    err: ?anyerror = null,

    traffic_secret: []const u8 = "", // current TLS 1.3 traffic secret

    pub fn deinit(self: *HalfConn, allocator: mem.Allocator) void {
        if (self.traffic_secret.len > 0) allocator.free(self.traffic_secret);
    }

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
                try record.appendSlice(allocator, payload);

                // Encrypt the actual ContentType and replace the plaintext one.
                try record.append(allocator, record.items[0]);
                record.items[0] = @enumToInt(RecordType.application_data);

                mem.writeIntBig(u16, record.items[3..5], @intCast(u16, payload.len + 1 + cipher.overhead()));

                const plaintext = try allocator.dupe(u8, record.items[record_header_len..]);
                defer allocator.free(plaintext);
                try record.resize(allocator, record_header_len);

                const additional_data = try allocator.dupe(u8, record.items);
                defer allocator.free(additional_data);

                try cipher.encrypt(allocator, record, nonce, plaintext, additional_data);
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
        out_rec_type: *RecordType,
    ) ![]const u8 {
        var plaintext: []const u8 = undefined;
        out_rec_type.* = @intToEnum(RecordType, record[0]);
        std.log.debug(
            "HalfConn.decrypt, self=0x{x}, rec_type={}, record.len={}, self.cipher.id={}",
            .{ @ptrToInt(self), out_rec_type.*, record.len, self.cipher },
        );
        var payload = record[record_header_len..];

        // In TLS 1.3, change_cipher_spec messages are to be ignored without being
        // decrypted. See RFC 8446, Appendix D.4.
        if (self.ver != null and self.ver.? == .v1_3 and out_rec_type.* == .change_cipher_spec) {
            return try allocator.dupe(u8, payload);
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
            const additional_data = if (self.ver.? == .v1_3)
                record[0..record_header_len]
            else blk: {
                mem.copy(u8, &self.scratch_buf, &self.seq);
                mem.copy(u8, self.scratch_buf[self.seq.len..], record[0..3]);
                const n = ciphertext_and_tag.len - cipher.overhead();
                mem.writeIntBig(
                    u16,
                    self.scratch_buf[self.seq.len + 3 .. self.seq.len + 5],
                    @intCast(u16, n),
                );
                break :blk self.scratch_buf[0 .. self.seq.len + 5];
            };

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
            std.log.debug(
                "HalfConn.decrypt, self=0x{x}, nonce.len={}, ciphertext_and_tag.len={}, additional_data.len={}",
                .{ @ptrToInt(self), nonce.len, ciphertext_and_tag.len, additional_data.len },
            );
            cipher.decrypt(allocator, &dest, nonce, ciphertext_and_tag, additional_data) catch |err| {
                std.log.err(
                    "HalfConn.decrypt, self=0x{x}, decrpyt err: {s}",
                    .{ @ptrToInt(self), @errorName(err) },
                );
                return error.BadRecordMac;
            };

            if (self.ver.? == .v1_3) {
                if (out_rec_type.* != .application_data) {
                    return error.UnexpectedMessage;
                }
                if (dest.items.len > max_plain_text + 1) {
                    return error.RecordOverflow;
                }

                // Remove padding and find the ContentType scanning from the end.
                var i: usize = dest.items.len - 1;
                while (i >= 0) : (i -= 1) {
                    if (dest.items[i] != 0) {
                        out_rec_type.* = @intToEnum(RecordType, dest.items[i]);
                        try dest.resize(allocator, i);
                        break;
                    }
                    if (i == 0) {
                        return error.UnexpectedMessage;
                    }
                }
            }

            plaintext = dest.toOwnedSlice(allocator);
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

    // ownership of secret will be moved to HalfConn even when this method returns an error.
    pub fn moveSetTrafficSecret(
        self: *HalfConn,
        allocator: mem.Allocator,
        suite: *const CipherSuiteTls13,
        secret: []const u8,
    ) !void {
        allocator.free(self.traffic_secret);
        self.traffic_secret = secret;

        var key: []const u8 = undefined;
        var iv: []const u8 = undefined;
        try suite.trafficKey(allocator, secret, &key, &iv);
        defer allocator.free(key);
        defer allocator.free(iv);
        self.cipher = suite.aead(key, iv);
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

    // Note: setError always returns the err.
    fn setError(self: *HalfConn, err: anyerror) !void {
        // TODO: set PermanentError if net error
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

// AtLeastReader reads from inner_reader, stopping with EOF once at least n bytes have been
// read. It is different from an io.LimitedReader in that it doesn't cut short
// the last Read call, and in that it considers an early EOF an error.
pub fn AtLeastReader(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,
        n: usize,

        pub const Error = error{UnexpectedEof} || ReaderType.Error;
        pub const Reader = io.Reader(*Self, Error, read);

        const Self = @This();

        /// Returns the number of bytes read. It may be less than dest.len.
        /// If the number of bytes read is 0, it means end of stream.
        /// End of stream is not an error condition.
        /// If the number of bytes read from inner_reader is 0 and self.n
        /// is greater than 0, it returns error.UnexpectedEof.
        pub fn read(self: *Self, dest: []u8) Error!usize {
            if (self.n == 0) {
                return 0;
            }
            const bytes_read = try self.inner_reader.read(dest);
            self.n -= std.math.min(self.n, bytes_read);
            if (bytes_read == 0 and self.n > 0) {
                return error.UnexpectedEof;
            }
            return bytes_read;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

/// Returns an initialised `AtLeastReader`
pub fn atLeastReader(inner_reader: anytype, n: usize) AtLeastReader(@TypeOf(inner_reader)) {
    return .{ .inner_reader = inner_reader, .n = n };
}

// hostnameInSni converts name into an appropriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See RFC 6066, Section 3.
pub fn hostnameInSni(name: []const u8) []const u8 {
    var host = name;
    if (host.len > 0 and host[0] == '[' and host[host.len - 1] == ']') {
        host = host[1 .. host.len - 1];
    }
    if (mem.lastIndexOfScalar(u8, host, '%')) |i| {
        host = host[0..i];
    }

    if (std.net.Address.parseIp(host, 0)) |_| {
        return "";
    } else |_| {
        return mem.trimRight(u8, name, ".");
    }
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

    var rec_type: RecordType = .application_data;
    const rec_ver: ProtocolVersion = .v1_2;
    var writer = out_buf.writer(allocator);
    try writer.writeByte(@enumToInt(rec_type));
    try writer.writeIntBig(u16, @enumToInt(rec_ver));
    try writer.writeIntBig(u16, @intCast(u16, plaintext.len));

    try hc.encrypt(allocator, &out_buf, plaintext);

    mem.set(u8, &hc.seq, 0);
    const decrypted = try hc.decrypt(allocator, out_buf.items, &rec_type);
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
    {
        const input = "hello";
        var fbs = io.fixedBufferStream(input);
        var reader = atLeastReader(fbs.reader(), 3);
        var buf = [_]u8{0} ** 4;
        try testing.expectEqual(buf.len, try reader.read(&buf));
        try testing.expectEqual(@as(usize, 0), try reader.read(&buf));
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
    // testing.log_level = .err;
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

test "free empty" {
    const allocator = testing.allocator;
    allocator.free("");
}
