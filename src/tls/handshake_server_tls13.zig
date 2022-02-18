const std = @import("std");
const mem = std.mem;
const Conn = @import("conn.zig").Conn;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const random_length = @import("handshake_msg.zig").random_length;
const CipherSuiteTls13 = @import("cipher_suites.zig").CipherSuiteTls13;
const mutualCipherSuiteTls13 = @import("cipher_suites.zig").mutualCipherSuiteTls13;
const has_aes_gcm_hardware_support = @import("cipher_suites.zig").has_aes_gcm_hardware_support;
const aesgcmPreferred = @import("cipher_suites.zig").aesgcmPreferred;
const default_cipher_suites_tls13 = @import("cipher_suites.zig").default_cipher_suites_tls13;
const default_cipher_suites_tls13_no_aes = @import("cipher_suites.zig").default_cipher_suites_tls13_no_aes;
const memx = @import("../memx.zig");

pub const ServerHandshakeStateTls13 = struct {
    conn: *Conn,
    client_hello: ClientHelloMsg,
    hello: ?ServerHelloMsg = null,
    master_secret: ?[]const u8 = null,
    cert_chain: ?*CertificateChain = null,

    pub fn init(conn: *Conn, client_hello: ClientHelloMsg) ServerHandshakeStateTls13 {
        return .{ .conn = conn, .client_hello = client_hello };
    }

    pub fn deinit(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) void {
        self.client_hello.deinit(allocator);
        if (self.hello) |*hello| hello.deinit(allocator);
        if (self.master_secret) |s| allocator.free(s);
    }

    pub fn handshake(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        // For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
        try self.processClientHello(allocator);
    }

    pub fn processClientHello(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        if (self.client_hello.supported_versions.len == 0) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.InvalidVersionToNegotiateTls13;
        }

        // Abort if the client is doing a fallback and landing lower than what we
        // support. See RFC 7507, which however does not specify the interaction
        // with supported_versions. The only difference is that with
        // supported_versions a client has a chance to attempt a [TLS 1.2, TLS 1.4]
        // handshake in case TLS 1.3 is broken but 1.2 is not. Alas, in that case,
        // it will have to drop the TLS_FALLBACK_SCSV protection if it falls back to
        // TLS 1.2, because a TLS 1.3 server would abort here. The situation before
        // supported_versions was not better because there was just no way to do a
        // TLS 1.4 handshake without risking the server selecting TLS 1.3.
        if (memx.containsScalar(
            CipherSuiteId,
            self.client_hello.cipher_suites,
            .tls_fallback_scsv,
        )) {
            // Use c.vers instead of max(supported_versions) because an attacker
            // could defeat this by adding an arbitrary high version otherwise.
            if (@enumToInt(self.conn.version.?) <
                @enumToInt(self.conn.config.maxSupportedVersion()))
            {
                self.conn.sendAlert(.inappropriate_fallback) catch {};
                return error.InappropriateProtocolFallback;
            }
        }

        if (self.client_hello.compression_methods.len != 1 or
            self.client_hello.compression_methods[0] != .none)
        {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.IllegalCompressionMethods;
        }

        var random = try allocator.alloc(u8, random_length);
        errdefer allocator.free(random);
        self.conn.config.random.bytes(random);

        if (self.client_hello.secure_renegotiation.len != 0) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.RenegotiationForInitialHandshake;
        }

        if (self.client_hello.early_data) {
            // See RFC 8446, Section 4.2.10 for the complicated behavior required
            // here. The scenario is that a different server at our address offered
            // to accept early data in the past, which we can't handle. For now, all
            // 0-RTT enabled session tickets need to expire before a Go server can
            // replace a server or join a pool. That's the same requirement that
            // applies to mixing or replacing with any TLS 1.2 server.
            self.conn.sendAlert(.unsupported_extension) catch {};
            return error.UnexpectedEarlyData;
        }

        var session_id = try allocator.dupe(u8, self.client_hello.session_id);
        errdefer allocator.free(session_id);

        const preference_list = if (has_aes_gcm_hardware_support and
            aesgcmPreferred(self.client_hello.cipher_suites))
            default_cipher_suites_tls13
        else
            default_cipher_suites_tls13_no_aes;

        var suite: ?*const CipherSuiteTls13 = null;
        for (preference_list) |suite_id| {
            suite = mutualCipherSuiteTls13(self.client_hello.cipher_suites, suite_id);
            if (suite != null) break;
        }
        if (suite == null) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.NoCipherSuiteSupported;
        }
        self.conn.cipher_suite_id = suite.?.id;

        // pub const ServerHelloMsg = struct {
        //     raw: ?[]const u8 = null,
        //     vers: ProtocolVersion = undefined,
        //     random: []const u8 = undefined,
        //     session_id: []const u8 = undefined,
        //     cipher_suite: ?CipherSuiteId = null,
        //     compression_method: CompressionMethod,
        //     ocsp_stapling: bool = undefined,
        //     ticket_supported: bool = false,
        //     secure_renegotiation_supported: bool = false,
        //     secure_renegotiation: []const u8 = "",
        //     alpn_protocol: ?[]const u8 = null,
        //     scts: ?[]const []const u8 = null,
        //     supported_version: ?ProtocolVersion = null,
        //     server_share: ?KeyShare = null,
        //     selected_identity: ?u16 = null,
        //     supported_points: ?[]const EcPointFormat = null,
        //     // HelloRetryRequest extensions
        //     cookie: ?[]const u8 = null,
        //     selected_group: ?CurveId = null,

        self.hello = ServerHelloMsg{
            // TLS 1.3 froze the ServerHello.legacy_version field, and uses
            // supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
            .vers = .v1_2,
            .random = random,
            .session_id = session_id,
            .cipher_suite = suite.?.id,
            .compression_method = .none,
            .supported_version = self.conn.version.?,
        };
        @panic("not implemented yet");
    }
};
