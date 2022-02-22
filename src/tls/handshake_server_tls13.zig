const std = @import("std");
const mem = std.mem;
const Conn = @import("conn.zig").Conn;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const EncryptedExtensionsMsg = @import("handshake_msg.zig").EncryptedExtensionsMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CurveId = @import("handshake_msg.zig").CurveId;
const KeyShare = @import("handshake_msg.zig").KeyShare;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const random_length = @import("handshake_msg.zig").random_length;
const CipherSuiteTls13 = @import("cipher_suites.zig").CipherSuiteTls13;
const mutualCipherSuiteTls13 = @import("cipher_suites.zig").mutualCipherSuiteTls13;
const has_aes_gcm_hardware_support = @import("cipher_suites.zig").has_aes_gcm_hardware_support;
const aesgcmPreferred = @import("cipher_suites.zig").aesgcmPreferred;
const default_cipher_suites_tls13 = @import("cipher_suites.zig").default_cipher_suites_tls13;
const default_cipher_suites_tls13_no_aes = @import("cipher_suites.zig").default_cipher_suites_tls13_no_aes;
const EcdheParameters = @import("key_schedule.zig").EcdheParameters;
const derived_label = @import("key_schedule.zig").derived_label;
const client_handshake_traffic_label = @import("key_schedule.zig").client_handshake_traffic_label;
const server_handshake_traffic_label = @import("key_schedule.zig").server_handshake_traffic_label;
const negotiateAlpn = @import("handshake_server.zig").negotiateAlpn;
const crypto = @import("crypto.zig");
const selectSignatureScheme = @import("auth.zig").selectSignatureScheme;
const ClientAuthType = @import("client_auth.zig").ClientAuthType;
const memx = @import("../memx.zig");

pub const ServerHandshakeStateTls13 = struct {
    conn: *Conn,
    client_hello: ClientHelloMsg,
    hello: ?ServerHelloMsg = null,
    sent_dummy_ccs: bool = false,
    using_psk: bool = false,
    suite: ?*const CipherSuiteTls13 = null,
    cert_chain: ?*CertificateChain = null,
    sig_alg: ?SignatureScheme = null,
    early_secret: ?[]const u8 = null,
    shared_key: []const u8 = "",
    handshake_secret: []const u8 = "",
    master_secret: []const u8 = "",
    traffic_secret: []const u8 = "",
    transcript: crypto.Hash = undefined,

    pub fn init(conn: *Conn, client_hello: ClientHelloMsg) ServerHandshakeStateTls13 {
        return .{ .conn = conn, .client_hello = client_hello };
    }

    pub fn deinit(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) void {
        self.client_hello.deinit(allocator);
        if (self.hello) |*hello| hello.deinit(allocator);
        if (self.early_secret) |s| allocator.free(s);
        if (self.shared_key.len > 0) allocator.free(self.shared_key);
        if (self.handshake_secret.len > 0) allocator.free(self.handshake_secret);
        if (self.master_secret.len > 0) allocator.free(self.master_secret);
        if (self.traffic_secret.len > 0) allocator.free(self.traffic_secret);
    }

    pub fn handshake(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        // For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
        try self.processClientHello(allocator);
        try self.checkForResumption(allocator);
        try self.pickCertificate(allocator);

        self.conn.buffering = true;
        try self.sendServerParameters(allocator);
        try self.sendServerCertificate(allocator);
        try self.sendServerFinished(allocator);
        // Note that at this point we could start sending application data without
        // waiting for the client's second flight, but the application might not
        // expect the lack of replay protection of the ClientHello parameters.
        try self.conn.flush();
        std.log.debug("ServerHandshakeStateTls13 after sendFinished, flush", .{});
        try self.readClientCertificate(allocator);
        try self.readClientFinished(allocator);

        self.conn.handshake_complete = true;
    }

    fn processClientHello(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
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

        for (preference_list) |suite_id| {
            self.suite = mutualCipherSuiteTls13(self.client_hello.cipher_suites, suite_id);
            if (self.suite != null) break;
        }
        if (self.suite == null) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.NoCipherSuiteSupported;
        }
        self.conn.cipher_suite_id = self.suite.?.id;
        self.transcript = crypto.Hash.init(self.suite.?.hash_type);

        // Pick the ECDHE group in server preference order, but give priority to
        // groups with a key share, to avoid a HelloRetryRequest round-trip.
        var selected_group: ?CurveId = null;
        var client_key_share: ?*const KeyShare = null;
        group_selection: for (self.conn.config.curve_preferences) |preferred_group| {
            for (self.client_hello.key_shares) |*ks| {
                if (ks.group == preferred_group) {
                    selected_group = ks.group;
                    client_key_share = ks;
                    break :group_selection;
                }
            }
            if (selected_group != null) {
                continue;
            }
            if (memx.containsScalar(CurveId, self.client_hello.supported_curves, preferred_group)) {
                selected_group = preferred_group;
            }
        }
        if (selected_group == null) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.NoCurveSupported;
        }
        if (client_key_share == null) {
            @panic("not implemented yet");
        }

        if (!selected_group.?.isSupported()) {
            self.conn.sendAlert(.internal_error) catch {};
            return error.UnsupportedCurveInPreferences;
        }

        var params = EcdheParameters.generate(
            allocator,
            selected_group.?,
            self.conn.config.random,
        ) catch |err| {
            self.conn.sendAlert(.internal_error) catch {};
            return err;
        };
        defer params.deinit(allocator);

        var server_share = KeyShare{
            .group = selected_group.?,
            .data = try allocator.dupe(u8, params.publicKey()),
        };
        errdefer server_share.deinit(allocator);

        self.hello = ServerHelloMsg{
            // TLS 1.3 froze the ServerHello.legacy_version field, and uses
            // supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
            .vers = .v1_2,
            .random = random,
            .session_id = session_id,
            .cipher_suite = self.suite.?.id,
            .compression_method = .none,
            .supported_version = self.conn.version.?,
            .server_share = server_share,
        };

        self.shared_key = try params.sharedKey(allocator, client_key_share.?.data);

        if (self.client_hello.server_name.len > 0) {
            self.conn.server_name = try allocator.dupe(u8, self.client_hello.server_name);
        }
    }

    fn checkForResumption(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        if (self.conn.config.session_tickets_disabled) {
            return;
        }
        _ = allocator;
        // TODO: implement
    }

    fn pickCertificate(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        // TODO: implement

        // signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
        if (self.client_hello.supported_signature_algorithms.len == 0) {
            return self.conn.sendAlert(.missing_extension);
        }

        // TODO: check client_hello
        var cert_chain = self.conn.config.getCertificate();
        errdefer cert_chain.deinit(allocator);

        self.sig_alg = selectSignatureScheme(
            allocator,
            self.conn.version.?,
            cert_chain,
            self.client_hello.supported_signature_algorithms,
        ) catch |err| {
            // getCertificate returned a certificate that is unsupported or
            // incompatible with the client's signature algorithms.
            self.conn.sendAlert(.handshake_failure) catch {};
            return err;
        };

        self.cert_chain = cert_chain;
    }

    fn sendServerParameters(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        self.transcript.update(try self.client_hello.marshal(allocator));
        const server_hello_bytes = try self.hello.?.marshal(allocator);
        self.transcript.update(server_hello_bytes);
        try self.conn.writeRecord(allocator, .handshake, server_hello_bytes);

        try self.sendDummyChangeCipherSpec(allocator);

        const early_secret = self.early_secret orelse try self.suite.?.extract(allocator, null, null);
        defer if (self.early_secret == null) allocator.free(early_secret);

        self.handshake_secret = blk: {
            const current_secret = try self.suite.?.deriveSecret(
                allocator,
                early_secret,
                derived_label,
                null,
            );
            defer allocator.free(current_secret);
            break :blk try self.suite.?.extract(allocator, self.shared_key, current_secret);
        };

        const client_secret = try self.suite.?.deriveSecret(
            allocator,
            self.handshake_secret,
            client_handshake_traffic_label,
            self.transcript,
        );
        defer allocator.free(client_secret);
        try self.conn.in.setTrafficSecret(allocator, self.suite.?, client_secret);

        const server_secret = try self.suite.?.deriveSecret(
            allocator,
            self.handshake_secret,
            server_handshake_traffic_label,
            self.transcript,
        );
        defer allocator.free(server_secret);
        try self.conn.out.setTrafficSecret(allocator, self.suite.?, server_secret);

        // TODO: implement write key log

        if (negotiateAlpn(
            self.conn.config.next_protos,
            self.client_hello.alpn_protocols,
        )) |selected_proto| {
            self.conn.client_protocol = try allocator.dupe(u8, selected_proto);

            var encrypted_extensions_msg = EncryptedExtensionsMsg{
                .alpn_protocol = selected_proto,
            };

            const encrypted_extensions_msg_bytes = try encrypted_extensions_msg.marshal(allocator);
            defer allocator.free(encrypted_extensions_msg_bytes);

            self.transcript.update(encrypted_extensions_msg_bytes);
            try self.conn.writeRecord(allocator, .handshake, encrypted_extensions_msg_bytes);
        } else |err| {
            self.conn.sendAlert(.no_application_protocol) catch {};
            return err;
        }
    }

    // sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
    // with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
    fn sendDummyChangeCipherSpec(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        if (self.sent_dummy_ccs) {
            return;
        }

        try self.conn.writeRecord(allocator, .change_cipher_spec, &[_]u8{1});
        self.sent_dummy_ccs = true;
    }

    fn requestClientCert(self: *const ServerHandshakeStateTls13) bool {
        return (@enumToInt(self.conn.config.client_auth) >=
            @enumToInt(ClientAuthType.request_client_cert)) and
            !self.using_psk;
    }

    fn sendServerCertificate(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        _ = allocator;

        // Only one of PSK and certificates are used at a time.
        if (self.using_psk) {
            return;
        }

        if (self.requestClientCert()) {
        // TODO: implement
        }
    }

    fn sendServerFinished(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        _ = self;
        _ = allocator;
        // TODO: implement
    }

    fn readClientCertificate(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        _ = self;
        _ = allocator;
        // TODO: implement
    }

    fn readClientFinished(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        _ = self;
        _ = allocator;
        // TODO: implement
    }
};
