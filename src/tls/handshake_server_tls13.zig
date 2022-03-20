const std = @import("std");
const mem = std.mem;
const datetime = @import("datetime");
const AlertDescription = @import("alert.zig").AlertDescription;
const Conn = @import("conn.zig").Conn;
const KeyLog = @import("conn.zig").KeyLog;
const MsgType = @import("handshake_msg.zig").MsgType;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const EcPointFormat = @import("handshake_msg.zig").EcPointFormat;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const EncryptedExtensionsMsg = @import("handshake_msg.zig").EncryptedExtensionsMsg;
const CertificateMsgTls13 = @import("handshake_msg.zig").CertificateMsgTls13;
const CertificateRequestMsgTls13 = @import("handshake_msg.zig").CertificateRequestMsgTls13;
const CertificateVerifyMsg = @import("handshake_msg.zig").CertificateVerifyMsg;
const FinishedMsg = @import("handshake_msg.zig").FinishedMsg;
const NewSessionTicketMsgTls13 = @import("handshake_msg.zig").NewSessionTicketMsgTls13;
const PskMode = @import("handshake_msg.zig").PskMode;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CurveId = @import("handshake_msg.zig").CurveId;
const KeyShare = @import("handshake_msg.zig").KeyShare;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const random_length = @import("handshake_msg.zig").random_length;
const CipherSuiteTls13 = @import("cipher_suites.zig").CipherSuiteTls13;
const cipherSuiteTls13ById = @import("cipher_suites.zig").cipherSuiteTls13ById;
const mutualCipherSuiteTls13 = @import("cipher_suites.zig").mutualCipherSuiteTls13;
const has_aes_gcm_hardware_support = @import("cipher_suites.zig").has_aes_gcm_hardware_support;
const aesgcmPreferred = @import("cipher_suites.zig").aesgcmPreferred;
const default_cipher_suites_tls13 = @import("cipher_suites.zig").default_cipher_suites_tls13;
const default_cipher_suites_tls13_no_aes = @import("cipher_suites.zig").default_cipher_suites_tls13_no_aes;
const EcdheParameters = @import("key_schedule.zig").EcdheParameters;
const derived_label = @import("key_schedule.zig").derived_label;
const client_handshake_traffic_label = @import("key_schedule.zig").client_handshake_traffic_label;
const server_handshake_traffic_label = @import("key_schedule.zig").server_handshake_traffic_label;
const client_application_traffic_label = @import("key_schedule.zig").client_application_traffic_label;
const server_application_traffic_label = @import("key_schedule.zig").server_application_traffic_label;
const resumption_label = @import("key_schedule.zig").resumption_label;
const resumption_binder_label = @import("key_schedule.zig").resumption_binder_label;
const resumption_master_label = @import("key_schedule.zig").resumption_master_label;
const negotiateAlpn = @import("handshake_server.zig").negotiateAlpn;
const crypto = @import("crypto.zig");
const selectSignatureScheme = @import("auth.zig").selectSignatureScheme;
const SignatureType = @import("auth.zig").SignatureType;
const HashType = @import("auth.zig").HashType;
const signedMessage = @import("auth.zig").signedMessage;
const server_signature_context = @import("auth.zig").server_signature_context;
const client_signature_context = @import("auth.zig").client_signature_context;
const isSupportedSignatureAlgorithm = @import("auth.zig").isSupportedSignatureAlgorithm;
const ClientAuthType = @import("client_auth.zig").ClientAuthType;
const verifyHandshakeSignature = @import("auth.zig").verifyHandshakeSignature;
const supported_signature_algorithms = @import("common.zig").supported_signature_algorithms;
const decryptTicket = @import("ticket.zig").decryptTicket;
const encryptTicket = @import("ticket.zig").encryptTicket;
const hello_retry_request_random = @import("common.zig").hello_retry_request_random;
const max_session_ticket_lifetime_seconds = @import("common.zig").max_session_ticket_lifetime_seconds;
const SessionStateTls13 = @import("ticket.zig").SessionStateTls13;
const hmac = @import("hmac.zig");
const memx = @import("../memx.zig");

// max_client_psk_identities is the number of client PSK identities the server will
// attempt to validate. It will ignore the rest not to let cheap ClientHello
// messages cause too much work in session ticket decryption attempts.
const max_client_psk_identities = 5;

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
    client_finished: []const u8 = "",

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
        if (self.client_finished.len > 0) allocator.free(self.client_finished);
    }

    pub fn handshake(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        std.log.info("ServerHandshakeStateTls13 handshake start", .{});
        // For an overview of the TLS 1.3 handshake, see RFC 8446, Section 2.
        try self.processClientHello(allocator);
        std.log.info("ServerHandshakeStateTls13 after processClientHello", .{});
        try self.checkForResumption(allocator);
        std.log.info("ServerHandshakeStateTls13 after checkForResumption", .{});
        try self.pickCertificate(allocator);
        std.log.info("ServerHandshakeStateTls13 after pickCertificate", .{});

        self.conn.buffering = true;
        try self.sendServerParameters(allocator);
        std.log.info("ServerHandshakeStateTls13 after sendServerParameters", .{});
        try self.sendServerCertificate(allocator);
        std.log.info("ServerHandshakeStateTls13 after sendServerCertificate", .{});
        try self.sendServerFinished(allocator);
        std.log.info("ServerHandshakeStateTls13 after sendServerFinished", .{});
        // Note that at this point we could start sending application data without
        // waiting for the client's second flight, but the application might not
        // expect the lack of replay protection of the ClientHello parameters.
        try self.conn.flush();
        std.log.info("ServerHandshakeStateTls13 after flush", .{});
        try self.readClientCertificate(allocator);
        std.log.info("ServerHandshakeStateTls13 after readClientCertificate", .{});
        try self.readClientFinished(allocator);
        std.log.info("ServerHandshakeStateTls13 after readClientFinished", .{});

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
            try self.doHelloRetryRequest(allocator, selected_group.?);
            client_key_share = &self.client_hello.key_shares[0];
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
        std.log.debug(
            "ServerHandshakeStateTls13.processClientHello shared_key={}",
            .{std.fmt.fmtSliceHexLower(self.shared_key)},
        );

        if (self.client_hello.server_name.len > 0) {
            self.conn.server_name = try allocator.dupe(u8, self.client_hello.server_name);
        }
    }

    fn doHelloRetryRequest(
        self: *ServerHandshakeStateTls13,
        allocator: mem.Allocator,
        selected_group: CurveId,
    ) !void {
        // The first ClientHello gets double-hashed into the transcript upon a
        // HelloRetryRequest. See RFC 8446, Section 4.4.1.
        self.transcript.update(try self.client_hello.marshal(allocator));
        var ch_hash_array = try crypto.Hash.DigestArray.init(self.transcript.digestLength());
        self.transcript.finalToSlice(ch_hash_array.slice());
        self.transcript.reset();
        self.transcript.update(&[_]u8{
            @enumToInt(MsgType.message_hash),
            0,
            0,
            @intCast(u8, ch_hash_array.slice().len),
        });
        self.transcript.update(ch_hash_array.slice());

        var hello_retry_request = ServerHelloMsg{
            .vers = self.hello.?.vers,
            .random = &hello_retry_request_random,
            .session_id = self.hello.?.session_id,
            .cipher_suite = self.hello.?.cipher_suite,
            .compression_method = self.hello.?.compression_method,
            .supported_version = self.hello.?.supported_version,
            .selected_group = selected_group,
        };
        self.transcript.update(try hello_retry_request.marshal(allocator));
        try self.conn.writeRecord(
            allocator,
            .handshake,
            try hello_retry_request.marshal(allocator),
        );

        try self.sendDummyChangeCipherSpec(allocator);

        var client_hello = blk: {
            var hs_msg = try self.conn.readHandshake(allocator);
            switch (hs_msg) {
                .client_hello => |m| break :blk m,
                else => {},
            }
            self.conn.sendAlert(.unexpected_message) catch {};
            return error.UnexpectedMessage;
        };
        defer client_hello.deinit(allocator);

        if (client_hello.key_shares.len != 1 or
            client_hello.key_shares[0].group != selected_group)
        {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.TlsClientSentInvalidKeyShareInSecondClientHello;
        }

        if (client_hello.early_data) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.TlsClientIndicatedEarlyDataInSecondClientHello;
        }

        if (illegalClientHelloChange(&client_hello, &self.client_hello)) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.TlsClientIllegallyModifiedSecondClientHello;
        }

        self.client_hello.deinit(allocator);
        self.client_hello = client_hello;
    }

    fn checkForResumption(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        std.log.info("ServerHandshakeStateTls13.checkForResumption start", .{});
        if (self.conn.config.session_tickets_disabled) {
            return;
        }

        if (!memx.containsScalar(PskMode, self.client_hello.psk_modes, .dhe)) {
            return;
        }

        if (self.client_hello.psk_identities.len != self.client_hello.psk_binders.len) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.InvalidOrMissingPskBinders;
        }
        if (self.client_hello.psk_identities.len == 0) {
            return;
        }

        for (self.client_hello.psk_identities) |identity, i| {
            if (i >= max_client_psk_identities) {
                break;
            }

            var used_old_key: bool = undefined;
            const plaintext = try decryptTicket(
                allocator,
                self.conn.ticket_keys,
                identity.label,
                &used_old_key,
            );
            if (plaintext.len == 0) {
                continue;
            }
            defer allocator.free(plaintext);

            var session_state = SessionStateTls13.unmarshal(
                allocator,
                plaintext,
            ) catch continue;
            defer session_state.deinit(allocator);

            const now = datetime.datetime.Datetime.now();
            if (@divTrunc(now.toTimestamp(), std.time.ms_per_s) - session_state.created_at >
                max_session_ticket_lifetime_seconds)
            {
                continue;
            }

            // We don't check the obfuscated ticket age because it's affected by
            // clock skew and it's only a freshness signal useful for shrinking the
            // window for replay attacks, which don't affect us as we don't do 0-RTT.

            const psk_suite = cipherSuiteTls13ById(session_state.cipher_suite);
            if (psk_suite == null or psk_suite.?.hash_type != self.suite.?.hash_type) {
                continue;
            }

            // PSK connections don't re-establish client certificates, but carry
            // them over in the session ticket. Ensure the presence of client certs
            // in the ticket is consistent with the configured requirements.
            const session_has_client_certs = session_state.certificate.certificate_chain.len != 0;
            const needs_client_certs = self.conn.config.client_auth.requiresClientCert();
            if (needs_client_certs and !session_has_client_certs) {
                continue;
            }
            if (session_has_client_certs and self.conn.config.client_auth == .no_client_cert) {
                continue;
            }

            std.log.info("ServerHandshakeStateTls13.checkForResumption resumption_secret={}", .{std.fmt.fmtSliceHexLower(session_state.resumption_secret)});
            const psk = try self.suite.?.expandLabel(
                allocator,
                session_state.resumption_secret,
                resumption_label,
                "",
                @intCast(u16, self.suite.?.hash_type.digestLength()),
            );
            defer allocator.free(psk);
            std.log.info("ServerHandshakeStateTls13.checkForResumption psk={}", .{std.fmt.fmtSliceHexLower(psk)});

            const early_secret = try self.suite.?.extract(allocator, psk, null);
            if (self.early_secret) |secret| allocator.free(secret);
            self.early_secret = early_secret;
            std.log.info("ServerHandshakeStateTls13.checkForResumption early_secret={}", .{std.fmt.fmtSliceHexLower(early_secret)});

            const binder_key = try self.suite.?.deriveSecret(
                allocator,
                early_secret,
                resumption_binder_label,
                null,
            );
            defer allocator.free(binder_key);
            std.log.info("ServerHandshakeStateTls13.checkForResumption binder_key={}", .{std.fmt.fmtSliceHexLower(binder_key)});

            var transcript = self.transcript.clone();
            const client_hello_bytes_without_binders = try self.client_hello.marshalWithoutBinders(allocator);
            std.log.info("ServerHandshakeStateTls13.checkForResumption client_hello_bytes_without_binders={}", .{std.fmt.fmtSliceHexLower(client_hello_bytes_without_binders)});
            transcript.update(client_hello_bytes_without_binders);
            const psk_binder = try self.suite.?.finishedHash(allocator, binder_key, transcript);
            std.log.info("ServerHandshakeStateTls13.checkForResumption client_hello.psk_binders[{}]={}", .{ i, std.fmt.fmtSliceHexLower(self.client_hello.psk_binders[i]) });
            std.log.info("ServerHandshakeStateTls13.checkForResumption psk_binder={}", .{std.fmt.fmtSliceHexLower(psk_binder)});
            defer allocator.free(psk_binder);
            if (!hmac.equal(self.client_hello.psk_binders[i], psk_binder)) {
                self.conn.sendAlert(.decrypt_error) catch {};
                return error.TlsInvalidPskBinder;
            }

            self.conn.did_resume = true;
            try self.conn.processCertsFromClient(allocator, &session_state.certificate);
            self.hello.?.selected_identity = @intCast(u16, i);
            std.log.info(
                "ServerHandshakeStateTls13.checkForResumption set server_hello.selected_identity to {}",
                .{i},
            );
            self.using_psk = true;
            return;
        }
    }

    fn pickCertificate(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        std.log.debug("ServerHandshakeStateTls13.pickCertificate start", .{});

        // Only one of PSK and certificates are used at a time.
        if (self.using_psk) {
            return;
        }

        // signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
        if (self.client_hello.supported_signature_algorithms.len == 0) {
            std.log.debug("ServerHandshakeStateTls13.pickCertificate err exit#1", .{});
            return self.conn.sendAlert(.missing_extension);
        }

        // TODO: check client_hello
        var cert_chain = self.conn.config.getCertificate();
        // errdefer cert_chain.deinit(allocator);

        self.sig_alg = selectSignatureScheme(
            allocator,
            self.conn.version.?,
            cert_chain,
            self.client_hello.supported_signature_algorithms,
        ) catch |err| {
            // getCertificate returned a certificate that is unsupported or
            // incompatible with the client's signature algorithms.
            self.conn.sendAlert(.handshake_failure) catch {};

            std.log.debug("ServerHandshakeStateTls13.pickCertificate err exit#2", .{});
            return err;
        };

        self.cert_chain = cert_chain;
        std.log.debug("ServerHandshakeStateTls13.pickCertificate exit", .{});
    }

    fn sendServerParameters(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        self.transcript.update(try self.client_hello.marshal(allocator));
        const server_hello_bytes = try self.hello.?.marshal(allocator);
        self.transcript.update(server_hello_bytes);
        try self.conn.writeRecord(allocator, .handshake, server_hello_bytes);

        try self.sendDummyChangeCipherSpec(allocator);

        {
            self.handshake_secret = blk: {
                const early_secret = self.early_secret orelse
                    try self.suite.?.extract(allocator, null, null);
                defer if (self.early_secret == null) allocator.free(early_secret);

                const current_secret = try self.suite.?.deriveSecret(
                    allocator,
                    early_secret,
                    derived_label,
                    null,
                );
                defer allocator.free(current_secret);
                break :blk try self.suite.?.extract(allocator, self.shared_key, current_secret);
            };
            std.log.debug(
                "ServerHandshakeStateTls13.sendServerParameters handshake_secret={}",
                .{std.fmt.fmtSliceHexLower(self.handshake_secret)},
            );

            const client_secret = try self.suite.?.deriveSecret(
                allocator,
                self.handshake_secret,
                client_handshake_traffic_label,
                self.transcript,
            );
            defer allocator.free(client_secret);
            std.log.debug(
                "ServerHandshakeStateTls13.sendServerParameters client_secret={}",
                .{std.fmt.fmtSliceHexLower(client_secret)},
            );
            try self.conn.in.setTrafficSecret(allocator, self.suite.?, client_secret);
            std.log.debug(
                "ServerHandshakeStateTls13.sendServerParameters in.traffic_secret={}",
                .{std.fmt.fmtSliceHexLower(self.conn.in.traffic_secret)},
            );

            const server_secret = try self.suite.?.deriveSecret(
                allocator,
                self.handshake_secret,
                server_handshake_traffic_label,
                self.transcript,
            );
            defer allocator.free(server_secret);
            std.log.debug(
                "ServerHandshakeStateTls13.sendServerParameters server_secret={}",
                .{std.fmt.fmtSliceHexLower(server_secret)},
            );
            try self.conn.out.setTrafficSecret(allocator, self.suite.?, server_secret);
            std.log.debug(
                "ServerHandshakeStateTls13.sendServerParameters out.traffic_secret={}",
                .{std.fmt.fmtSliceHexLower(self.conn.out.traffic_secret)},
            );

            try self.conn.config.writeKeyLog(
                allocator,
                KeyLog.label_client_handshake,
                self.client_hello.random,
                client_secret,
            );
            try self.conn.config.writeKeyLog(
                allocator,
                KeyLog.label_server_handshake,
                self.client_hello.random,
                server_secret,
            );
        }

        const selected_proto = negotiateAlpn(
            self.conn.config.next_protos,
            self.client_hello.alpn_protocols,
        ) catch |err| {
            self.conn.sendAlert(.no_application_protocol) catch {};
            return err;
        };
        self.conn.client_protocol = try allocator.dupe(u8, selected_proto);

        var encrypted_extensions_msg = EncryptedExtensionsMsg{
            .alpn_protocol = try allocator.dupe(u8, selected_proto),
        };
        defer encrypted_extensions_msg.deinit(allocator);

        const encrypted_extensions_msg_bytes = try encrypted_extensions_msg.marshal(allocator);
        self.transcript.update(encrypted_extensions_msg_bytes);
        try self.conn.writeRecord(allocator, .handshake, encrypted_extensions_msg_bytes);
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
        // Only one of PSK and certificates are used at a time.
        if (self.using_psk) {
            return;
        }

        if (self.requestClientCert()) {
            var cert_req_msg = CertificateRequestMsgTls13{
                .ocsp_stapling = true,
                .scts = true,
                .supported_signature_algorithms = try allocator.dupe(
                    SignatureScheme,
                    supported_signature_algorithms,
                ),
            };
            defer cert_req_msg.deinit(allocator);

            if (self.conn.config.client_cas) |*cas| {
                cert_req_msg.certificate_authorities = try cas.subjects(allocator);
            }

            const cert_req_msg_bytes = try cert_req_msg.marshal(allocator);
            self.transcript.update(cert_req_msg_bytes);
            try self.conn.writeRecord(allocator, .handshake, cert_req_msg_bytes);
        }

        {
            var cert_msg = blk: {
                const scts = self.client_hello.scts and
                    self.cert_chain.?.signed_certificate_timestamps != null and
                    self.cert_chain.?.signed_certificate_timestamps.?.len > 0;
                const ocsp_stapling = self.client_hello.ocsp_stapling and
                    self.cert_chain.?.ocsp_staple.len > 0;
                std.log.debug(
                    "ServerHandshakeStateTls13.sendServerCertificate scts={}, ocsp_stapling={}",
                    .{ scts, ocsp_stapling },
                );

                var cert_chain = CertificateChain{
                    .certificate_chain = try memx.dupeStringList(
                        allocator,
                        self.cert_chain.?.certificate_chain,
                    ),
                };
                errdefer cert_chain.deinit(allocator);

                if (scts) {
                    cert_chain.signed_certificate_timestamps =
                        try memx.dupeStringList(
                        allocator,
                        self.cert_chain.?.signed_certificate_timestamps.?,
                    );
                }
                if (ocsp_stapling) {
                    cert_chain.ocsp_staple = try allocator.dupe(u8, self.cert_chain.?.ocsp_staple);
                }

                break :blk CertificateMsgTls13{
                    .cert_chain = cert_chain,
                    .ocsp_stapling = ocsp_stapling,
                    .scts = scts,
                };
            };
            defer cert_msg.deinit(allocator);

            const cert_msg_bytes = try cert_msg.marshal(allocator);
            self.transcript.update(cert_msg_bytes);
            try self.conn.writeRecord(allocator, .handshake, cert_msg_bytes);
        }

        {
            var cert_verify_msg = blk: {
                const sig_type = try SignatureType.fromSignatureScheme(self.sig_alg.?);
                const sig_hash = try HashType.fromSignatureScheme(self.sig_alg.?);

                var signed = try signedMessage(
                    allocator,
                    sig_hash,
                    server_signature_context,
                    self.transcript,
                );
                defer allocator.free(signed);
                std.log.debug(
                    "ServerHandshakeStateTls13.sendServerCertificate signed={}",
                    .{std.fmt.fmtSliceHexLower(signed)},
                );

                const sign_opts = if (sig_type == .rsa_pss)
                    crypto.SignOpts{ .hash_type = sig_hash, .salt_length = .equals_hash }
                else
                    crypto.SignOpts{ .hash_type = sig_hash };
                std.log.debug(
                    "ServerHandshakeStateTls13.sendServerCertificate cert={}",
                    .{std.fmt.fmtSliceHexLower(self.cert_chain.?.certificate_chain[0])},
                );
                var sig = self.cert_chain.?.private_key.?.sign(
                    allocator,
                    signed,
                    sign_opts,
                ) catch {
                    const alert_desc: AlertDescription = blk_alert_desc: {
                        if (sig_type == .rsa_pss) {
                            switch (self.cert_chain.?.private_key.?) {
                                .rsa => break :blk_alert_desc .handshake_failure,
                                else => {},
                            }
                        }
                        break :blk_alert_desc .internal_error;
                    };
                    self.conn.sendAlert(alert_desc) catch {};
                    return error.SignHandshakeFailed;
                };
                std.log.debug(
                    "ServerHandshakeStateTls13.sendServerCertificate sig={}",
                    .{std.fmt.fmtSliceHexLower(sig)},
                );

                break :blk CertificateVerifyMsg{
                    .signature_algorithm = self.sig_alg.?,
                    .signature = sig,
                };
            };
            defer cert_verify_msg.deinit(allocator);

            const cert_verify_msg_bytes = try cert_verify_msg.marshal(allocator);
            self.transcript.update(cert_verify_msg_bytes);
            try self.conn.writeRecord(allocator, .handshake, cert_verify_msg_bytes);
        }
    }

    fn sendServerFinished(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        {
            var finished_msg = FinishedMsg{
                .verify_data = try self.suite.?.finishedHash(
                    allocator,
                    self.conn.out.traffic_secret,
                    self.transcript,
                ),
            };
            defer finished_msg.deinit(allocator);

            const finished_msg_bytes = try finished_msg.marshal(allocator);
            self.transcript.update(finished_msg_bytes);
            try self.conn.writeRecord(allocator, .handshake, finished_msg_bytes);
        }

        // Derive secrets that take context through the server Finished.

        self.master_secret = blk: {
            const current_secret = try self.suite.?.deriveSecret(
                allocator,
                self.handshake_secret,
                derived_label,
                null,
            );
            defer allocator.free(current_secret);
            break :blk try self.suite.?.extract(allocator, null, current_secret);
        };
        std.log.debug(
            "ServerHandshakeStateTls13.sendServerFinished master_secret={}",
            .{std.fmt.fmtSliceHexLower(self.master_secret)},
        );

        self.traffic_secret = try self.suite.?.deriveSecret(
            allocator,
            self.master_secret,
            client_application_traffic_label,
            self.transcript,
        );
        std.log.debug(
            "ServerHandshakeStateTls13.sendServerFinished traffic_secret={}",
            .{std.fmt.fmtSliceHexLower(self.traffic_secret)},
        );

        {
            const server_secret = try self.suite.?.deriveSecret(
                allocator,
                self.master_secret,
                server_application_traffic_label,
                self.transcript,
            );
            defer allocator.free(server_secret);
            std.log.debug(
                "ServerHandshakeStateTls13.sendServerFinished server_secret={}",
                .{std.fmt.fmtSliceHexLower(server_secret)},
            );
            try self.conn.out.setTrafficSecret(allocator, self.suite.?, server_secret);
            std.log.debug(
                "ServerHandshakeStateTls13.sendServerFinished out.traffic_secret={}",
                .{std.fmt.fmtSliceHexLower(self.conn.out.traffic_secret)},
            );

            try self.conn.config.writeKeyLog(
                allocator,
                KeyLog.label_client_traffic,
                self.client_hello.random,
                self.traffic_secret,
            );
            try self.conn.config.writeKeyLog(
                allocator,
                KeyLog.label_server_traffic,
                self.client_hello.random,
                server_secret,
            );
        }

        // If we did not request client certificates, at this point we can
        // precompute the client finished and roll the transcript forward to send
        // session tickets in our first flight.
        if (!self.requestClientCert()) {
            try self.sendSessionTickets(allocator);
        }
    }

    fn shouldSendSessionTickets(self: *const ServerHandshakeStateTls13) bool {
        std.log.info("ServerHandshakeStateTls13.shouldSendSessionTickets self.conn.config.session_tickets_disabled={}", .{self.conn.config.session_tickets_disabled});
        if (self.conn.config.session_tickets_disabled) {
            return false;
        }

        // Don't send tickets the client wouldn't use. See RFC 8446, Section 4.2.9.
        std.log.info("ServerHandshakeStateTls13.shouldSendSessionTickets self.client_hello.psk_modes={any}", .{self.client_hello.psk_modes});
        return memx.containsScalar(PskMode, self.client_hello.psk_modes, .dhe);
    }

    fn sendSessionTickets(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        std.log.info("ServerHandshakeStateTls13.sendSessionTickets start", .{});
        self.client_finished = try self.suite.?.finishedHash(
            allocator,
            self.conn.in.traffic_secret,
            self.transcript,
        );

        {
            var finished_msg = FinishedMsg{
                .verify_data = self.client_finished,
            };
            defer {
                finished_msg.verify_data = "";
                finished_msg.deinit(allocator);
            }

            const finished_msg_bytes = try finished_msg.marshal(allocator);
            self.transcript.update(finished_msg_bytes);
        }

        std.log.info("ServerHandshakeStateTls13.sendSessionTickets before shouldSendSessionTickets", .{});
        if (!self.shouldSendSessionTickets()) {
            return;
        }

        std.log.info("ServerHandshakeStateTls13.sendSessionTickets after shouldSendSessionTickets", .{});

        const label = blk_label: {
            var state = blk_state: {
                const resumption_secret = try self.suite.?.deriveSecret(
                    allocator,
                    self.master_secret,
                    resumption_master_label,
                    self.transcript,
                );
                errdefer allocator.free(resumption_secret);

                var certs_from_client = blk_certs: {
                    var certs = try allocator.alloc([]const u8, self.conn.peer_certificates.len);
                    var i: usize = 0;
                    errdefer memx.freeElemsAndFreeSliceInError([]const u8, certs, allocator, i);
                    while (i < self.conn.peer_certificates.len) : (i += 1) {
                        certs[i] = try allocator.dupe(u8, self.conn.peer_certificates[i].raw);
                    }
                    break :blk_certs certs;
                };
                errdefer memx.freeElemsAndFreeSlice([]const u8, certs_from_client, allocator);

                var ocsp_response = try allocator.dupe(u8, self.conn.ocsp_response);
                errdefer allocator.free(ocsp_response);

                var scts = try memx.dupeStringList(allocator, self.conn.scts);
                errdefer memx.freeElemsAndFreeSlice([]const u8, scts, allocator);

                const now = datetime.datetime.Datetime.now();
                break :blk_state SessionStateTls13{
                    .cipher_suite = self.suite.?.id,
                    .created_at = @intCast(u64, @divTrunc(now.toTimestamp(), std.time.ms_per_s)),
                    .resumption_secret = resumption_secret,
                    .certificate = CertificateChain{
                        .certificate_chain = certs_from_client,
                        .ocsp_staple = ocsp_response,
                        .signed_certificate_timestamps = scts,
                    },
                };
            };
            defer state.deinit(allocator);

            const state_bytes = try state.marshal(allocator);
            defer allocator.free(state_bytes);

            break :blk_label try encryptTicket(
                allocator,
                self.conn.ticket_keys,
                state_bytes,
                self.conn.config.random,
            );
        };

        var msg = NewSessionTicketMsgTls13{
            .lifetime = max_session_ticket_lifetime_seconds,
            .label = label,
        };
        defer msg.deinit(allocator);

        try self.conn.writeRecord(allocator, .handshake, try msg.marshal(allocator));
        std.log.info("ServerHandshakeStateTls13.sendSessionTickets written NewSessionTicketMsgTls13", .{});
    }

    fn readClientCertificate(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        if (!self.requestClientCert()) {
            // Make sure the connection is still being verified whether or not
            // the server requested a client certificate.

            // TODO: implement using self.conn.verifyConnection
            return;
        }

        // If we requested a client certificate, then the client must send a
        // certificate message. If it's empty, no CertificateVerify is sent.

        var cert_msg = blk: {
            var hs_msg = try self.conn.readHandshake(allocator);
            switch (hs_msg) {
                .certificate => |m| {
                    switch (m) {
                        .v1_3 => break :blk m.v1_3,
                        else => {},
                    }
                },
                else => {},
            }
            self.conn.sendAlert(.unexpected_message) catch {};
            return error.UnexpectedMessage;
        };
        defer cert_msg.deinit(allocator);

        self.transcript.update(try cert_msg.marshal(allocator));

        try self.conn.processCertsFromClient(allocator, &cert_msg.cert_chain);

        // TODO: implement using self.conn.verifyConnection

        if (cert_msg.cert_chain.certificate_chain.len != 0) {
            var cert_verify_msg = blk: {
                var hs_msg = try self.conn.readHandshake(allocator);
                errdefer hs_msg.deinit(allocator);
                switch (hs_msg) {
                    .certificate_verify => |m| break :blk m,
                    else => {
                        self.conn.sendAlert(.unexpected_message) catch {};
                        return error.UnexpectedMessage;
                    },
                }
            };
            defer cert_verify_msg.deinit(allocator);

            const sig_alg = cert_verify_msg.signature_algorithm;
            if (!isSupportedSignatureAlgorithm(sig_alg, supported_signature_algorithms)) {
                self.conn.sendAlert(.illegal_parameter) catch {};
                return error.InvalidSignatureAlgorithmInClientCertificate;
            }

            const sig_type = SignatureType.fromSignatureScheme(sig_alg) catch |err| {
                self.conn.sendAlert(.internal_error) catch {};
                return err;
            };
            const sig_hash = HashType.fromSignatureScheme(sig_alg) catch |err| {
                self.conn.sendAlert(.internal_error) catch {};
                return err;
            };
            if (sig_type == .pkcs1v15 or .sig_hash == .sha1) {
                self.conn.sendAlert(.illegal_parameter) catch {};
                return error.InvalidSignatureAlgorithmInClientCertificate;
            }

            var signed = try signedMessage(
                allocator,
                sig_hash,
                client_signature_context,
                self.transcript,
            );
            defer allocator.free(signed);

            verifyHandshakeSignature(
                allocator,
                sig_type,
                self.conn.peer_certificates[0].public_key,
                sig_hash,
                signed,
                cert_verify_msg.signature,
            ) catch {
                self.conn.sendAlert(.decrypt_error) catch {};
                return error.InvalidSignatureByClientCertificate;
            };

            self.transcript.update(try cert_verify_msg.marshal(allocator));
            self.transcript.logFinal("ServerHandshakeStateTls13.transcript after cert_verify: ");
        }

        // If we waited until the client certificates to send session tickets, we
        // are ready to do it now.
        try self.sendSessionTickets(allocator);
    }

    fn readClientFinished(self: *ServerHandshakeStateTls13, allocator: mem.Allocator) !void {
        std.log.info("ServerHandshakeStateTls13.readClientFinished start", .{});
        var finished_msg = blk: {
            var hs_msg = try self.conn.readHandshake(allocator);
            break :blk switch (hs_msg) {
                .finished => |m| m,
                else => {
                    self.conn.sendAlert(.unexpected_message) catch {};
                    return error.UnexpectedMessage;
                },
            };
        };
        defer finished_msg.deinit(allocator);
        std.log.info("ServerHandshakeStateTls13.readClientFinished read client finished_msg OK", .{});

        if (!hmac.equal(self.client_finished, finished_msg.verify_data)) {
            self.conn.sendAlert(.decrypt_error) catch {};
            return error.InvalidClientFinishedHash;
        }

        try self.conn.in.setTrafficSecret(allocator, self.suite.?, self.traffic_secret);
        std.log.info("ServerHandshakeStateTls13.readClientFinished exit", .{});
    }
};

fn illegalClientHelloChange(ch: *const ClientHelloMsg, ch1: *const ClientHelloMsg) bool {
    return !mem.eql(ProtocolVersion, ch.supported_versions, ch1.supported_versions) or
        !mem.eql(CipherSuiteId, ch.cipher_suites, ch1.cipher_suites) or
        !mem.eql(CurveId, ch.supported_curves, ch1.supported_curves) or
        !mem.eql(SignatureScheme, ch.supported_signature_algorithms, ch1.supported_signature_algorithms) or
        !mem.eql(SignatureScheme, ch.supported_signature_algorithms_cert, ch1.supported_signature_algorithms_cert) or
        !memx.eqlStringList(ch.alpn_protocols, ch1.alpn_protocols) or
        ch.vers != ch1.vers or
        !mem.eql(u8, ch.random, ch1.random) or
        !mem.eql(u8, ch.session_id, ch1.session_id) or
        !mem.eql(CompressionMethod, ch.compression_methods, ch1.compression_methods) or
        !mem.eql(u8, ch.server_name, ch1.server_name) or
        ch.ocsp_stapling != ch1.ocsp_stapling or
        !mem.eql(EcPointFormat, ch.supported_points, ch1.supported_points) or
        ch.ticket_supported != ch1.ticket_supported or
        !mem.eql(u8, ch.session_ticket, ch1.session_ticket) or
        ch.secure_renegotiation_supported != ch1.secure_renegotiation_supported or
        !mem.eql(u8, ch.secure_renegotiation, ch1.secure_renegotiation) or
        ch.scts != ch1.scts or
        !mem.eql(u8, ch.cookie, ch1.cookie) or
        !mem.eql(PskMode, ch.psk_modes, ch1.psk_modes);
}
