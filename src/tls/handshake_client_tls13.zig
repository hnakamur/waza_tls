const std = @import("std");
const mem = std.mem;
const Conn = @import("conn.zig").Conn;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const FinishedMsg = @import("handshake_msg.zig").FinishedMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const EcdheParameters = @import("key_schedule.zig").EcdheParameters;
const CipherSuiteTls13 = @import("cipher_suites.zig").CipherSuiteTls13;
const mutualCipherSuiteTls13 = @import("cipher_suites.zig").mutualCipherSuiteTls13;
const cipherSuiteTls13ById = @import("cipher_suites.zig").cipherSuiteTls13ById;
const hello_retry_request_random = @import("common.zig").hello_retry_request_random;
const supported_signature_algorithms = @import("common.zig").supported_signature_algorithms;
const checkAlpn = @import("handshake_client.zig").checkAlpn;
const isSupportedSignatureAlgorithm = @import("auth.zig").isSupportedSignatureAlgorithm;
const SignatureType = @import("auth.zig").SignatureType;
const HashType = @import("auth.zig").HashType;
const signedMessage = @import("auth.zig").signedMessage;
const verifyHandshakeSignature = @import("auth.zig").verifyHandshakeSignature;
const derived_label = @import("key_schedule.zig").derived_label;
const client_handshake_traffic_label = @import("key_schedule.zig").client_handshake_traffic_label;
const server_handshake_traffic_label = @import("key_schedule.zig").server_handshake_traffic_label;
const client_application_traffic_label = @import("key_schedule.zig").client_application_traffic_label;
const server_application_traffic_label = @import("key_schedule.zig").server_application_traffic_label;
const server_signature_context = @import("auth.zig").server_signature_context;
const hmac = @import("hmac.zig");
const crypto = @import("crypto.zig");
const memx = @import("../memx.zig");

const ClientSessionState = struct {
    cipher_suite: CipherSuiteId,
};

pub const ClientHandshakeStateTls13 = struct {
    conn: *Conn,
    hello: ClientHelloMsg,
    server_hello: ServerHelloMsg,
    ecdhe_params: EcdheParameters,

    sent_dummy_ccs: bool = false,

    suite: ?*const CipherSuiteTls13 = null,
    master_secret: []const u8 = "",
    traffic_secret: []const u8 = "", // client_application_traffic_secret_0
    transcript: crypto.Hash = undefined,

    using_psk: bool = false,
    early_secret: []const u8 = "",

    session: ?ClientSessionState = null,

    pub fn init(
        conn: *Conn,
        client_hello: ClientHelloMsg,
        server_hello: ServerHelloMsg,
        ecdhe_params: EcdheParameters,
    ) ClientHandshakeStateTls13 {
        return .{
            .hello = client_hello,
            .server_hello = server_hello,
            .conn = conn,
            .ecdhe_params = ecdhe_params,
        };
    }

    pub fn deinit(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) void {
        self.hello.deinit(allocator);
        self.server_hello.deinit(allocator);
        if (self.early_secret.len > 0) allocator.free(self.early_secret);
        if (self.master_secret.len > 0) allocator.free(self.master_secret);
        if (self.traffic_secret.len > 0) allocator.free(self.traffic_secret);
    }

    pub fn handshake(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        if (self.conn.handshakes > 0) {
            self.conn.sendAlert(.protocol_version) catch {};
            return error.ServerSelectedTls13InRenegotiation;
        }

        // Consistency check on the presence of a keyShare and its parameters.
        if (self.hello.key_shares.len != 1) {
            try self.conn.sendAlert(.internal_error);
        }

        try self.checkServerHelloOrHrr();

        self.transcript = crypto.Hash.init(self.suite.?.hash_type);
        self.transcript.update(try self.hello.marshal(allocator));

        if (mem.eql(u8, self.server_hello.random, &hello_retry_request_random)) {
            try self.sendDummyChangeCipherSpec(allocator);
            try self.processHelloRetryRequest(allocator);
        }

        self.transcript.update(try self.server_hello.marshal(allocator));
        self.conn.buffering = true;
        try self.processServerHello(allocator);
        try self.sendDummyChangeCipherSpec(allocator);
        try self.establishHandshakeKeys(allocator);
        try self.readServerParameters(allocator);
        try self.readServerCertificate(allocator);
        try self.readServerFinished(allocator);
        try self.sendClientCertificate(allocator);
        try self.sendClientFinished(allocator);
        try self.conn.flush();

        self.conn.handshake_complete = true;
    }

    // checkServerHelloOrHrr does validity checks that apply to both ServerHello and
    // HelloRetryRequest messages. It sets self.suite.
    fn checkServerHelloOrHrr(self: *ClientHandshakeStateTls13) !void {
        if (self.server_hello.supported_version == null) {
            self.conn.sendAlert(.missing_extension) catch {};
            return error.ServerSelectedTls13UsingLegacyVersionField;
        }

        if (self.server_hello.supported_version.? != .v1_3) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerSelectedInvalidVersionAfterHelloRetryRequest;
        }

        if (self.server_hello.vers != .v1_2) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerSentIncorrectLegacyVersion;
        }

        if (self.server_hello.ocsp_stapling or
            self.server_hello.ticket_supported or
            self.server_hello.secure_renegotiation_supported or
            self.server_hello.secure_renegotiation.len > 0 or
            self.server_hello.alpn_protocol.len > 0 or
            self.server_hello.scts.len > 0)
        {
            self.conn.sendAlert(.unsupported_extension) catch {};
            return error.ServerSentServerHelloExtensionForbiddenInTls13;
        }

        if (!mem.eql(u8, self.hello.session_id, self.server_hello.session_id)) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerDidNotEchoLegacySessionId;
        }

        if (self.server_hello.compression_method != .none) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerSelectedUnsupportedCompressionFormat;
        }

        const selected_suite = mutualCipherSuiteTls13(
            self.hello.cipher_suites,
            self.server_hello.cipher_suite.?,
        );
        if (self.suite != null and selected_suite != self.suite) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerChangedCipherSuiteAfterHelloRetryRequest;
        }
        if (selected_suite == null) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerSelectedUnconfiguredCipherSuite;
        }
        self.suite = selected_suite;
        self.conn.cipher_suite_id = self.suite.?.id;
        std.log.debug("ClientHandshakeStateTls13 selected suite={}", .{selected_suite.?.id});
    }

    // sendDummyChangeCipherSpec sends a ChangeCipherSpec record for compatibility
    // with middleboxes that didn't implement TLS correctly. See RFC 8446, Appendix D.4.
    fn sendDummyChangeCipherSpec(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        if (self.sent_dummy_ccs) {
            return;
        }

        try self.conn.writeRecord(allocator, .change_cipher_spec, &[_]u8{1});
        self.sent_dummy_ccs = true;
    }

    fn processHelloRetryRequest(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        _ = self;
        _ = allocator;
        @panic("not implemented yet");
    }

    fn processServerHello(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        if (mem.eql(u8, self.server_hello.random, &hello_retry_request_random)) {
            self.conn.sendAlert(.unexpected_message) catch {};
            return error.ServerSentTwoHelloRetryRequestMessages;
        }

        if (self.server_hello.cookie.len > 0) {
            self.conn.sendAlert(.unsupported_extension) catch {};
            return error.ServerSentCookieInNormalServerHello;
        }

        if (self.server_hello.selected_group != null) {
            self.conn.sendAlert(.decode_error) catch {};
            return error.MalformedKeyShareExtension;
        }

        if (self.server_hello.server_share == null) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerDidNotSendKeyShare;
        }
        if (self.server_hello.server_share.?.group != self.ecdhe_params.curveId()) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerSelectedUnsupportedGroup;
        }

        if (self.server_hello.selected_identity == null) {
            return;
        }

        if (@as(usize, self.server_hello.selected_identity.?) >= self.hello.psk_identities.len) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerSelectedInvalidPsk;
        }
        if (self.hello.psk_identities.len != 1 or self.session == null) {
            try self.conn.sendAlert(.internal_error);
        }

        const psk_suite = cipherSuiteTls13ById(self.session.?.cipher_suite);
        if (psk_suite == null) {
            try self.conn.sendAlert(.internal_error);
        }
        if (psk_suite.?.hash_type != self.suite.?.hash_type) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.ServerSelectedInvalidPskCipherSuitePair;
        }

        self.using_psk = true;
        _ = allocator;
        @panic("not implemented yet");
    }

    fn establishHandshakeKeys(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        const shared_key = self.ecdhe_params.sharedKey(
            allocator,
            self.server_hello.server_share.?.data,
        ) catch {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.InvalidServerKeyShare;
        };
        defer allocator.free(shared_key);
        std.log.debug(
            "ClientHandshakeStateTls13.establishHandshakeKeys shared_key={}",
            .{std.fmt.fmtSliceHexLower(shared_key)},
        );

        const handshake_secret = blk: {
            const early_secret = if (self.using_psk)
                self.early_secret
            else
                try self.suite.?.extract(allocator, null, null);
            defer if (!self.using_psk) allocator.free(early_secret);

            const current_secret = try self.suite.?.deriveSecret(
                allocator,
                early_secret,
                derived_label,
                null,
            );
            defer allocator.free(current_secret);
            break :blk try self.suite.?.extract(allocator, shared_key, current_secret);
        };
        defer allocator.free(handshake_secret);
        std.log.debug(
            "ClientHandshakeStateTls13.establishHandshakeKeys handshake_secret={}",
            .{std.fmt.fmtSliceHexLower(handshake_secret)},
        );

        const client_secret = try self.suite.?.deriveSecret(
            allocator,
            handshake_secret,
            client_handshake_traffic_label,
            self.transcript,
        );
        defer allocator.free(client_secret);
        std.log.debug(
            "ClientHandshakeStateTls13.establishHandshakeKeys client_secret={}",
            .{std.fmt.fmtSliceHexLower(client_secret)},
        );
        try self.conn.out.setTrafficSecret(allocator, self.suite.?, client_secret);
        std.log.debug(
            "ClientHandshakeStateTls13.establishHandshakeKeys out.traffic_secret={}",
            .{std.fmt.fmtSliceHexLower(self.conn.out.traffic_secret)},
        );

        const server_secret = try self.suite.?.deriveSecret(
            allocator,
            handshake_secret,
            server_handshake_traffic_label,
            self.transcript,
        );
        defer allocator.free(server_secret);
        std.log.debug(
            "ClientHandshakeStateTls13.establishHandshakeKeys server_secret={}",
            .{std.fmt.fmtSliceHexLower(server_secret)},
        );
        try self.conn.in.setTrafficSecret(allocator, self.suite.?, server_secret);
        std.log.debug(
            "ClientHandshakeStateTls13.establishHandshakeKeys in.traffic_secret={}",
            .{std.fmt.fmtSliceHexLower(self.conn.in.traffic_secret)},
        );

        // TODO: implement write key log

        self.master_secret = blk: {
            const current_secret = try self.suite.?.deriveSecret(
                allocator,
                handshake_secret,
                derived_label,
                null,
            );
            defer allocator.free(current_secret);
            break :blk try self.suite.?.extract(allocator, null, current_secret);
        };
        std.log.debug(
            "ClientHandshakeStateTls13.establishHandshakeKeys master_secret={}",
            .{std.fmt.fmtSliceHexLower(self.master_secret)},
        );
    }

    fn readServerParameters(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        var ext_msg = blk: {
            var hs_msg = try self.conn.readHandshake(allocator);
            break :blk switch (hs_msg) {
                .EncryptedExtensions => |m| m,
                else => {
                    self.conn.sendAlert(.unexpected_message) catch {};
                    return error.UnexpectedMessage;
                },
            };
        };
        defer ext_msg.deinit(allocator);

        self.transcript.update(try ext_msg.marshal(allocator));

        checkAlpn(self.hello.alpn_protocols, ext_msg.alpn_protocol) catch |err| {
            self.conn.sendAlert(.unsupported_extension) catch {};
            return err;
        };
        self.conn.client_protocol = try allocator.dupe(u8, ext_msg.alpn_protocol);
    }

    fn readServerCertificate(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        // Either a PSK or a certificate is always used, but not both.
        // See RFC 8446, Section 4.1.1.
        if (self.using_psk) {
            @panic("not implemented yet");
        }

        var hs_msg = try self.conn.readHandshake(allocator);
        switch (hs_msg) {
            .CertificateRequest => {
                // self.transcript.update(try m.marshal(allocator));
                @panic("not implemented yet");
                // hs_msg = try self.conn.readHandshake(allocator);
            },
            else => {},
        }

        var cert_msg = switch (hs_msg) {
            .Certificate => |m| m.v1_3,
            else => {
                self.conn.sendAlert(.unexpected_message) catch {};
                return error.UnexpectedMessage;
            },
        };
        defer cert_msg.deinit(allocator);

        if (cert_msg.cert_chain.certificate_chain.len == 0) {
            self.conn.sendAlert(.decode_error) catch {};
            return error.ReceivedEmptyCertificatesMessage;
        }
        self.transcript.update(try cert_msg.marshal(allocator));

        if (cert_msg.cert_chain.signed_certificate_timestamps) |scts| {
            self.conn.scts = try memx.dupeStringList(allocator, scts);
        }
        self.conn.ocsp_response = try allocator.dupe(u8, cert_msg.cert_chain.ocsp_staple);

        try self.conn.verifyServerCertificate(cert_msg.cert_chain.certificate_chain);

        var cert_verify_msg = blk: {
            hs_msg = try self.conn.readHandshake(allocator);
            break :blk switch (hs_msg) {
                .CertificateVerify => |m| m,
                else => {
                    self.conn.sendAlert(.unexpected_message) catch {};
                    return error.UnexpectedMessage;
                },
            };
        };
        defer cert_verify_msg.deinit(allocator);

        // See RFC 8446, Section 4.4.3.
        if (!isSupportedSignatureAlgorithm(
            cert_verify_msg.signature_algorithm,
            supported_signature_algorithms,
        )) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.CertificateUsedWithInvalidSignatureAlgorithm;
        }

        const sig_type = try SignatureType.fromSignatureScheme(cert_verify_msg.signature_algorithm);
        const sig_hash = try HashType.fromSignatureScheme(cert_verify_msg.signature_algorithm);
        if (sig_type == .pkcs1v15 or sig_hash == .sha1) {
            self.conn.sendAlert(.illegal_parameter) catch {};
            return error.CertificateUsedWithInvalidSignatureAlgorithm;
        }

        var signed = try signedMessage(
            allocator,
            sig_hash,
            server_signature_context,
            self.transcript,
        );
        defer allocator.free(signed);
        std.log.debug(
            "ClientHandshakeStateTls13.readServerCertificate signed={}",
            .{std.fmt.fmtSliceHexLower(signed)},
        );

        std.log.debug(
            "ClientHandshakeStateTls13.readServerCertificate cert={}",
            .{std.fmt.fmtSliceHexLower(self.conn.peer_certificates[0].raw)},
        );
        verifyHandshakeSignature(
            allocator,
            sig_type,
            self.conn.peer_certificates[0].public_key,
            sig_hash,
            signed,
            cert_verify_msg.signature,
        ) catch {
            self.conn.sendAlert(.decrypt_error) catch {};
            return error.InvalidSignatureByServerCertificate;
        };

        self.transcript.update(try cert_verify_msg.marshal(allocator));
    }

    fn readServerFinished(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        var finished_msg = blk: {
            var hs_msg = try self.conn.readHandshake(allocator);
            break :blk switch (hs_msg) {
                .Finished => |m| m,
                else => {
                    self.conn.sendAlert(.unexpected_message) catch {};
                    return error.UnexpectedMessage;
                },
            };
        };
        defer finished_msg.deinit(allocator);

        const expected_mac = try self.suite.?.finishedHash(
            allocator,
            self.conn.in.traffic_secret,
            self.transcript,
        );
        defer allocator.free(expected_mac);

        if (!hmac.equal(expected_mac, finished_msg.verify_data)) {
            self.conn.sendAlert(.decrypt_error) catch {};
            return error.InvalidServerFinishedHash;
        }

        self.transcript.update(try finished_msg.marshal(allocator));

        // Derive secrets that take context through the server Finished.

        self.traffic_secret = try self.suite.?.deriveSecret(
            allocator,
            self.master_secret,
            client_application_traffic_label,
            self.transcript,
        );
        std.log.debug(
            "ClientHandshakeStateTls13.establishHandshakeKeys traffic_secret={}",
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
                "ClientHandshakeStateTls13.establishHandshakeKeys server_secret={}",
                .{std.fmt.fmtSliceHexLower(server_secret)},
            );
            try self.conn.in.setTrafficSecret(allocator, self.suite.?, server_secret);
            std.log.debug(
                "ClientHandshakeStateTls13.establishHandshakeKeys in.traffic_secret={}",
                .{std.fmt.fmtSliceHexLower(self.conn.in.traffic_secret)},
            );
        }

        // TODO: implement writing key log
    }

    fn sendClientCertificate(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        _ = self;
        _ = allocator;

        // TODO: implement
        return;
    }

    fn sendClientFinished(self: *ClientHandshakeStateTls13, allocator: mem.Allocator) !void {
        var finished_msg = FinishedMsg{
            .verify_data = try self.suite.?.finishedHash(
                allocator,
                self.conn.out.traffic_secret,
                self.transcript,
            ),
        };
        defer finished_msg.deinit(allocator);
        defer allocator.free(finished_msg.verify_data);

        const finished_msg_bytes = try finished_msg.marshal(allocator);
        self.transcript.update(finished_msg_bytes);
        try self.conn.writeRecord(allocator, .handshake, finished_msg_bytes);

        try self.conn.out.setTrafficSecret(allocator, self.suite.?, self.traffic_secret);

        // TODO: implement
    }
};
