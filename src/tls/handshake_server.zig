const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;
const HashType = @import("auth.zig").HashType;
const SignatureType = @import("auth.zig").SignatureType;
const isSupportedSignatureAlgorithm = @import("auth.zig").isSupportedSignatureAlgorithm;
const verifyHandshakeSignature = @import("auth.zig").verifyHandshakeSignature;
const ClientAuthType = @import("client_auth.zig").ClientAuthType;
const CurveId = @import("handshake_msg.zig").CurveId;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CertificateMsgTls12 = @import("handshake_msg.zig").CertificateMsgTls12;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const CertificateRequestMsgTls12 = @import("handshake_msg.zig").CertificateRequestMsgTls12;
const ServerHelloDoneMsg = @import("handshake_msg.zig").ServerHelloDoneMsg;
const FinishedMsg = @import("handshake_msg.zig").FinishedMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const EcPointFormat = @import("handshake_msg.zig").EcPointFormat;
const generateRandom = @import("handshake_msg.zig").generateRandom;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const random_length = @import("handshake_msg.zig").random_length;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuiteTls12 = @import("cipher_suites.zig").CipherSuiteTls12;
const selectCipherSuiteTls12 = @import("cipher_suites.zig").selectCipherSuiteTls12;
const cipherSuiteTls12ById = @import("cipher_suites.zig").cipherSuiteTls12ById;
const has_aes_gcm_hardware_support = @import("cipher_suites.zig").has_aes_gcm_hardware_support;
const aesgcmPreferred = @import("cipher_suites.zig").aesgcmPreferred;
const cipher_suites_preference_order = @import("cipher_suites.zig").cipher_suites_preference_order;
const cipher_suites_preference_order_no_aes = @import("cipher_suites.zig").cipher_suites_preference_order_no_aes;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const SessionStateTls12 = @import("ticket.zig").SessionStateTls12;
const ClientHandshakeState = @import("handshake_client.zig").ClientHandshakeState;
const KeyAgreement = @import("key_agreement.zig").KeyAgreement;
const masterFromPreMasterSecret = @import("prf.zig").masterFromPreMasterSecret;
const ConnectionKeys = @import("prf.zig").ConnectionKeys;
const constantTimeEqlBytes = @import("constant_time.zig").constantTimeEqlBytes;
const Conn = @import("conn.zig").Conn;
const downgrade_canary_tls12 = @import("conn.zig").downgrade_canary_tls12;
const supported_signature_algorithms = @import("common.zig").supported_signature_algorithms;
const ServerHandshakeStateTls13 = @import("handshake_server_tls13.zig").ServerHandshakeStateTls13;
const decryptTicket = @import("ticket.zig").decryptTicket;
const fmtx = @import("../fmtx.zig");
const memx = @import("../memx.zig");

pub const ServerHandshakeState = union(ProtocolVersion) {
    v1_3: ServerHandshakeStateTls13,
    v1_2: ServerHandshakeStateTls12,
    v1_1: void,
    v1_0: void,

    pub fn init(ver: ProtocolVersion, conn: *Conn, client_hello: ClientHelloMsg) ServerHandshakeState {
        return switch (ver) {
            .v1_3 => ServerHandshakeState{ .v1_3 = ServerHandshakeStateTls13.init(conn, client_hello) },
            .v1_2 => ServerHandshakeState{ .v1_2 = ServerHandshakeStateTls12.init(conn, client_hello) },
            .v1_1, .v1_0 => @panic("unsupported version"),
        };
    }

    pub fn deinit(self: *ServerHandshakeState, allocator: mem.Allocator) void {
        switch (self.*) {
            .v1_3 => |*hs| hs.deinit(allocator),
            .v1_2 => |*hs| hs.deinit(allocator),
            .v1_1, .v1_0 => @panic("unsupported version"),
        }
    }

    pub fn handshake(self: *ServerHandshakeState, allocator: mem.Allocator) !void {
        switch (self.*) {
            .v1_3 => |*hs| try hs.handshake(allocator),
            .v1_2 => |*hs| try hs.handshake(allocator),
            .v1_1, .v1_0 => @panic("unsupported version"),
        }
    }
};

// ServerHandshakeStateTls12 contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
pub const ServerHandshakeStateTls12 = struct {
    conn: *Conn,
    client_hello: ClientHelloMsg,
    hello: ?ServerHelloMsg = null,
    suite: ?*const CipherSuiteTls12 = null,
    ecdhe_ok: bool = false,
    ec_sign_ok: bool = false,
    rsa_decrypt_ok: bool = false,
    rsa_sign_ok: bool = false,
    session_state: ?SessionStateTls12 = null,
    finished_hash: ?FinishedHash = null,
    master_secret: ?[]const u8 = null,
    cert_chain: ?*const CertificateChain = null,

    pub fn init(conn: *Conn, client_hello: ClientHelloMsg) ServerHandshakeStateTls12 {
        return .{ .conn = conn, .client_hello = client_hello };
    }

    pub fn deinit(self: *ServerHandshakeStateTls12, allocator: mem.Allocator) void {
        self.client_hello.deinit(allocator);
        if (self.hello) |*hello| hello.deinit(allocator);
        if (self.finished_hash) |*fh| fh.deinit();
        if (self.master_secret) |s| allocator.free(s);
    }

    pub fn handshake(self: *ServerHandshakeStateTls12, allocator: mem.Allocator) !void {
        try self.processClientHello(allocator);

        // For an overview of TLS handshaking, see RFC 5246, Section 7.3.
        self.conn.buffering = true;
        if (self.checkForResumption(allocator)) {
            // TODO: implement
            @panic("not implemented yet");
        } else {
            // The client didn't include a session ticket, or it wasn't
            // valid so we do a full handshake.
            try self.pickCipherSuite();
            try self.doFullHandshake(allocator);
            try self.establishKeys(allocator);
            std.log.debug("ServerHandshakeStateTls12.handshake before readFinished", .{});
            try self.readFinished(allocator, &self.conn.client_finished);
            std.log.debug(
                "ServerHandshakeStateTls12 client_finished={}",
                .{fmtx.fmtSliceHexEscapeLower(&self.conn.client_finished)},
            );
            self.conn.buffering = true;
            try self.sendFinished(allocator, null);
            try self.conn.flush();
            std.log.debug("ServerHandshakeStateTls12 after sendFinished, flush", .{});
        }

        self.conn.handshake_complete = true;
    }

    pub fn processClientHello(self: *ServerHandshakeStateTls12, allocator: mem.Allocator) !void {
        if (!memx.containsScalar(CompressionMethod, self.client_hello.compression_methods, .none)) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.ClientNotSupportUncompressedMethod;
        }

        var random = try allocator.alloc(u8, random_length);
        errdefer allocator.free(random);

        // Downgrade protection canaries. See RFC 8446, Section 4.1.3.
        const max_vers = self.conn.config.maxSupportedVersion();
        if (@enumToInt(max_vers) >= @enumToInt(ProtocolVersion.v1_2) and
            @enumToInt(self.conn.version.?) < @enumToInt(max_vers) and
            self.conn.version.? == .v1_2)
        {
            mem.copy(u8, random[24..], downgrade_canary_tls12);
            self.conn.config.random.bytes(random[0..24]);
        } else {
            self.conn.config.random.bytes(random);
        }

        if (self.client_hello.secure_renegotiation.len > 0) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.InitialHandshakeWithRenegotiation;
        }

        var hello = ServerHelloMsg{
            .vers = self.conn.version.?,
            .random = random,
            .secure_renegotiation_supported = self.client_hello.secure_renegotiation_supported,
            .compression_method = .none,
            .ocsp_stapling = false,
        };

        if (self.client_hello.server_name.len > 0) {
            self.conn.server_name = try allocator.dupe(u8, self.client_hello.server_name);
        }

        if (negotiateAlpn(
            self.conn.config.next_protos,
            self.client_hello.alpn_protocols,
        )) |selected_proto| {
            hello.alpn_protocol = try allocator.dupe(u8, selected_proto);
            self.conn.client_protocol = try allocator.dupe(u8, selected_proto);
        } else |err| {
            self.conn.sendAlert(.no_application_protocol) catch {};
            return err;
        }

        // TODO: check client_hello
        self.cert_chain = self.conn.config.getCertificate();

        self.ecdhe_ok = supportsEcdHe(
            self.conn.config,
            self.client_hello.supported_curves,
            self.client_hello.supported_points,
        );
        std.log.debug("ServerHandshakeStateTls12 ecdhe_ok={}", .{self.ecdhe_ok});
        if (self.ecdhe_ok) {
            // Although omitting the ec_point_formats extension is permitted, some
            // old OpenSSL version will refuse to handshake if not present.
            //
            // Per RFC 4492, section 5.1.2, implementations MUST support the
            // uncompressed point format. See golang.org/issue/31943.
            hello.supported_points = try allocator.dupe(
                EcPointFormat,
                &[_]EcPointFormat{.uncompressed},
            );
        }

        self.hello = hello;

        if (self.cert_chain) |cert_chain| {
            // TODO: check private_key implements sing or decrypt method.
            switch (cert_chain.private_key.?) {
                .ecdsa, .ed25519 => self.ec_sign_ok = true,
                .rsa => {
                    self.rsa_sign_ok = true;
                    self.rsa_decrypt_ok = true;
                },
                else => {
                    self.conn.sendAlert(.internal_error) catch {};
                    return error.UnsupportedSignKeyType;
                },
            }
        }
    }

    // checkForResumption reports whether we should perform resumption on this connection.
    fn checkForResumption(self: *const ServerHandshakeStateTls12, allocator: mem.Allocator) bool {
        if (self.conn.config.session_tickets_disabled) {
            return false;
        }

        var used_old_key: bool = undefined;
        const plaintext = try decryptTicket(
            allocator,
            self.conn.ticket_keys,
            self.client_hello.session_ticket,
            &used_old_key,
        );
        if (plaintext.len == 0) {
            return false;
        }

        // TODO: implemnt

        return true;
    }

    pub fn pickCipherSuite(self: *ServerHandshakeStateTls12) !void {
        const allocator = self.conn.allocator;

        var preference_list = blk: {
            const config_cipher_suites = self.conn.config.cipher_suites;
            var cipher_suites = try std.ArrayListUnmanaged(CipherSuiteId).initCapacity(
                allocator,
                config_cipher_suites.len,
            );
            errdefer cipher_suites.deinit(allocator);

            const preference_order = if (has_aes_gcm_hardware_support and
                aesgcmPreferred(self.client_hello.cipher_suites))
                &cipher_suites_preference_order
            else
                &cipher_suites_preference_order_no_aes;
            for (preference_order) |suite_id| {
                if (memx.containsScalar(CipherSuiteId, config_cipher_suites, suite_id)) {
                    try cipher_suites.append(allocator, suite_id);
                }
            }
            break :blk cipher_suites.toOwnedSlice(allocator);
        };
        defer allocator.free(preference_list);

        self.suite = selectCipherSuiteTls12(
            preference_list,
            self.client_hello.cipher_suites,
            self,
            cipherSuiteOk,
        );
        if (self.suite) |_| {} else {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.CipherNegotiationFailed;
        }
        self.conn.cipher_suite_id = self.suite.?.id;

        if (memx.containsScalar(
            CipherSuiteId,
            self.client_hello.cipher_suites,
            .tls_fallback_scsv,
        )) {
            // The client is doing a fallback connection. See RFC 7507.
            const cli_ver = self.client_hello.vers;
            const max_ver = self.conn.config.maxSupportedVersion();
            std.log.debug("ServerHandshakeStateTls12.pickCipherSuite max_ver={}", .{max_ver});
            if (@enumToInt(cli_ver) < @enumToInt(max_ver)) {
                self.conn.sendAlert(.inappropriate_fallback) catch {};
                return error.InnapropriateProtocolFallback;
            }
        }
    }

    fn cipherSuiteOk(self: *const ServerHandshakeStateTls12, c: *const CipherSuiteTls12) bool {
        if (c.flags.ecdhe) {
            if (!self.ecdhe_ok) {
                return false;
            }
            if (c.flags.ec_sign) {
                if (!self.ec_sign_ok) {
                    return false;
                }
            } else if (!self.rsa_sign_ok) {
                return false;
            }
        } else if (!self.rsa_decrypt_ok) {
            return false;
        }
        if (@enumToInt(self.conn.version.?) < @enumToInt(ProtocolVersion.v1_2) and c.flags.tls12) {
            return false;
        }
        return true;
    }

    pub fn doFullHandshake(self: *ServerHandshakeStateTls12, allocator: mem.Allocator) !void {
        self.hello.?.cipher_suite = self.suite.?.id;

        if (self.client_hello.ocsp_stapling and self.cert_chain.?.ocsp_staple.len > 0) {
            self.hello.?.ocsp_stapling = true;
        }

        self.finished_hash = FinishedHash.new(allocator, self.conn.version.?, self.suite.?);
        if (self.conn.config.client_auth == .no_client_cert) {
            // No need to keep a full record of the handshake if client
            // certificates won't be used.
            self.finished_hash.?.discardHandshakeBuffer();
        }
        try self.finished_hash.?.write(try self.client_hello.marshal(allocator));
        const server_hello_bytes = try self.hello.?.marshal(allocator);
        try self.finished_hash.?.write(server_hello_bytes);
        try self.finished_hash.?.debugLogClientHash(allocator, "server: serverHello");
        try self.conn.writeRecord(allocator, .handshake, server_hello_bytes);
        std.log.info("server: server_hello: {}", .{std.fmt.fmtSliceHexLower(server_hello_bytes)});

        {
            const certificates = try memx.dupeStringList(
                allocator,
                self.cert_chain.?.certificate_chain,
            );
            var cert_msg = CertificateMsgTls12{ .certificates = certificates };
            defer cert_msg.deinit(allocator);

            const cert_msg_bytes = try cert_msg.marshal(allocator);
            try self.finished_hash.?.write(cert_msg_bytes);
            try self.finished_hash.?.debugLogClientHash(allocator, "server: cert");
            try self.conn.writeRecord(allocator, .handshake, cert_msg_bytes);
        }

        if (self.hello.?.ocsp_stapling) {
            @panic("not implemented yet");
        }

        var key_agreement = self.suite.?.ka(self.conn.version.?);
        defer key_agreement.deinit(allocator);

        var skx = try key_agreement.generateServerKeyExchange(
            allocator,
            self.cert_chain.?,
            &self.client_hello,
            &self.hello.?,
        );
        defer skx.deinit(allocator);

        const skx_bytes = try skx.marshal(allocator);
        try self.finished_hash.?.write(skx_bytes);
        try self.finished_hash.?.debugLogClientHash(allocator, "server: skx");
        try self.conn.writeRecord(allocator, .handshake, skx_bytes);
        std.log.info("server: skx: {}", .{std.fmt.fmtSliceHexLower(skx_bytes)});

        std.log.info("server: client_auth: {}", .{self.conn.config.client_auth});
        var cert_req_msg: ?CertificateRequestMsgTls12 = null;
        if (@enumToInt(self.conn.config.client_auth) >=
            @enumToInt(ClientAuthType.request_client_cert))
        {
            cert_req_msg = blk: {
                const cert_types = try allocator.dupe(
                    CertificateRequestMsgTls12.CertificateType,
                    &[_]CertificateRequestMsgTls12.CertificateType{
                        .rsa_sign, .ecdsa_sign,
                    },
                );
                errdefer allocator.free(cert_types);

                const sig_algs = try allocator.dupe(
                    SignatureScheme,
                    supported_signature_algorithms,
                );

                // An empty list of certificateAuthorities signals to
                // the client that it may send any certificate in response
                // to our request. When we know the CAs we trust, then
                // we can send them down, so that the client can choose
                // an appropriate certificate to give to us.
                const auths = if (self.conn.config.client_cas) |*cas| blk2: {
                    break :blk2 try cas.subjects(allocator);
                } else &[_][]u8{};

                break :blk CertificateRequestMsgTls12{
                    .certificate_types = cert_types,
                    .supported_signature_algorithms = sig_algs,
                    .certificate_authorities = auths,
                };
            };

            const cert_req_msg_bytes = try cert_req_msg.?.marshal(allocator);
            try self.finished_hash.?.write(cert_req_msg_bytes);
            try self.conn.writeRecord(allocator, .handshake, cert_req_msg_bytes);
            std.log.info("server: certReq: {}", .{std.fmt.fmtSliceHexLower(cert_req_msg_bytes)});
        }
        defer if (cert_req_msg) |*msg| msg.deinit(allocator);

        var hello_done = ServerHelloDoneMsg{};
        defer hello_done.deinit(allocator);
        const hello_done_bytes = try hello_done.marshal(allocator);
        try self.finished_hash.?.write(hello_done_bytes);
        try self.finished_hash.?.debugLogClientHash(allocator, "server: helloDone");
        try self.conn.writeRecord(allocator, .handshake, hello_done_bytes);
        std.log.info("server: helloDone: {}", .{std.fmt.fmtSliceHexLower(hello_done_bytes)});

        try self.conn.flush();

        var hs_msg = try self.conn.readHandshake(allocator);
        std.log.info("server supposed ckx={}", .{hs_msg});
        // If we requested a client certificate, then the client must send a
        // certificate message, even if it's empty.
        if (@enumToInt(self.conn.config.client_auth) >=
            @enumToInt(ClientAuthType.request_client_cert))
        {
            {
                var cert_msg: CertificateMsgTls12 = undefined;
                switch (hs_msg) {
                    .Certificate => |*c| {
                        switch (c.*) {
                            .v1_2 => |c12| cert_msg = c12,
                            else => {
                                hs_msg.deinit(allocator);
                                self.conn.sendAlert(.unexpected_message) catch {};
                                return error.UnexpectedMessage;
                            },
                        }
                    },
                    else => {
                        hs_msg.deinit(allocator);
                        self.conn.sendAlert(.unexpected_message) catch {};
                        return error.UnexpectedMessage;
                    },
                }
                defer cert_msg.deinit(allocator);

                try self.finished_hash.?.write(cert_msg.raw.?);

                try self.conn.processCertsFromClient(allocator, &CertificateChain{
                    .certificate_chain = cert_msg.certificates,
                });

                if (cert_msg.certificates.len != 0) {}
            }

            hs_msg = try self.conn.readHandshake(allocator);
        }

        // TODO: implement veirfy connection

        // Get client key exchange
        var ckx_msg = switch (hs_msg) {
            .ClientKeyExchange => |c| c,
            else => {
                hs_msg.deinit(allocator);
                self.conn.sendAlert(.unexpected_message) catch {};
                return error.UnexpectedMessage;
            },
        };
        defer ckx_msg.deinit(allocator);
        try self.finished_hash.?.write(try ckx_msg.marshal(allocator));
        try self.finished_hash.?.debugLogClientHash(allocator, "server: ckx");

        const pre_master_secret = key_agreement.processClientKeyExchange(
            allocator,
            self.cert_chain.?,
            &ckx_msg,
            self.conn.version.?,
        ) catch |err| {
            self.conn.sendAlert(.handshake_failure) catch {};
            return err;
        };
        defer allocator.free(pre_master_secret);

        self.master_secret = try masterFromPreMasterSecret(
            allocator,
            self.conn.version.?,
            self.suite.?,
            pre_master_secret,
            self.client_hello.random,
            self.hello.?.random,
        );
        std.log.debug(
            "ServerHandshakeStateTls12 master_secret={}",
            .{fmtx.fmtSliceHexEscapeLower(self.master_secret.?)},
        );

        // If we received a client cert in response to our certificate request message,
        // the client will send us a certificateVerifyMsg immediately after the
        // clientKeyExchangeMsg. This message is a digest of all preceding
        // handshake-layer messages that is signed using the private key corresponding
        // to the client's certificate. This allows us to verify that the client is in
        // possession of the private key of the certificate.
        if (self.conn.peer_certificates.len > 0) {
            var cert_verify_msg = blk: {
                hs_msg = try self.conn.readHandshake(allocator);
                errdefer hs_msg.deinit(allocator);
                switch (hs_msg) {
                    .CertificateVerify => |m| break :blk m,
                    else => {
                        self.conn.sendAlert(.unexpected_message) catch {};
                        return error.UnexpectedMessage;
                    },
                }
            };
            defer cert_verify_msg.deinit(allocator);

            const sig_alg = cert_verify_msg.signature_algorithm;
            if (!isSupportedSignatureAlgorithm(
                sig_alg,
                cert_req_msg.?.supported_signature_algorithms,
            )) {
                self.conn.sendAlert(.illegal_parameter) catch {};
                return error.InvalidSignatureAlgorithmInClientCertificate;
            }

            const sig_type = SignatureType.fromSignatureScheme(sig_alg) catch {
                try self.conn.sendAlert(.internal_error);
            };
            const sig_hash = HashType.fromSignatureScheme(sig_alg) catch {
                try self.conn.sendAlert(.internal_error);
            };
            var signed = try self.finished_hash.?.hashForClientCertificate(
                allocator,
                sig_type,
                sig_hash,
            );
            defer allocator.free(signed);
            std.log.info(
                "ServerHandshakeStateTls12.doFullHandshake signed={}",
                .{std.fmt.fmtSliceHexLower(signed)},
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
                return error.InvalidSignatureByClientCertificate;
            };

            try self.finished_hash.?.write(try cert_verify_msg.marshal(allocator));
            try self.finished_hash.?.debugLogClientHash(allocator, "server: certVerify");
        }

        self.finished_hash.?.discardHandshakeBuffer();
    }

    pub fn establishKeys(self: *ServerHandshakeStateTls12, allocator: mem.Allocator) !void {
        const ver = self.conn.version.?;
        const suite = self.suite.?;
        var keys = try ConnectionKeys.fromMasterSecret(
            allocator,
            ver,
            suite,
            self.master_secret.?,
            self.client_hello.random,
            self.hello.?.random,
            suite.mac_len,
            suite.key_len,
            suite.iv_len,
        );
        defer keys.deinit(allocator);

        // TODO: implement if (suite.cipher) |cipher| {
        // } else {
        var client_cipher = suite.aead.?(keys.client_key, keys.client_iv);
        var server_cipher = suite.aead.?(keys.server_key, keys.server_iv);
        // }

        self.conn.in.prepareCipherSpec(ver, client_cipher);
        self.conn.out.prepareCipherSpec(ver, server_cipher);
    }

    fn readFinished(self: *ServerHandshakeStateTls12, allocator: mem.Allocator, out: []u8) !void {
        std.log.debug("ServerHandshakeStateTls12 readFinished start", .{});
        try self.conn.readChangeCipherSpec(allocator);
        std.log.debug("ServerHandshakeStateTls12 after readChangeCipherSpec", .{});

        var hs_msg = try self.conn.readHandshake(allocator);
        std.log.debug("ServerHandshakeStateTls12 after rreadHandshake", .{});
        var client_finished_msg = switch (hs_msg) {
            .Finished => |m| m,
            else => {
                self.conn.sendAlert(.unexpected_message) catch {};
                return error.UnexpectedMessage;
            },
        };
        defer client_finished_msg.deinit(allocator);

        std.log.debug("ServerHandshakeStateTls12 got client_finished", .{});
        const verify_data = try self.finished_hash.?.clientSum(
            allocator,
            self.master_secret.?,
        );

        if (constantTimeEqlBytes(&verify_data, client_finished_msg.verify_data) != 1) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.IncorrectClientFinishedMessage;
        }

        try self.finished_hash.?.write(try client_finished_msg.marshal(allocator));
        try self.finished_hash.?.debugLogClientHash(allocator, "server: clientFinished");
        mem.copy(u8, out, &verify_data);
    }

    fn sendFinished(self: *ServerHandshakeStateTls12, allocator: mem.Allocator, out: ?[]u8) !void {
        try self.conn.writeRecord(allocator, .change_cipher_spec, &[_]u8{1});

        const verify_data = try self.finished_hash.?.serverSum(
            allocator,
            self.master_secret.?,
        );
        var finished = FinishedMsg{
            .verify_data = &verify_data,
        };
        defer finished.deinit(allocator);

        const finished_bytes = try finished.marshal(allocator);
        try self.finished_hash.?.write(finished_bytes);
        try self.finished_hash.?.debugLogClientHash(allocator, "server: finished");
        try self.conn.writeRecord(allocator, .handshake, finished_bytes);
        std.log.debug(
            "ServerHandshakeStateTls12.sendFinished after writeRecord finished={}",
            .{fmtx.fmtSliceHexEscapeLower(finished_bytes)},
        );
        if (out) |o| {
            mem.copy(u8, o, finished.verify_data);
        }
        std.log.debug(
            "ServerHandshakeStateTls12 server_finished={}",
            .{fmtx.fmtSliceHexEscapeLower(finished.verify_data)},
        );
    }
};

// supportsECDHE returns whether ECDHE key exchanges can be used with this
// pre-TLS 1.3 client.
fn supportsEcdHe(
    c: *const Conn.Config,
    supported_curves: []const CurveId,
    supported_points: []const EcPointFormat,
) bool {
    std.log.debug("supportsEcdHe supported_curves={any}, supported_points={any}", .{
        supported_curves, supported_points,
    });
    const supports_curve = memx.containsScalarFn(
        CurveId,
        supported_curves,
        c,
        Conn.Config.supportsCurve,
    );

    const supports_point_format = memx.containsScalar(
        EcPointFormat,
        supported_points,
        .uncompressed,
    );

    return supports_curve and supports_point_format;
}

const alpn_h2 = "h2";
const alpn_http_1_1 = "http/1.1";

// negotiateAlpn picks a shared ALPN protocol that both sides support in server
// preference order. If ALPN is not configured or the peer doesn't support it,
// it returns "" and no error.
pub fn negotiateAlpn(server_protos: []const []const u8, client_protos: []const []const u8) ![]const u8 {
    if (server_protos.len == 0 or client_protos.len == 0) {
        return "";
    }
    var http11_fallback = false;
    for (server_protos) |s| {
        for (client_protos) |c| {
            if (mem.eql(u8, s, c)) {
                return s;
            }
            if (mem.eql(u8, s, alpn_h2) and mem.eql(u8, c, alpn_http_1_1)) {
                http11_fallback = true;
            }
        }
    }
    // As a special case, let http/1.1 clients connect to h2 servers as if they
    // didn't support ALPN. We used not to enforce protocol overlap, so over
    // time a number of HTTP servers were configured with only "h2", but
    // expected to accept connections from "http/1.1" clients. See Issue 46310.
    return if (http11_fallback)
        ""
    else
        error.UnsupportedAlpn;
}

const testing = std.testing;

test "supportsEcdHe" {
    const f = struct {
        fn f(
            want: bool,
            c: Conn.Config,
            supported_curves: []const CurveId,
            supported_points: []const EcPointFormat,
        ) !void {
            const got = supportsEcdHe(&c, supported_curves, supported_points);
            try testing.expectEqual(want, got);
        }
    }.f;

    try f(true, .{}, &.{.x25519}, &.{.uncompressed});
}

const testEd25519Certificate = "\x30\x82\x01\x2e\x30\x81\xe1\xa0\x03\x02\x01\x02\x02\x10\x0f\x43\x1c\x42\x57\x93\x94\x1d\xe9\x87\xe4\xf1\xad\x15\x00\x5d\x30\x05\x06\x03\x2b\x65\x70\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x1e\x17\x0d\x31\x39\x30\x35\x31\x36\x32\x31\x33\x38\x30\x31\x5a\x17\x0d\x32\x30\x30\x35\x31\x35\x32\x31\x33\x38\x30\x31\x5a\x30\x12\x31\x10\x30\x0e\x06\x03\x55\x04\x0a\x13\x07\x41\x63\x6d\x65\x20\x43\x6f\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00\x3f\xe2\x15\x2e\xe6\xe3\xef\x3f\x4e\x85\x4a\x75\x77\xa3\x64\x9e\xed\xe0\xbf\x84\x2c\xcc\x92\x26\x8f\xfa\x6f\x34\x83\xaa\xec\x8f\xa3\x4d\x30\x4b\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa0\x30\x13\x06\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30\x16\x06\x03\x55\x1d\x11\x04\x0f\x30\x0d\x82\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x30\x05\x06\x03\x2b\x65\x70\x03\x41\x00\x63\x44\xed\x9c\xc4\xbe\x53\x24\x53\x9f\xd2\x10\x8d\x9f\xe8\x21\x08\x90\x95\x39\xe5\x0d\xc1\x55\xff\x2c\x16\xb7\x1d\xfc\xab\x7d\x4d\xd4\xe0\x93\x13\xd0\xa9\x42\xe0\xb6\x6b\xfe\x5d\x67\x48\xd7\x9f\x50\xbc\x6c\xcd\x4b\x03\x83\x7c\xf2\x08\x58\xcd\xac\xcf\x0c";
const testEd25519PrivateKey = "\x3a\x88\x49\x65\xe7\x6b\x3f\x55\xe5\xfa\xf9\x61\x54\x58\xa9\x23\x54\x89\x42\x34\xde\x3e\xc9\xf6\x84\xd4\x6d\x55\xce\xbf\x3d\xc6\x3f\xe2\x15\x2e\xe6\xe3\xef\x3f\x4e\x85\x4a\x75\x77\xa3\x64\x9e\xed\xe0\xbf\x84\x2c\xcc\x92\x26\x8f\xfa\x6f\x34\x83\xaa\xec\x8f";

test "Ed25519.sign" {
    try testing.expectEqual(@as(usize, crypto.sign.Ed25519.secret_length), testEd25519PrivateKey.len);

    const key_pair = crypto.sign.Ed25519.KeyPair.fromSecretKey(testEd25519PrivateKey.*);
    const message = "\xf0\x8d\x1b\x90\x67\x3b\x23\x46\xac\xf7\x79\xf2\xf9\xe8\x90\x98\xb3\x52\xb2\x55\x2a\xfb\x0f\x1e\xdd\x4f\xb3\x75\x4b\x9b\x88\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x44\x4f\x57\x4e\x47\x52\x44\x01\x03\x00\x1d\x20\x2f\xe5\x7d\xa3\x47\xcd\x62\x43\x15\x28\xda\xac\x5f\xbb\x29\x07\x30\xff\xf6\x84\xaf\xc4\xcf\xc2\xed\x90\x99\x5f\x58\xcb\x3b\x74";
    const sig = try crypto.sign.Ed25519.sign(message, key_pair, null);
    const want = "\x1f\x56\x21\x8a\x44\x04\x69\x65\xee\xf8\x93\x52\x4c\xf0\x49\x42\x57\x4c\x5b\xf5\x1a\xef\x43\xad\x39\x93\x03\xa3\x64\x84\xda\xe5\x82\x32\xfc\x77\x12\x61\xf3\xf4\x2c\xd8\x61\x9e\x86\x01\x1f\xc0\xa0\x98\x94\xa3\x7f\x15\x75\xc8\xe6\x2f\x20\xbd\xaf\x7c\xbe\x0e";
    try testing.expectEqualSlices(u8, want, &sig);
}
