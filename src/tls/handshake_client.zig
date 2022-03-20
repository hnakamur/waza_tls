const std = @import("std");
const mem = std.mem;
const datetime = @import("datetime");
const HashType = @import("auth.zig").HashType;
const SignatureType = @import("auth.zig").SignatureType;
const selectSignatureScheme = @import("auth.zig").selectSignatureScheme;
const HandshakeMsg = @import("handshake_msg.zig").HandshakeMsg;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CertificateMsgTls12 = @import("handshake_msg.zig").CertificateMsgTls12;
const CertificateRequestMsgTls12 = @import("handshake_msg.zig").CertificateRequestMsgTls12;
const CertificateVerifyMsg = @import("handshake_msg.zig").CertificateVerifyMsg;
const ClientKeyExchangeMsg = @import("handshake_msg.zig").ClientKeyExchangeMsg;
const FinishedMsg = @import("handshake_msg.zig").FinishedMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const freeOptionalField = @import("handshake_msg.zig").freeOptionalField;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const SignatureScheme = @import("handshake_msg.zig").SignatureScheme;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuiteTls12 = @import("cipher_suites.zig").CipherSuiteTls12;
const cipherSuiteTls12ById = @import("cipher_suites.zig").cipherSuiteTls12ById;
const mutualCipherSuiteTls12 = @import("cipher_suites.zig").mutualCipherSuiteTls12;
const x509 = @import("x509.zig");
const prfForVersion = @import("prf.zig").prfForVersion;
const master_secret_length = @import("prf.zig").master_secret_length;
const master_secret_label = @import("prf.zig").master_secret_label;
const masterFromPreMasterSecret = @import("prf.zig").masterFromPreMasterSecret;
const ConnectionKeys = @import("prf.zig").ConnectionKeys;
const finished_verify_length = @import("prf.zig").finished_verify_length;
const constantTimeEqlBytes = @import("constant_time.zig").constantTimeEqlBytes;
const Conn = @import("conn.zig").Conn;
const ClientHandshakeStateTls13 = @import("handshake_client_tls13.zig").ClientHandshakeStateTls13;
const ClientSessionState = @import("session.zig").ClientSessionState;
const KeyLog = @import("conn.zig").KeyLog;
const crypto = @import("crypto.zig");
const fmtx = @import("../fmtx.zig");
const memx = @import("../memx.zig");

pub const ClientHandshakeState = union(ProtocolVersion) {
    v1_3: ClientHandshakeStateTls13,
    v1_2: ClientHandshakeStateTls12,
    v1_1: void,
    v1_0: void,

    pub fn deinit(self: *ClientHandshakeState, allocator: mem.Allocator) void {
        switch (self.*) {
            .v1_3 => |*hs| hs.deinit(allocator),
            .v1_2 => |*hs| hs.deinit(allocator),
            .v1_1, .v1_0 => @panic("unsupported version"),
        }
    }

    pub fn handshake(self: *ClientHandshakeState, allocator: mem.Allocator) !void {
        switch (self.*) {
            .v1_3 => |*hs| try hs.handshake(allocator),
            .v1_2 => |*hs| try hs.handshake(allocator),
            .v1_1, .v1_0 => @panic("unsupported version"),
        }
    }

    pub fn getSession(self: *const ClientHandshakeState) ?*ClientSessionState {
        return switch (self.*) {
            .v1_3 => |*hs| hs.session,
            .v1_2 => |*hs| hs.session,
            .v1_1, .v1_0 => @panic("unsupported version"),
        };
    }
};

pub const ClientHandshakeStateTls12 = struct {
    conn: *Conn,
    hello: ClientHelloMsg,
    server_hello: ServerHelloMsg,
    suite: ?*const CipherSuiteTls12 = null,
    finished_hash: ?FinishedHash = null,
    master_secret: ?[]const u8 = null,
    owns_session: bool = false,
    session: ?*ClientSessionState = null,

    pub fn deinit(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) void {
        self.hello.deinit(allocator);
        self.server_hello.deinit(allocator);
        if (self.finished_hash) |*fh| fh.deinit();
        if (self.master_secret) |s| allocator.free(s);
        if (self.owns_session) {
            self.session.?.deinit(allocator);
            allocator.destroy(self.session.?);
        }
    }

    pub fn handshake(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) !void {
        std.log.info("ClientHandshakeStateTls12.handshake start", .{});
        const is_resume = try self.processServerHello(allocator);
        std.log.info("ClientHandshakeStateTls12.handshake is_resume={}", .{is_resume});

        self.finished_hash = FinishedHash.new(allocator, self.conn.version.?, self.suite.?);

        // No signatures of the handshake are needed in a resumption.
        // Otherwise, in a full handshake, if we don't have any certificates
        // configured then we will never send a CertificateVerify message and
        // thus no signatures are needed in that case either.
        if (is_resume or self.conn.config.certificates.len == 0) {
            self.finished_hash.?.discardHandshakeBuffer();
        }

        try self.finished_hash.?.write(try self.hello.marshal(allocator));
        std.log.debug("client: clientHello {}", .{std.fmt.fmtSliceHexLower(self.hello.raw.?)});
        try self.finished_hash.?.debugLogClientHash(allocator, "client: clientHello");
        try self.finished_hash.?.write(try self.server_hello.marshal(allocator));
        std.log.debug("client: serverHello {}", .{std.fmt.fmtSliceHexLower(self.server_hello.raw.?)});
        try self.finished_hash.?.debugLogClientHash(allocator, "client: serverHello");

        self.conn.buffering = true;
        self.conn.did_resume = is_resume;
        if (is_resume) {
            std.log.info("ClientHandshakeStateTls12 is_resume=true, before establishKeys", .{});
            try self.establishKeys(allocator);
            std.log.info("ClientHandshakeStateTls12 before readSessionTicket", .{});
            try self.readSessionTicket(allocator);
            std.log.info("ClientHandshakeStateTls12 before readFinished", .{});
            try self.readFinished(allocator, &self.conn.server_finished);
            self.conn.client_finished_is_first = false;

            // Make sure the connection is still being verified whether or not this
            // is a resumption. Resumptions currently don't reverify certificates so
            // they don't call verifyServerCertificate. See Issue 31641.
            // TODO: implement using self.conn.config.verifyConnection

            std.log.info("ClientHandshakeStateTls12 before sendFinished", .{});
            try self.sendFinished(allocator, &self.conn.client_finished);
            std.log.info(
                "ClientHandshakeStateTls12 client_finished={}",
                .{fmtx.fmtSliceHexEscapeLower(&self.conn.client_finished)},
            );
            try self.conn.flush();
        } else {
            std.log.info("ClientHandshakeStateTls12 before doFullHandshake", .{});
            try self.doFullHandshake(allocator);
            std.log.info("ClientHandshakeStateTls12 before establishKeys", .{});
            try self.establishKeys(allocator);
            std.log.info("ClientHandshakeStateTls12 before sendFinished", .{});
            try self.sendFinished(allocator, &self.conn.client_finished);
            std.log.info(
                "ClientHandshakeStateTls12 client_finished={}",
                .{fmtx.fmtSliceHexEscapeLower(&self.conn.client_finished)},
            );
            try self.conn.flush();
            self.conn.client_finished_is_first = true;
            std.log.info("ClientHandshakeStateTls12 before readSessionTicket", .{});
            try self.readSessionTicket(allocator);
            std.log.info("ClientHandshakeStateTls12 before readFinished", .{});
            try self.readFinished(allocator, &self.conn.server_finished);
            std.log.info(
                "ClientHandshakeStateTls12 server_finished={}",
                .{fmtx.fmtSliceHexEscapeLower(&self.conn.server_finished)},
            );
        }

        self.conn.handshake_complete = true;
    }

    pub fn doFullHandshake(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) !void {
        var cert_msg = blk_cert_msg: {
            var hs_msg = try self.conn.readHandshake(allocator);
            errdefer hs_msg.deinit(allocator);
            switch (hs_msg) {
                .certificate => |*c| {
                    switch (c.*) {
                        .v1_2 => |cert_msg_tls12| {
                            if (cert_msg_tls12.certificates.len != 0) {
                                break :blk_cert_msg cert_msg_tls12;
                            }
                        },
                        else => {},
                    }
                },
                else => {},
            }
            self.conn.sendAlert(.unexpected_message) catch {};
            return error.UnexpectedMessage;
        };
        defer cert_msg.deinit(allocator);

        try self.finished_hash.?.write(try cert_msg.marshal(allocator));
        std.log.info("client: cert {}", .{std.fmt.fmtSliceHexLower(cert_msg.raw.?)});
        try self.finished_hash.?.debugLogClientHash(allocator, "client: cert");

        var hs_msg = try self.conn.readHandshake(allocator);
        switch (hs_msg) {
            .certificate_status => |*cs| {
                // RFC4366 on Certificate Status Request:
                // The server MAY return a "certificate_status" message.
                if (!self.server_hello.ocsp_stapling) {
                    // If a server returns a "CertificateStatus" message, then the
                    // server MUST have included an extension of type "status_request"
                    // with empty "extension_data" in the extended server hello.
                    self.conn.sendAlert(.unexpected_message) catch {};
                    return error.UnexpectedCertificateStatusMessage;
                }

                try self.finished_hash.?.write(try cs.marshal(allocator));

                allocator.free(self.conn.ocsp_response);
                self.conn.ocsp_response = cs.response;
                cs.response = "";

                hs_msg = try self.conn.readHandshake(allocator);
            },
            else => {},
        }

        if (self.conn.handshakes == 0) {
            // If this is the first handshake on a connection, process and
            // (optionally) verify the server's certificates.
            {
                for (cert_msg.certificates) |cert, i| {
                    std.log.info("client: cert_msg cert[{}]=0x{x}", .{ i, @ptrToInt(cert.ptr) });
                }
            }
            try self.conn.verifyServerCertificate(cert_msg.certificates);
        } else {
            // This is a renegotiation handshake. We require that the
            // server's identity (i.e. leaf certificate) is unchanged and
            // thus any previous trust decision is still valid.
            //
            // See https://mitls.org/pages/attacks/3SHAKE for the
            // motivation behind this requirement.
            if (!mem.eql(u8, self.conn.peer_certificates[0].raw, cert_msg.certificates[0])) {
                self.conn.sendAlert(.unexpected_message) catch {};
                return error.TlsServerIdentityChangedDuringRenegotiaion;
            }
        }
        var key_agreement = self.suite.?.ka(self.conn.version.?);
        defer key_agreement.deinit(allocator);

        switch (hs_msg) {
            .server_key_exchange => |*skx_msg| {
                {
                    defer skx_msg.deinit(allocator);
                    try self.finished_hash.?.write(try skx_msg.marshal(allocator));
                    std.log.info("client: skx {}", .{std.fmt.fmtSliceHexLower(skx_msg.raw.?)});
                    try self.finished_hash.?.debugLogClientHash(allocator, "client: skx");
                    key_agreement.processServerKeyExchange(
                        allocator,
                        &self.hello,
                        &self.server_hello,
                        &self.conn.peer_certificates[0],
                        skx_msg,
                    ) catch |err| {
                        self.conn.sendAlert(.unexpected_message) catch {};
                        return err;
                    };
                }
                hs_msg = try self.conn.readHandshake(allocator);
            },
            else => {},
        }

        var cert_requested = false;
        var cert_req_msg: CertificateRequestMsgTls12 = undefined;
        var chain_to_send: *const CertificateChain = undefined;
        switch (hs_msg) {
            .certificate_request => |*m| {
                std.log.info("client: CertificateRequest={}", .{m.*});
                switch (m.*) {
                    .v1_2 => |m2| {
                        cert_requested = true;
                        cert_req_msg = m2;
                        std.log.info(
                            "client: certReq {}",
                            .{std.fmt.fmtSliceHexLower(cert_req_msg.raw.?)},
                        );
                        std.log.info("client: cert_req_msg={}", .{cert_req_msg});

                        try self.finished_hash.?.write(try cert_req_msg.marshal(allocator));
                        try self.finished_hash.?.debugLogClientHash(allocator, "client: certReq");

                        const sig_schemes = blk: {
                            var rsa_avail = false;
                            var ec_avail = false;
                            for (cert_req_msg.certificate_types) |cert_type| {
                                switch (cert_type) {
                                    .rsa_sign => rsa_avail = true,
                                    .ecdsa_sign => ec_avail = true,
                                }
                            }

                            var schemes = try std.ArrayList(SignatureScheme).initCapacity(
                                allocator,
                                cert_req_msg.supported_signature_algorithms.len,
                            );
                            errdefer schemes.deinit();
                            for (cert_req_msg.supported_signature_algorithms) |sig_alg| {
                                const sig_type = SignatureType.fromSignatureScheme(
                                    sig_alg,
                                ) catch continue;
                                switch (sig_type) {
                                    .ecdsa, .ed25519 => if (ec_avail) {
                                        try schemes.append(sig_alg);
                                    },
                                    .rsa_pss, .pkcs1v15 => if (rsa_avail) {
                                        try schemes.append(sig_alg);
                                    },
                                    else => {},
                                }
                            }
                            break :blk schemes.toOwnedSlice();
                        };
                        defer allocator.free(sig_schemes);

                        // Filter the signature schemes based on the certificate types.
                        // See RFC 5246, Section 7.4.4 (where it calls this
                        // "somewhat complicated").
                        chain_to_send = self.conn.getClientCertificate(
                            allocator,
                            cert_req_msg.certificate_authorities,
                            sig_schemes,
                            self.conn.version.?,
                        ) orelse &CertificateChain{};

                        hs_msg = try self.conn.readHandshake(allocator);
                    },
                    else => {
                        hs_msg.deinit(allocator);
                        self.conn.sendAlert(.unexpected_message) catch {};
                        return error.UnexpectedMessage;
                    },
                }
            },
            else => {},
        }
        defer if (cert_requested) cert_req_msg.deinit(allocator);

        switch (hs_msg) {
            .server_hello_done => |*hello_done_msg| {
                defer hello_done_msg.deinit(allocator);
                try self.finished_hash.?.write(try hello_done_msg.marshal(allocator));
                std.log.info("client: helloDone {}", .{std.fmt.fmtSliceHexLower(hello_done_msg.raw.?)});
                try self.finished_hash.?.debugLogClientHash(allocator, "client: helloDone");
            },
            else => {
                hs_msg.deinit(allocator);
                self.conn.sendAlert(.unexpected_message) catch {};
                return error.UnexpectedMessage;
            },
        }

        // If the server requested a certificate then we have to send a
        // Certificate message, even if it's empty because we don't have a
        // certificate to send.
        if (cert_requested) {
            var client_cert_msg = CertificateMsgTls12{
                .certificates = try memx.dupeStringList(allocator, chain_to_send.certificate_chain),
            };
            defer client_cert_msg.deinit(allocator);

            const client_cert_msg_bytes = try client_cert_msg.marshal(allocator);
            try self.finished_hash.?.write(client_cert_msg_bytes);
            std.log.info("client: cert {}", .{std.fmt.fmtSliceHexLower(client_cert_msg_bytes)});
            try self.finished_hash.?.debugLogClientHash(allocator, "client: cert");
            try self.conn.writeRecord(allocator, .handshake, client_cert_msg_bytes);
        }

        var pre_master_secret: []const u8 = undefined;
        var ckx_msg: ClientKeyExchangeMsg = undefined;
        key_agreement.generateClientKeyExchange(
            allocator,
            &self.hello,
            &self.conn.peer_certificates[0],
            &pre_master_secret,
            &ckx_msg,
        ) catch |err| {
            self.conn.sendAlert(.internal_error) catch {};
            return err;
        };
        defer ckx_msg.deinit(allocator);
        defer allocator.free(pre_master_secret);
        std.log.debug("ClientHandshakeStateTls12.doFullHandshake, pre_master_secret={}", .{
            std.fmt.fmtSliceHexLower(pre_master_secret),
        });
        // TODO: implement for case when cks_msg is not generated.
        const ckx_msg_bytes = try ckx_msg.marshal(allocator);
        std.log.debug("client: ckx {}", .{std.fmt.fmtSliceHexLower(ckx_msg_bytes)});
        try self.finished_hash.?.write(ckx_msg_bytes);
        try self.finished_hash.?.debugLogClientHash(allocator, "client: ckx");
        try self.conn.writeRecord(allocator, .handshake, ckx_msg_bytes);

        if (cert_requested and chain_to_send.certificate_chain.len > 0) {
            var cert_verify_msg = blk: {
                const sig_alg = selectSignatureScheme(
                    allocator,
                    self.conn.version.?,
                    chain_to_send,
                    cert_req_msg.supported_signature_algorithms,
                ) catch |err| {
                    self.conn.sendAlert(.handshake_failure) catch {};
                    return err;
                };

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
                    "ClientHandshakeStateTls12.doFullHandshake signed={}",
                    .{std.fmt.fmtSliceHexLower(signed)},
                );

                const sign_opts = if (sig_type == .rsa_pss)
                    crypto.SignOpts{ .hash_type = sig_hash, .salt_length = .equals_hash }
                else
                    crypto.SignOpts{ .hash_type = sig_hash };
                std.log.info(
                    "ClientHandshakeStateTls12.doFullHandshake cert={}",
                    .{std.fmt.fmtSliceHexLower(chain_to_send.certificate_chain[0])},
                );
                var sig = chain_to_send.private_key.?.sign(
                    allocator,
                    signed,
                    sign_opts,
                ) catch {
                    self.conn.sendAlert(.internal_error) catch {};
                    return error.SignHandshakeFailed;
                };
                std.log.info(
                    "ClientHandshakeStateTls12.doFullHandshake sig={}",
                    .{std.fmt.fmtSliceHexLower(sig)},
                );

                break :blk CertificateVerifyMsg{
                    .signature_algorithm = sig_alg,
                    .signature = sig,
                };
            };
            defer cert_verify_msg.deinit(allocator);

            const cert_verify_msg_bytes = try cert_verify_msg.marshal(allocator);
            try self.finished_hash.?.write(cert_verify_msg_bytes);
            try self.finished_hash.?.debugLogClientHash(allocator, "client: certVerify");
            try self.conn.writeRecord(allocator, .handshake, cert_verify_msg_bytes);
            std.log.info(
                "ClientHandshakeStateTls12.doFullHandshake sent cert_verify_msg={}",
                .{std.fmt.fmtSliceHexLower(cert_verify_msg_bytes)},
            );
        }

        self.master_secret = try masterFromPreMasterSecret(
            allocator,
            self.conn.version.?,
            self.suite.?,
            pre_master_secret,
            self.hello.random,
            self.server_hello.random,
        );
        std.log.debug(
            "ClientHandshakeStateTls12 master_secret={}",
            .{std.fmt.fmtSliceHexLower(self.master_secret.?)},
        );

        try self.conn.config.writeKeyLog(
            allocator,
            KeyLog.label_tls12,
            self.hello.random,
            self.master_secret.?,
        );

        self.finished_hash.?.discardHandshakeBuffer();
    }

    pub fn establishKeys(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) !void {
        const ver = self.conn.version.?;
        const suite = self.suite.?;
        var keys = try ConnectionKeys.fromMasterSecret(
            allocator,
            ver,
            suite,
            self.master_secret.?,
            self.hello.random,
            self.server_hello.random,
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

        self.conn.in.prepareCipherSpec(ver, server_cipher);
        self.conn.out.prepareCipherSpec(ver, client_cipher);
    }

    pub fn readSessionTicket(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) !void {
        std.log.info("ClientHandshakeStateTls12.readSessionTicket start", .{});
        if (!self.server_hello.ticket_supported) {
            std.log.info("ClientHandshakeStateTls12.readSessionTicket early exit#1", .{});
            return;
        }

        var session_ticket_msg = blk: {
            var hs_msg = try self.conn.readHandshake(allocator);
            switch (hs_msg) {
                .new_session_ticket => |*msg| {
                    switch (msg.*) {
                        .v1_2 => |msg_tls12| break :blk msg_tls12,
                        else => {
                            self.conn.sendAlert(.unexpected_message) catch {};
                            return error.UnexpectedMessage;
                        },
                    }
                },
                else => {
                    self.conn.sendAlert(.unexpected_message) catch {};
                    return error.UnexpectedMessage;
                },
            }
        };
        defer session_ticket_msg.deinit(allocator);

        try self.finished_hash.?.write(try session_ticket_msg.marshal(allocator));
        std.log.info(
            "client: sessionTicket={}",
            .{std.fmt.fmtSliceHexLower(session_ticket_msg.raw.?)},
        );

        {
            const session_ticket = session_ticket_msg.ticket;
            session_ticket_msg.ticket = "";

            const master_secret = try allocator.dupe(u8, self.master_secret.?);
            errdefer allocator.free(master_secret);

            var server_certificates = try x509.Certificate.cloneSlice(
                self.conn.peer_certificates,
                allocator,
            );
            errdefer memx.deinitSliceAndElems(x509.Certificate, server_certificates, allocator);

            var verified_chains = try x509.Certificate.cloneChains(
                self.conn.verified_chains,
                allocator,
            );
            errdefer x509.Certificate.deinitChains(verified_chains, allocator);

            const ocsp_response = try allocator.dupe(u8, self.conn.ocsp_response);
            errdefer allocator.free(ocsp_response);

            const scts = try memx.dupeStringList(allocator, self.conn.scts);
            errdefer memx.freeElemsAndFreeSlice([]const u8, scts, allocator);

            const now = datetime.datetime.Datetime.now();

            var session = ClientSessionState{
                .session_ticket = session_ticket,
                .ver = self.conn.version.?,
                .cipher_suite = self.suite.?.id,
                .master_secret = master_secret,
                .server_certificates = server_certificates,
                .verified_chains = verified_chains,
                .received_at = now,
                .ocsp_response = ocsp_response,
                .scts = scts,
            };
            errdefer session.deinit(allocator);

            if (self.owns_session) {
                self.session.?.deinit(allocator);
            } else {
                self.session = try allocator.create(ClientSessionState);
                self.owns_session = true;
            }
            self.session.?.* = session;
        }
        std.log.info("ClientHandshakeStateTls12.readSessionTicket set session", .{});
    }

    fn sendFinished(self: *ClientHandshakeStateTls12, allocator: mem.Allocator, out: []u8) !void {
        try self.conn.writeRecord(allocator, .change_cipher_spec, &[_]u8{1});
        std.log.debug("ClientHandshakeStateTls12.sendFinished after writeRecord change_cipher_spec", .{});

        const verify_data = try self.finished_hash.?.clientSum(
            allocator,
            self.master_secret.?,
        );
        var finished = FinishedMsg{
            .verify_data = &verify_data,
        };
        defer {
            finished.verify_data = "";
            finished.deinit(allocator);
        }

        const finished_bytes = try finished.marshal(allocator);
        try self.finished_hash.?.write(finished_bytes);
        std.log.debug("client: clientFinished={}", .{std.fmt.fmtSliceHexLower(finished_bytes)});
        try self.finished_hash.?.debugLogClientHash(allocator, "client: clientFinished");
        try self.conn.writeRecord(allocator, .handshake, finished_bytes);
        std.log.debug("ClientHandshakeStateTls12.sendFinished after writeRecord finished", .{});
        mem.copy(u8, out, finished.verify_data);
    }

    fn readFinished(self: *ClientHandshakeStateTls12, allocator: mem.Allocator, out: []u8) !void {
        std.log.debug("ClientHandshakeStateTls12.readFinished start", .{});
        try self.conn.readChangeCipherSpec(allocator);
        std.log.debug("ClientHandshakeStateTls12.readFinished after readChangeCipherSpec", .{});

        var hs_msg = try self.conn.readHandshake(allocator);
        std.log.debug("ClientHandshakeStateTls12.readFinished after readHandshake", .{});
        var server_finished_msg = switch (hs_msg) {
            .finished => |m| m,
            else => {
                self.conn.sendAlert(.unexpected_message) catch {};
                return error.UnexpectedMessage;
            },
        };
        defer server_finished_msg.deinit(allocator);
        std.log.debug(
            "ClientHandshakeStateTls12.readFinished server_finished_bytes={}",
            .{fmtx.fmtSliceHexEscapeLower(server_finished_msg.raw.?)},
        );

        const verify_data = try self.finished_hash.?.serverSum(
            allocator,
            self.master_secret.?,
        );

        if (constantTimeEqlBytes(&verify_data, server_finished_msg.verify_data) != 1) {
            std.log.debug("ClientHandshakeStateTls12.readFinished verified data mismach,\n  ours={}\ntheirs={}", .{
                fmtx.fmtSliceHexColonLower(&verify_data),
                fmtx.fmtSliceHexColonLower(server_finished_msg.verify_data),
            });
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.IncorrectServerFinishedMessage;
        }

        try self.finished_hash.?.write(try server_finished_msg.marshal(allocator));
        try self.finished_hash.?.debugLogClientHash(allocator, "client: server_finished");
        mem.copy(u8, out, &verify_data);
    }

    fn processServerHello(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) !bool {
        std.log.info("ClientHandshakeStateTls12.processServerHello start", .{});
        try self.pickCipherSuite();

        if (self.server_hello.compression_method != .none) {
            self.conn.sendAlert(.unexpected_message) catch {};
            return error.ServerSelectedUnsupportedCompressionFormat;
        }

        if (self.conn.handshakes == 0 and self.server_hello.secure_renegotiation_supported) {
            self.conn.secure_renegotiation = true;
            if (self.server_hello.secure_renegotiation.len != 0) {
                self.conn.sendAlert(.handshake_failure) catch {};
                return error.TlsInitialHandshakeHadNonEmptyRenegotiationExtension;
            }
        }

        if (self.conn.handshakes > 0 and self.conn.secure_renegotiation) {
            if (!mem.eql(
                u8,
                self.server_hello.secure_renegotiation[0..finished_verify_length],
                &self.conn.client_finished,
            ) or
                !mem.eql(
                u8,
                self.server_hello.secure_renegotiation[finished_verify_length..],
                &self.conn.server_finished,
            )) {
                self.conn.sendAlert(.handshake_failure) catch {};
                return error.TlsIncorrectRenegotiationExtensionContents;
            }
        }

        checkAlpn(self.hello.alpn_protocols, self.server_hello.alpn_protocol) catch |err| {
            self.conn.sendAlert(.unsupported_extension) catch {};
            return err;
        };
        allocator.free(self.conn.client_protocol);
        self.conn.client_protocol = try allocator.dupe(u8, self.server_hello.alpn_protocol);

        memx.freeElemsAndFreeSlice([]const u8, self.conn.scts, allocator);
        self.conn.scts = try memx.dupeStringList(allocator, self.server_hello.scts);

        if (!self.serverResumedSession()) {
            std.log.info("ClientHandshakeStateTls12.processServerHello returns false since serverResumedSession was false", .{});
            return false;
        }

        if (self.session.?.ver != self.conn.version.?) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.TlsServerResumedSessionWithDifferentVersion;
        }

        if (self.session.?.cipher_suite != self.suite.?.id) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.TlsServerResumedSessionWithDifferentCipherSuite;
        }

        // Restore masterSecret, peerCerts, and ocspResponse from previous state
        if (self.master_secret) |secret| allocator.free(secret);
        self.master_secret = try allocator.dupe(u8, self.session.?.master_secret);

        memx.deinitSliceAndElems(x509.Certificate, self.conn.peer_certificates, allocator);
        self.conn.peer_certificates = try x509.Certificate.cloneSlice(
            self.session.?.server_certificates,
            allocator,
        );

        x509.Certificate.deinitChains(self.conn.verified_chains, allocator);
        self.conn.verified_chains = try x509.Certificate.cloneChains(
            self.session.?.verified_chains,
            allocator,
        );

        allocator.free(self.conn.ocsp_response);
        self.conn.ocsp_response = try allocator.dupe(u8, self.session.?.ocsp_response);

        // Let the ServerHello SCTs override the session SCTs from the original
        // connection, if any are provided
        if (self.conn.scts.len == 0 and self.session.?.scts.len != 0) {
            self.conn.scts = try memx.dupeStringList(allocator, self.session.?.scts);
        }

        return true;
    }

    fn serverResumedSession(self: *const ClientHandshakeStateTls12) bool {
        // If the server responded with the same sessionId then it means the
        // sessionTicket is being used to resume a TLS session.
        std.log.info("ClientHandshakeStateTls12.serverResumedSession, self.session={}, self.hello.session_id={}", .{
            self.session,
            std.fmt.fmtSliceHexLower(self.hello.session_id),
        });
        return self.session != null and self.hello.session_id.len != 0 and
            mem.eql(u8, self.server_hello.session_id, self.hello.session_id);
    }

    fn pickCipherSuite(self: *ClientHandshakeStateTls12) !void {
        if (mutualCipherSuiteTls12(
            self.hello.cipher_suites,
            self.server_hello.cipher_suite.?,
        )) |suite| {
            self.suite = suite;
            std.log.debug("ClientHandshakeStateTls12.pickCipherSuite, suite={}", .{suite});
            self.conn.cipher_suite_id = suite.id;
        } else {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.ServerChoseAnUnconfiguredCipherSuite;
        }
    }
};

// checkAlpn ensure that the server's choice of ALPN protocol is compatible with
// the protocols that we advertised in the Client Hello.
pub fn checkAlpn(client_protos: []const []const u8, server_proto: []const u8) !void {
    if (server_proto.len == 0) {
        return;
    }
    if (client_protos.len == 0) {
        return error.ServerAdvertisedUnrequestedAlpnExtension;
    }
    for (client_protos) |proto| {
        if (mem.eql(u8, proto, server_proto)) {
            return;
        }
    }
    return error.ServerSelectedUnadvertisedAlpnProtocol;
}

test "sha256" {
    const Sha256 = std.crypto.hash.sha2.Sha256;

    const TestCase = struct {
        label: []const u8,
        input: []const u8,
        want: []const u8,
    };
    const test_cases = [_]TestCase{
        .{
            .label = "clientHello",
            .input = "\x01\x00\x00\x71\x03\x03\x64\xe7\xe0\xe6\x3f\x9c\x2d\xa3\xae\xca\x81\x30\x97\x62\xf8\xeb\x7c\xaf\x23\xcd\x5f\x7d\x29\x67\x7f\xb2\x49\x24\xeb\x1f\xe9\x4f\x20\xc4\x26\xd0\x88\xa4\x90\x3a\x18\x52\xae\x28\xd3\x20\xb3\xac\xe1\x83\x10\x62\x55\x50\xf5\x39\x1d\x62\x39\xb5\xce\xf6\x0f\xbf\x21\x00\x02\xc0\x2b\x01\x00\x00\x26\x00\x00\x00\x0e\x00\x0c\x00\x00\x09\x6e\x61\x72\x75\x68\x2e\x64\x65\x76\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00",
            .want = "\x65\x4b\x9c\x3e\xdb\xed\xda\x37\x0c\x9d\x5e\xd0\x31\xcf\x82\xf9\x66\x8a\x21\x9d\x5e\x0e\xd7\xc1\x23\xe1\xc0\xcd\x3d\x50\xf1\xa5",
        },
        .{
            .label = "serverHello",
            .input = "\x02\x00\x00\x2e\x03\x03\xa4\x35\x86\x91\xd9\x29\xb9\x95\x9e\xb8\x90\x75\x51\xdd\x76\xcc\x73\x7f\x60\x94\x6b\x82\x12\x35\x44\x4f\x57\x4e\x47\x52\x44\x01\x00\xc0\x2b\x00\x00\x06\x00\x0b\x00\x02\x01\x00",
            .want = "\xc4\x74\x60\x8c\x86\x75\x39\xe5\x95\x6b\xad\xa4\xc2\x97\xf1\x3e\x53\x21\x06\x52\x29\x21\x06\xbf\x0c\x2d\xd2\x13\xb1\x52\xbd\x02",
        },
        .{
            .label = "cert",
            .input = "\x0b\x00\x0e\xea\x00\x0e\xe7\x00\x04\x60\x30\x82\x04\x5c\x30\x82\x03\x44\xa0\x03\x02\x01\x02\x02\x12\x03\x4d\xd1\x33\x2d\x2a\x42\xf3\x27\x01\xcc\x5e\x2e\x2c\x3c\x71\x0f\x14\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x30\x32\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x16\x30\x14\x06\x03\x55\x04\x0a\x13\x0d\x4c\x65\x74\x27\x73\x20\x45\x6e\x63\x72\x79\x70\x74\x31\x0b\x30\x09\x06\x03\x55\x04\x03\x13\x02\x52\x33\x30\x1e\x17\x0d\x32\x32\x30\x32\x30\x35\x30\x38\x31\x31\x33\x31\x5a\x17\x0d\x32\x32\x30\x35\x30\x36\x30\x38\x31\x31\x33\x30\x5a\x30\x14\x31\x12\x30\x10\x06\x03\x55\x04\x03\x13\x09\x6e\x61\x72\x75\x68\x2e\x64\x65\x76\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x5b\x39\x17\xb1\x5d\xe8\x79\xc1\x8e\xde\x3a\xa4\x52\x41\xe5\x5d\xff\xc1\x8e\x7f\xbb\x14\x27\x8d\xca\xf0\x4e\x2a\x66\x3a\xd8\x6b\x9a\x50\xf4\x10\xd8\x32\xec\xb4\x61\x1f\xa4\x5e\x67\x95\x73\xbf\xa5\x09\x18\x71\x30\x68\x4a\xb6\x98\x36\x80\x35\x26\xe8\x74\xac\xa3\x82\x02\x53\x30\x82\x02\x4f\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x07\x80\x30\x1d\x06\x03\x55\x1d\x25\x04\x16\x30\x14\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02\x30\x0c\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x02\x30\x00\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\xbd\x34\x39\xb1\x5b\x09\xe3\x85\xe3\xe3\x43\x83\xf0\xb3\x51\x7a\xe5\xde\xa3\xa9\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\x14\x2e\xb3\x17\xb7\x58\x56\xcb\xae\x50\x09\x40\xe6\x1f\xaf\x9d\x8b\x14\xc2\xc6\x30\x55\x06\x08\x2b\x06\x01\x05\x05\x07\x01\x01\x04\x49\x30\x47\x30\x21\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x01\x86\x15\x68\x74\x74\x70\x3a\x2f\x2f\x72\x33\x2e\x6f\x2e\x6c\x65\x6e\x63\x72\x2e\x6f\x72\x67\x30\x22\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x02\x86\x16\x68\x74\x74\x70\x3a\x2f\x2f\x72\x33\x2e\x69\x2e\x6c\x65\x6e\x63\x72\x2e\x6f\x72\x67\x2f\x30\x23\x06\x03\x55\x1d\x11\x04\x1c\x30\x1a\x82\x09\x6e\x61\x72\x75\x68\x2e\x64\x65\x76\x82\x0d\x77\x77\x77\x2e\x6e\x61\x72\x75\x68\x2e\x64\x65\x76\x30\x4c\x06\x03\x55\x1d\x20\x04\x45\x30\x43\x30\x08\x06\x06\x67\x81\x0c\x01\x02\x01\x30\x37\x06\x0b\x2b\x06\x01\x04\x01\x82\xdf\x13\x01\x01\x01\x30\x28\x30\x26\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x01\x16\x1a\x68\x74\x74\x70\x3a\x2f\x2f\x63\x70\x73\x2e\x6c\x65\x74\x73\x65\x6e\x63\x72\x79\x70\x74\x2e\x6f\x72\x67\x30\x82\x01\x04\x06\x0a\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02\x04\x81\xf5\x04\x81\xf2\x00\xf0\x00\x75\x00\x6f\x53\x76\xac\x31\xf0\x31\x19\xd8\x99\x00\xa4\x51\x15\xff\x77\x15\x1c\x11\xd9\x02\xc1\x00\x29\x06\x8d\xb2\x08\x9a\x37\xd9\x13\x00\x00\x01\x7e\xc9\x27\x1e\xbb\x00\x00\x04\x03\x00\x46\x30\x44\x02\x20\x27\xf3\x72\x2c\x3c\x6f\xd7\xf4\x7b\x81\x48\xce\xf7\x14\xa7\xf0\x3a\xd0\x96\xe7\x0a\x13\x2a\x47\xdf\xa1\x3d\x83\x72\x26\xea\xc3\x02\x20\x02\xdb\x0a\xef\x92\xea\x7c\xa6\x28\x24\xd9\xb1\x07\x8e\x0f\x45\xf4\x93\x20\x53\xd5\xd6\x28\x5e\xba\x99\x21\xd2\x64\x59\x2f\x5b\x00\x77\x00\x46\xa5\x55\xeb\x75\xfa\x91\x20\x30\xb5\xa2\x89\x69\xf4\xf3\x7d\x11\x2c\x41\x74\xbe\xfd\x49\xb8\x85\xab\xf2\xfc\x70\xfe\x6d\x47\x00\x00\x01\x7e\xc9\x27\x1e\xbb\x00\x00\x04\x03\x00\x48\x30\x46\x02\x21\x00\x99\x80\x2c\x91\x5e\x0e\xbc\xb2\x34\x90\xbe\xb9\x3b\x1a\x10\x5e\xf6\x9c\xb2\x98\xf3\xa0\x70\xa2\xf5\x5a\xda\x8e\xe9\x7d\xb4\x7f\x02\x21\x00\xc9\xed\x90\xf2\x15\x37\xa6\x9b\x76\x32\x5e\x7b\x42\xa4\x50\xc7\x57\x35\x5b\xf0\x48\x3f\x77\x08\x6b\xef\x72\x99\x90\xac\x5e\x46\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x85\x83\x87\x97\x43\x18\xcd\x56\x35\x1f\xf6\x63\x72\xb1\xd0\xdb\x21\x43\xe3\x03\x04\x5a\x63\xc9\xcf\x57\x22\xcc\x38\x03\x6c\x4f\xc5\x0f\x6b\x90\x1d\xf6\xb3\x1b\x31\xfe\x5e\x9c\xf5\x67\xd8\x31\xe1\x95\x8e\x1d\xdc\x03\x43\x19\x96\xc8\xa4\xa1\x05\x8f\xa9\x7d\xb3\xa9\xd7\xbf\xd8\x32\xf0\x32\x66\x1a\x12\x48\xd4\x1e\x12\xdb\xe9\x86\x4c\xad\x24\x78\xdd\xe9\x0b\xd0\x28\x43\xcf\x85\xdb\xcb\x09\x9b\xdf\xf5\x3d\xdd\x06\xc6\x48\x0e\x28\x25\x9b\x5a\x71\xb8\x76\x35\x9d\x37\xdb\xd2\xee\x72\x14\xb6\x71\x57\x05\x80\x86\x72\xa2\xae\xb7\xeb\x2a\x22\x87\x58\xe8\xee\x32\x62\x41\x3b\x8b\x36\x50\xc3\x6b\x99\x8b\xa9\xce\x64\x32\x24\xd8\x3c\x37\x0b\xc2\x23\x20\xb8\x5f\x94\x3f\xf6\xe7\x4f\x7d\x79\x8d\x9e\x8c\xec\x0f\x3d\xb3\xde\xce\x3b\xa7\xdc\xfe\x06\x21\x7f\x42\x6e\x6c\x74\xc2\x88\x84\x1f\xe6\xa8\x65\x51\xd0\x63\xa5\xfe\xdc\x8e\x89\x64\xce\x06\x88\x64\xd8\x3d\x93\x34\x9f\x3b\x3b\x1e\xd8\xd3\xa9\x40\xa9\x8e\x81\xbd\x0c\xe6\xbc\x19\x78\x38\xc9\x30\xf8\x41\xcc\xbc\x51\x1c\x25\x9d\x5b\x0c\x99\xf0\x90\x4b\x8d\x59\x6e\xa1\xf4\xc0\xa7\x4d\x00\x05\x1a\x30\x82\x05\x16\x30\x82\x02\xfe\xa0\x03\x02\x01\x02\x02\x11\x00\x91\x2b\x08\x4a\xcf\x0c\x18\xa7\x53\xf6\xd6\x2e\x25\xa7\x5f\x5a\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x30\x4f\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x29\x30\x27\x06\x03\x55\x04\x0a\x13\x20\x49\x6e\x74\x65\x72\x6e\x65\x74\x20\x53\x65\x63\x75\x72\x69\x74\x79\x20\x52\x65\x73\x65\x61\x72\x63\x68\x20\x47\x72\x6f\x75\x70\x31\x15\x30\x13\x06\x03\x55\x04\x03\x13\x0c\x49\x53\x52\x47\x20\x52\x6f\x6f\x74\x20\x58\x31\x30\x1e\x17\x0d\x32\x30\x30\x39\x30\x34\x30\x30\x30\x30\x30\x30\x5a\x17\x0d\x32\x35\x30\x39\x31\x35\x31\x36\x30\x30\x30\x30\x5a\x30\x32\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x16\x30\x14\x06\x03\x55\x04\x0a\x13\x0d\x4c\x65\x74\x27\x73\x20\x45\x6e\x63\x72\x79\x70\x74\x31\x0b\x30\x09\x06\x03\x55\x04\x03\x13\x02\x52\x33\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xbb\x02\x15\x28\xcc\xf6\xa0\x94\xd3\x0f\x12\xec\x8d\x55\x92\xc3\xf8\x82\xf1\x99\xa6\x7a\x42\x88\xa7\x5d\x26\xaa\xb5\x2b\xb9\xc5\x4c\xb1\xaf\x8e\x6b\xf9\x75\xc8\xa3\xd7\x0f\x47\x94\x14\x55\x35\x57\x8c\x9e\xa8\xa2\x39\x19\xf5\x82\x3c\x42\xa9\x4e\x6e\xf5\x3b\xc3\x2e\xdb\x8d\xc0\xb0\x5c\xf3\x59\x38\xe7\xed\xcf\x69\xf0\x5a\x0b\x1b\xbe\xc0\x94\x24\x25\x87\xfa\x37\x71\xb3\x13\xe7\x1c\xac\xe1\x9b\xef\xdb\xe4\x3b\x45\x52\x45\x96\xa9\xc1\x53\xce\x34\xc8\x52\xee\xb5\xae\xed\x8f\xde\x60\x70\xe2\xa5\x54\xab\xb6\x6d\x0e\x97\xa5\x40\x34\x6b\x2b\xd3\xbc\x66\xeb\x66\x34\x7c\xfa\x6b\x8b\x8f\x57\x29\x99\xf8\x30\x17\x5d\xba\x72\x6f\xfb\x81\xc5\xad\xd2\x86\x58\x3d\x17\xc7\xe7\x09\xbb\xf1\x2b\xf7\x86\xdc\xc1\xda\x71\x5d\xd4\x46\xe3\xcc\xad\x25\xc1\x88\xbc\x60\x67\x75\x66\xb3\xf1\x18\xf7\xa2\x5c\xe6\x53\xff\x3a\x88\xb6\x47\xa5\xff\x13\x18\xea\x98\x09\x77\x3f\x9d\x53\xf9\xcf\x01\xe5\xf5\xa6\x70\x17\x14\xaf\x63\xa4\xff\x99\xb3\x93\x9d\xdc\x53\xa7\x06\xfe\x48\x85\x1d\xa1\x69\xae\x25\x75\xbb\x13\xcc\x52\x03\xf5\xed\x51\xa1\x8b\xdb\x15\x02\x03\x01\x00\x01\xa3\x82\x01\x08\x30\x82\x01\x04\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x86\x30\x1d\x06\x03\x55\x1d\x25\x04\x16\x30\x14\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x02\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01\x30\x12\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x08\x30\x06\x01\x01\xff\x02\x01\x00\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\x14\x2e\xb3\x17\xb7\x58\x56\xcb\xae\x50\x09\x40\xe6\x1f\xaf\x9d\x8b\x14\xc2\xc6\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\x79\xb4\x59\xe6\x7b\xb6\xe5\xe4\x01\x73\x80\x08\x88\xc8\x1a\x58\xf6\xe9\x9b\x6e\x30\x32\x06\x08\x2b\x06\x01\x05\x05\x07\x01\x01\x04\x26\x30\x24\x30\x22\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x02\x86\x16\x68\x74\x74\x70\x3a\x2f\x2f\x78\x31\x2e\x69\x2e\x6c\x65\x6e\x63\x72\x2e\x6f\x72\x67\x2f\x30\x27\x06\x03\x55\x1d\x1f\x04\x20\x30\x1e\x30\x1c\xa0\x1a\xa0\x18\x86\x16\x68\x74\x74\x70\x3a\x2f\x2f\x78\x31\x2e\x63\x2e\x6c\x65\x6e\x63\x72\x2e\x6f\x72\x67\x2f\x30\x22\x06\x03\x55\x1d\x20\x04\x1b\x30\x19\x30\x08\x06\x06\x67\x81\x0c\x01\x02\x01\x30\x0d\x06\x0b\x2b\x06\x01\x04\x01\x82\xdf\x13\x01\x01\x01\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x02\x01\x00\x85\xca\x4e\x47\x3e\xa3\xf7\x85\x44\x85\xbc\xd5\x67\x78\xb2\x98\x63\xad\x75\x4d\x1e\x96\x3d\x33\x65\x72\x54\x2d\x81\xa0\xea\xc3\xed\xf8\x20\xbf\x5f\xcc\xb7\x70\x00\xb7\x6e\x3b\xf6\x5e\x94\xde\xe4\x20\x9f\xa6\xef\x8b\xb2\x03\xe7\xa2\xb5\x16\x3c\x91\xce\xb4\xed\x39\x02\xe7\x7c\x25\x8a\x47\xe6\x65\x6e\x3f\x46\xf4\xd9\xf0\xce\x94\x2b\xee\x54\xce\x12\xbc\x8c\x27\x4b\xb8\xc1\x98\x2f\xa2\xaf\xcd\x71\x91\x4a\x08\xb7\xc8\xb8\x23\x7b\x04\x2d\x08\xf9\x08\x57\x3e\x83\xd9\x04\x33\x0a\x47\x21\x78\x09\x82\x27\xc3\x2a\xc8\x9b\xb9\xce\x5c\xf2\x64\xc8\xc0\xbe\x79\xc0\x4f\x8e\x6d\x44\x0c\x5e\x92\xbb\x2e\xf7\x8b\x10\xe1\xe8\x1d\x44\x29\xdb\x59\x20\xed\x63\xb9\x21\xf8\x12\x26\x94\x93\x57\xa0\x1d\x65\x04\xc1\x0a\x22\xae\x10\x0d\x43\x97\xa1\x18\x1f\x7e\xe0\xe0\x86\x37\xb5\x5a\xb1\xbd\x30\xbf\x87\x6e\x2b\x2a\xff\x21\x4e\x1b\x05\xc3\xf5\x18\x97\xf0\x5e\xac\xc3\xa5\xb8\x6a\xf0\x2e\xbc\x3b\x33\xb9\xee\x4b\xde\xcc\xfc\xe4\xaf\x84\x0b\x86\x3f\xc0\x55\x43\x36\xf6\x68\xe1\x36\x17\x6a\x8e\x99\xd1\xff\xa5\x40\xa7\x34\xb7\xc0\xd0\x63\x39\x35\x39\x75\x6e\xf2\xba\x76\xc8\x93\x02\xe9\xa9\x4b\x6c\x17\xce\x0c\x02\xd9\xbd\x81\xfb\x9f\xb7\x68\xd4\x06\x65\xb3\x82\x3d\x77\x53\xf8\x8e\x79\x03\xad\x0a\x31\x07\x75\x2a\x43\xd8\x55\x97\x72\xc4\x29\x0e\xf7\xc4\x5d\x4e\xc8\xae\x46\x84\x30\xd7\xf2\x85\x5f\x18\xa1\x79\xbb\xe7\x5e\x70\x8b\x07\xe1\x86\x93\xc3\xb9\x8f\xdc\x61\x71\x25\x2a\xaf\xdf\xed\x25\x50\x52\x68\x8b\x92\xdc\xe5\xd6\xb5\xe3\xda\x7d\xd0\x87\x6c\x84\x21\x31\xae\x82\xf5\xfb\xb9\xab\xc8\x89\x17\x3d\xe1\x4c\xe5\x38\x0e\xf6\xbd\x2b\xbd\x96\x81\x14\xeb\xd5\xdb\x3d\x20\xa7\x7e\x59\xd3\xe2\xf8\x58\xf9\x5b\xb8\x48\xcd\xfe\x5c\x4f\x16\x29\xfe\x1e\x55\x23\xaf\xc8\x11\xb0\x8d\xea\x7c\x93\x90\x17\x2f\xfd\xac\xa2\x09\x47\x46\x3f\xf0\xe9\xb0\xb7\xff\x28\x4d\x68\x32\xd6\x67\x5e\x1e\x69\xa3\x93\xb8\xf5\x9d\x8b\x2f\x0b\xd2\x52\x43\xa6\x6f\x32\x57\x65\x4d\x32\x81\xdf\x38\x53\x85\x5d\x7e\x5d\x66\x29\xea\xb8\xdd\xe4\x95\xb5\xcd\xb5\x56\x12\x42\xcd\xc4\x4e\xc6\x25\x38\x44\x50\x6d\xec\xce\x00\x55\x18\xfe\xe9\x49\x64\xd4\x4e\xca\x97\x9c\xb4\x5b\xc0\x73\xa8\xab\xb8\x47\xc2\x00\x05\x64\x30\x82\x05\x60\x30\x82\x04\x48\xa0\x03\x02\x01\x02\x02\x10\x40\x01\x77\x21\x37\xd4\xe9\x42\xb8\xee\x76\xaa\x3c\x64\x0a\xb7\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x30\x3f\x31\x24\x30\x22\x06\x03\x55\x04\x0a\x13\x1b\x44\x69\x67\x69\x74\x61\x6c\x20\x53\x69\x67\x6e\x61\x74\x75\x72\x65\x20\x54\x72\x75\x73\x74\x20\x43\x6f\x2e\x31\x17\x30\x15\x06\x03\x55\x04\x03\x13\x0e\x44\x53\x54\x20\x52\x6f\x6f\x74\x20\x43\x41\x20\x58\x33\x30\x1e\x17\x0d\x32\x31\x30\x31\x32\x30\x31\x39\x31\x34\x30\x33\x5a\x17\x0d\x32\x34\x30\x39\x33\x30\x31\x38\x31\x34\x30\x33\x5a\x30\x4f\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x29\x30\x27\x06\x03\x55\x04\x0a\x13\x20\x49\x6e\x74\x65\x72\x6e\x65\x74\x20\x53\x65\x63\x75\x72\x69\x74\x79\x20\x52\x65\x73\x65\x61\x72\x63\x68\x20\x47\x72\x6f\x75\x70\x31\x15\x30\x13\x06\x03\x55\x04\x03\x13\x0c\x49\x53\x52\x47\x20\x52\x6f\x6f\x74\x20\x58\x31\x30\x82\x02\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x02\x0f\x00\x30\x82\x02\x0a\x02\x82\x02\x01\x00\xad\xe8\x24\x73\xf4\x14\x37\xf3\x9b\x9e\x2b\x57\x28\x1c\x87\xbe\xdc\xb7\xdf\x38\x90\x8c\x6e\x3c\xe6\x57\xa0\x78\xf7\x75\xc2\xa2\xfe\xf5\x6a\x6e\xf6\x00\x4f\x28\xdb\xde\x68\x86\x6c\x44\x93\xb6\xb1\x63\xfd\x14\x12\x6b\xbf\x1f\xd2\xea\x31\x9b\x21\x7e\xd1\x33\x3c\xba\x48\xf5\xdd\x79\xdf\xb3\xb8\xff\x12\xf1\x21\x9a\x4b\xc1\x8a\x86\x71\x69\x4a\x66\x66\x6c\x8f\x7e\x3c\x70\xbf\xad\x29\x22\x06\xf3\xe4\xc0\xe6\x80\xae\xe2\x4b\x8f\xb7\x99\x7e\x94\x03\x9f\xd3\x47\x97\x7c\x99\x48\x23\x53\xe8\x38\xae\x4f\x0a\x6f\x83\x2e\xd1\x49\x57\x8c\x80\x74\xb6\xda\x2f\xd0\x38\x8d\x7b\x03\x70\x21\x1b\x75\xf2\x30\x3c\xfa\x8f\xae\xdd\xda\x63\xab\xeb\x16\x4f\xc2\x8e\x11\x4b\x7e\xcf\x0b\xe8\xff\xb5\x77\x2e\xf4\xb2\x7b\x4a\xe0\x4c\x12\x25\x0c\x70\x8d\x03\x29\xa0\xe1\x53\x24\xec\x13\xd9\xee\x19\xbf\x10\xb3\x4a\x8c\x3f\x89\xa3\x61\x51\xde\xac\x87\x07\x94\xf4\x63\x71\xec\x2e\xe2\x6f\x5b\x98\x81\xe1\x89\x5c\x34\x79\x6c\x76\xef\x3b\x90\x62\x79\xe6\xdb\xa4\x9a\x2f\x26\xc5\xd0\x10\xe1\x0e\xde\xd9\x10\x8e\x16\xfb\xb7\xf7\xa8\xf7\xc7\xe5\x02\x07\x98\x8f\x36\x08\x95\xe7\xe2\x37\x96\x0d\x36\x75\x9e\xfb\x0e\x72\xb1\x1d\x9b\xbc\x03\xf9\x49\x05\xd8\x81\xdd\x05\xb4\x2a\xd6\x41\xe9\xac\x01\x76\x95\x0a\x0f\xd8\xdf\xd5\xbd\x12\x1f\x35\x2f\x28\x17\x6c\xd2\x98\xc1\xa8\x09\x64\x77\x6e\x47\x37\xba\xce\xac\x59\x5e\x68\x9d\x7f\x72\xd6\x89\xc5\x06\x41\x29\x3e\x59\x3e\xdd\x26\xf5\x24\xc9\x11\xa7\x5a\xa3\x4c\x40\x1f\x46\xa1\x99\xb5\xa7\x3a\x51\x6e\x86\x3b\x9e\x7d\x72\xa7\x12\x05\x78\x59\xed\x3e\x51\x78\x15\x0b\x03\x8f\x8d\xd0\x2f\x05\xb2\x3e\x7b\x4a\x1c\x4b\x73\x05\x12\xfc\xc6\xea\xe0\x50\x13\x7c\x43\x93\x74\xb3\xca\x74\xe7\x8e\x1f\x01\x08\xd0\x30\xd4\x5b\x71\x36\xb4\x07\xba\xc1\x30\x30\x5c\x48\xb7\x82\x3b\x98\xa6\x7d\x60\x8a\xa2\xa3\x29\x82\xcc\xba\xbd\x83\x04\x1b\xa2\x83\x03\x41\xa1\xd6\x05\xf1\x1b\xc2\xb6\xf0\xa8\x7c\x86\x3b\x46\xa8\x48\x2a\x88\xdc\x76\x9a\x76\xbf\x1f\x6a\xa5\x3d\x19\x8f\xeb\x38\xf3\x64\xde\xc8\x2b\x0d\x0a\x28\xff\xf7\xdb\xe2\x15\x42\xd4\x22\xd0\x27\x5d\xe1\x79\xfe\x18\xe7\x70\x88\xad\x4e\xe6\xd9\x8b\x3a\xc6\xdd\x27\x51\x6e\xff\xbc\x64\xf5\x33\x43\x4f\x02\x03\x01\x00\x01\xa3\x82\x01\x46\x30\x82\x01\x42\x30\x0f\x06\x03\x55\x1d\x13\x01\x01\xff\x04\x05\x30\x03\x01\x01\xff\x30\x0e\x06\x03\x55\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x01\x06\x30\x4b\x06\x08\x2b\x06\x01\x05\x05\x07\x01\x01\x04\x3f\x30\x3d\x30\x3b\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x02\x86\x2f\x68\x74\x74\x70\x3a\x2f\x2f\x61\x70\x70\x73\x2e\x69\x64\x65\x6e\x74\x72\x75\x73\x74\x2e\x63\x6f\x6d\x2f\x72\x6f\x6f\x74\x73\x2f\x64\x73\x74\x72\x6f\x6f\x74\x63\x61\x78\x33\x2e\x70\x37\x63\x30\x1f\x06\x03\x55\x1d\x23\x04\x18\x30\x16\x80\x14\xc4\xa7\xb1\xa4\x7b\x2c\x71\xfa\xdb\xe1\x4b\x90\x75\xff\xc4\x15\x60\x85\x89\x10\x30\x54\x06\x03\x55\x1d\x20\x04\x4d\x30\x4b\x30\x08\x06\x06\x67\x81\x0c\x01\x02\x01\x30\x3f\x06\x0b\x2b\x06\x01\x04\x01\x82\xdf\x13\x01\x01\x01\x30\x30\x30\x2e\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x01\x16\x22\x68\x74\x74\x70\x3a\x2f\x2f\x63\x70\x73\x2e\x72\x6f\x6f\x74\x2d\x78\x31\x2e\x6c\x65\x74\x73\x65\x6e\x63\x72\x79\x70\x74\x2e\x6f\x72\x67\x30\x3c\x06\x03\x55\x1d\x1f\x04\x35\x30\x33\x30\x31\xa0\x2f\xa0\x2d\x86\x2b\x68\x74\x74\x70\x3a\x2f\x2f\x63\x72\x6c\x2e\x69\x64\x65\x6e\x74\x72\x75\x73\x74\x2e\x63\x6f\x6d\x2f\x44\x53\x54\x52\x4f\x4f\x54\x43\x41\x58\x33\x43\x52\x4c\x2e\x63\x72\x6c\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14\x79\xb4\x59\xe6\x7b\xb6\xe5\xe4\x01\x73\x80\x08\x88\xc8\x1a\x58\xf6\xe9\x9b\x6e\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00\x0a\x73\x00\x6c\x96\x6e\xff\x0e\x52\xd0\xae\xdd\x8c\xe7\x5a\x06\xad\x2f\xa8\xe3\x8f\xbf\xc9\x0a\x03\x15\x50\xc2\xe5\x6c\x42\xbb\x6f\x9b\xf4\xb4\x4f\xc2\x44\x88\x08\x75\xcc\xeb\x07\x9b\x14\x62\x6e\x78\xde\xec\x27\xba\x39\x5c\xf5\xa2\xa1\x6e\x56\x94\x70\x10\x53\xb1\xbb\xe4\xaf\xd0\xa2\xc3\x2b\x01\xd4\x96\xf4\xc5\x20\x35\x33\xf9\xd8\x61\x36\xe0\x71\x8d\xb4\xb8\xb5\xaa\x82\x45\x95\xc0\xf2\xa9\x23\x28\xe7\xd6\xa1\xcb\x67\x08\xda\xa0\x43\x2c\xaa\x1b\x93\x1f\xc9\xde\xf5\xab\x69\x5d\x13\xf5\x5b\x86\x58\x22\xca\x4d\x55\xe4\x70\x67\x6d\xc2\x57\xc5\x46\x39\x41\xcf\x8a\x58\x83\x58\x6d\x99\xfe\x57\xe8\x36\x0e\xf0\x0e\x23\xaa\xfd\x88\x97\xd0\xe3\x5c\x0e\x94\x49\xb5\xb5\x17\x35\xd2\x2e\xbf\x4e\x85\xef\x18\xe0\x85\x92\xeb\x06\x3b\x6c\x29\x23\x09\x60\xdc\x45\x02\x4c\x12\x18\x3b\xe9\xfb\x0e\xde\xdc\x44\xf8\x58\x98\xae\xea\xbd\x45\x45\xa1\x88\x5d\x66\xca\xfe\x10\xe9\x6f\x82\xc8\x11\x42\x0d\xfb\xe9\xec\xe3\x86\x00\xde\x9d\x10\xe3\x38\xfa\xa4\x7d\xb1\xd8\xe8\x49\x82\x84\x06\x9b\x2b\xe8\x6b\x4f\x01\x0c\x38\x77\x2e\xf9\xdd\xe7\x39",
            .want = "\x78\x42\xbf\xc1\xb3\x63\x6f\xc2\x68\xb5\x1e\xca\xd5\x8d\xe7\xe7\x80\x0b\x99\x7e\x3c\x3f\xb6\x63\x64\x81\x15\x29\xdf\x4c\xb7\x15",
        },
        .{
            .label = "skx",
            .input = "\x0c\x00\x00\x70\x03\x00\x1d\x20\x6d\x4a\xcc\x64\x73\x1f\xa0\xd5\x3d\x7e\x8d\x4f\x55\x10\x57\xa5\x32\x70\xd7\x8d\xa4\xee\xb6\x1a\xa9\x86\xe7\xf1\xec\x48\xff\x18\x02\x03\x00\x48\x30\x46\x02\x21\x00\xd5\x43\x45\x04\x2e\x87\xce\xbb\x78\xcc\x9a\xd9\x92\x6d\xa3\xbe\x0c\xf5\x79\x14\xb5\xd6\xcb\x39\xcf\x69\xd9\x84\x34\x46\xc3\x33\x02\x21\x00\x95\x38\x6d\xe1\x77\x8b\x76\x5d\x8a\x89\xac\x76\xcc\xcc\x79\xf8\x49\x58\x4d\x1a\x57\x2f\x3c\x63\x01\x32\xa2\x5a\xbd\x25\x50\xc5",
            .want = "\xb8\x6e\xd7\x50\x67\x50\x3e\x00\xd3\x98\xe7\xf5\x2d\xab\x9a\x3d\x76\xf4\x8d\x4f\xea\xbd\x96\x29\x7a\xc2\x3c\x27\x0a\xbe\x6e\x9d",
        },
        .{
            .label = "helloDone",
            .input = "\x0e\x00\x00\x00",
            .want = "\x85\xe6\x72\x55\xe1\x65\xe9\x89\x68\xce\xa5\xda\x01\x9b\x0f\x08\x49\xbf\xba\xd5\xf5\x86\xb1\x6a\x44\x53\x79\x52\x5e\xa7\xc3\x4d",
        },
        .{
            .label = "ckx",
            .input = "\x10\x00\x00\x21\x20\x60\xb9\xe8\x91\x6c\x44\x68\x09\xfa\xbf\x21\x89\x15\x37\xe4\x45\xcb\x69\x7b\x64\x96\x85\xa8\xa9\x51\x7f\x5a\x91\xdf\xbb\x52\x37",
            .want = "\x25\xa6\x2f\xf5\xb8\xb6\xc9\xb0\xd2\xe8\xb2\xce\xfb\x06\xdc\xcb\x4d\x43\x10\xfc\x84\xdf\x6d\x15\x70\x50\xc4\x08\xc5\x9f\x7b\x94",
        },
        .{
            .label = "clientFinished",
            .input = "\x14\x00\x00\x0c\x62\x33\xd4\x1b\xe0\x00\xad\x37\x6a\x2c\xdf\x4d",
            .want = "\xde\x98\xb0\x5b\xc3\x47\x1d\x22\x64\x72\xaa\x4a\x05\xd9\x76\x7c\x44\x40\xd3\xdf\xf5\x5a\x08\xc6\x5c\xcd\xff\x36\x91\xfc\x85\x3e",
        },
    };
    var h = Sha256.init(.{});
    for (test_cases) |c, i| {
        h.update(c.input);
        var got: [Sha256.digest_length]u8 = undefined;
        var h2 = h;
        h2.final(&got);
        if (!std.mem.eql(u8, c.want, &got)) {
            std.debug.print("hash mismatch, i={}, label={s}, got={}, want={}\n", .{
                i, c.label, std.fmt.fmtSliceHexLower(c.want), std.fmt.fmtSliceHexLower(&got),
            });
        }
    }
}
