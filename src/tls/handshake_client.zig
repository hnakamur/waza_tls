const std = @import("std");
const mem = std.mem;
const HandshakeMsg = @import("handshake_msg.zig").HandshakeMsg;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const ClientKeyExchangeMsg = @import("handshake_msg.zig").ClientKeyExchangeMsg;
const FinishedMsg = @import("handshake_msg.zig").FinishedMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const freeOptionalField = @import("handshake_msg.zig").freeOptionalField;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const cipherSuite12ById = @import("cipher_suites.zig").cipherSuite12ById;
const x509 = @import("x509.zig");
const prfForVersion = @import("prf.zig").prfForVersion;
const master_secret_length = @import("prf.zig").master_secret_length;
const master_secret_label = @import("prf.zig").master_secret_label;
const masterFromPreMasterSecret = @import("prf.zig").masterFromPreMasterSecret;
const ConnectionKeys = @import("prf.zig").ConnectionKeys;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const constantTimeEqlBytes = @import("constant_time.zig").constantTimeEqlBytes;
const Conn = @import("conn.zig").Conn;
const fmtx = @import("../fmtx.zig");

pub const ClientHandshakeState = union(ProtocolVersion) {
    v1_3: void,
    v1_2: ClientHandshakeStateTls12,
    v1_0: void,

    pub fn init(
        ver: ProtocolVersion,
        conn: *Conn,
        client_hello: ClientHelloMsg,
        server_hello: ServerHelloMsg,
    ) ClientHandshakeState {
        return switch (ver) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2 => ClientHandshakeState{
                .v1_2 = ClientHandshakeStateTls12.init(conn, client_hello, server_hello),
            },
            .v1_0 => @panic("unsupported version"),
        };
    }

    pub fn deinit(self: *ClientHandshakeState, allocator: mem.Allocator) void {
        switch (self.*) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2 => |*hs| hs.deinit(allocator),
            .v1_0 => @panic("unsupported version"),
        }
    }

    pub fn handshake(self: *ClientHandshakeState, allocator: mem.Allocator) !void {
        switch (self.*) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2 => |*hs| try hs.handshake(allocator),
            .v1_0 => @panic("unsupported version"),
        }
    }
};

pub const ClientHandshakeStateTls12 = struct {
    conn: *Conn,
    hello: ClientHelloMsg,
    server_hello: ServerHelloMsg,
    suite: ?*const CipherSuite12 = null,
    finished_hash: ?FinishedHash = null,
    master_secret: ?[]const u8 = null,

    pub fn init(
        conn: *Conn,
        client_hello: ClientHelloMsg,
        server_hello: ServerHelloMsg,
    ) ClientHandshakeStateTls12 {
        return .{
            .hello = client_hello,
            .server_hello = server_hello,
            .conn = conn,
        };
    }

    pub fn deinit(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) void {
        self.hello.deinit(allocator);
        self.server_hello.deinit(allocator);
        if (self.finished_hash) |*fh| fh.deinit();
        if (self.master_secret) |s| allocator.free(s);
    }

    pub fn handshake(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) !void {
        const is_resume = try self.processServerHello(allocator);

        self.finished_hash = FinishedHash.new(allocator, self.conn.version.?, self.suite.?);

        // TODO: implement

        try self.finished_hash.?.write(try self.hello.marshal(allocator));
        try self.finished_hash.?.write(try self.server_hello.marshal(allocator));

        self.conn.buffering = true;
        if (is_resume) {
            // TODO: implement
        } else {
            try self.doFullHandshake(allocator);
            try self.establishKeys(allocator);
            try self.sendFinished(allocator, &self.conn.client_finished);
            std.log.debug(
                "ClientHandshakeStateTls12 client_finished={}",
                .{fmtx.fmtSliceHexEscapeLower(&self.conn.client_finished)},
            );
            try self.conn.flush();
            try self.readFinished(allocator, &self.conn.server_finished);
            std.log.debug(
                "ClientHandshakeStateTls12 server_finished={}",
                .{fmtx.fmtSliceHexEscapeLower(&self.conn.server_finished)},
            );
        }

        self.conn.handshake_complete = true;
    }

    pub fn doFullHandshake(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) !void {
        var hs_msg = try self.conn.readHandshake(allocator);
        var cert_msg = switch (hs_msg) {
            .Certificate => |c| c,
            else => {
                // TODO: send alert
                return error.UnexpectedMessage;
            },
        };
        defer cert_msg.deinit(allocator);
        if (cert_msg.certificates.len == 0) {
            // TODO: send alert
            return error.UnexpectedMessage;
        }

        try self.finished_hash.?.write(try cert_msg.marshal(allocator));

        var cert_chain = CertificateChain{
            .certificate_chain = try allocator.dupe([]const u8, cert_msg.certificates),
        };
        defer cert_chain.deinit(allocator);

        hs_msg = try self.conn.readHandshake(allocator);
        switch (hs_msg) {
            .CertificateStatus => |cs| {
                _ = cs;
                hs_msg = try self.conn.readHandshake(allocator);
            },
            else => {},
        }

        var key_agreement = self.suite.?.ka(self.conn.version.?);
        defer key_agreement.deinit(allocator);

        switch (hs_msg) {
            .ServerKeyExchange => |*skx_msg| {
                {
                    defer skx_msg.deinit(allocator);
                    try self.finished_hash.?.write(try skx_msg.marshal(allocator));
                    try key_agreement.processServerKeyExchange(
                        allocator,
                        &self.hello,
                        &self.server_hello,
                        &cert_chain,
                        skx_msg,
                    );
                }
                hs_msg = try self.conn.readHandshake(allocator);
            },
            else => {},
        }

        switch (hs_msg) {
            .ServerHelloDone => |*hello_done_msg| {
                defer hello_done_msg.deinit(allocator);
                try self.finished_hash.?.write(try hello_done_msg.marshal(allocator));
            },
            else => {
                // TODO: send alert
                return error.UnexpectedMessage;
            },
        }

        var pre_master_secret: []const u8 = undefined;
        var ckx_msg: ClientKeyExchangeMsg = undefined;
        try key_agreement.generateClientKeyExchange(
            allocator,
            &self.hello,
            &cert_chain,
            &pre_master_secret,
            &ckx_msg,
        );
        defer ckx_msg.deinit(allocator);
        defer allocator.free(pre_master_secret);
        const ckx_msg_bytes = try ckx_msg.marshal(allocator);
        try self.finished_hash.?.write(ckx_msg_bytes);
        try self.conn.writeRecord(allocator, .handshake, ckx_msg_bytes);

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
            .{fmtx.fmtSliceHexEscapeLower(self.master_secret.?)},
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
        defer finished.deinit(allocator);

        const finished_bytes = try finished.marshal(allocator);
        try self.finished_hash.?.write(finished_bytes);
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
            .Finished => |m| m,
            else => {
                // TODO: send alert
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
            // TODO: send alert
            return error.IncorrectServerFinishedMessage;
        }

        try self.finished_hash.?.write(try server_finished_msg.marshal(allocator));
        mem.copy(u8, out, &verify_data);
    }

    fn processServerHello(self: *ClientHandshakeStateTls12, allocator: mem.Allocator) !bool {
        try self.pickCipherSuite();
        _ = allocator;
        return false;
    }

    fn pickCipherSuite(self: *ClientHandshakeStateTls12) !void {
        // TODO: stop hardcoding
        var suite = cipherSuite12ById(.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256).?;
        self.suite = suite;
    }
};
