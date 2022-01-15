const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;
const CurveId = @import("handshake_msg.zig").CurveId;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CertificateMsg = @import("handshake_msg.zig").CertificateMsg;
const ServerHelloDoneMsg = @import("handshake_msg.zig").ServerHelloDoneMsg;
const FinishedMsg = @import("handshake_msg.zig").FinishedMsg;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CompressionMethod = @import("handshake_msg.zig").CompressionMethod;
const EcPointFormat = @import("handshake_msg.zig").EcPointFormat;
const generateRandom = @import("handshake_msg.zig").generateRandom;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const FinishedHash = @import("finished_hash.zig").FinishedHash;
const CipherSuite12 = @import("cipher_suites.zig").CipherSuite12;
const makeCipherPreferenceList12 = @import("cipher_suites.zig").makeCipherPreferenceList12;
const cipherSuite12ById = @import("cipher_suites.zig").cipherSuite12ById;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;
const SessionState = @import("ticket.zig").SessionState;
const ClientHandshakeState = @import("handshake_client.zig").ClientHandshakeState;
const KeyAgreement = @import("key_agreement.zig").KeyAgreement;
const masterFromPreMasterSecret = @import("prf.zig").masterFromPreMasterSecret;
const ConnectionKeys = @import("prf.zig").ConnectionKeys;
const constantTimeEqlBytes = @import("constant_time.zig").constantTimeEqlBytes;
const Conn = @import("conn.zig").Conn;
const fmtx = @import("../fmtx.zig");
const memx = @import("../memx.zig");

pub const ServerHandshakeState = union(ProtocolVersion) {
    v1_3: void,
    v1_2: ServerHandshakeStateTls12,
    v1_0: void,

    pub fn init(ver: ProtocolVersion, conn: *Conn, client_hello: ClientHelloMsg) ServerHandshakeState {
        return switch (ver) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2 => ServerHandshakeState{ .v1_2 = ServerHandshakeStateTls12.init(conn, client_hello) },
            .v1_0 => @panic("unsupported version"),
        };
    }

    pub fn deinit(self: *ServerHandshakeState, allocator: mem.Allocator) void {
        switch (self.*) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2 => |*hs| hs.deinit(allocator),
            .v1_0 => @panic("unsupported version"),
        }
    }

    pub fn handshake(self: *ServerHandshakeState, allocator: mem.Allocator) !void {
        switch (self.*) {
            .v1_3 => @panic("not implemented yet"),
            .v1_2 => |*hs| try hs.handshake(allocator),
            .v1_0 => @panic("unsupported version"),
        }
    }
};

// ServerHandshakeStateTls12 contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
pub const ServerHandshakeStateTls12 = struct {
    conn: *Conn,
    client_hello: ClientHelloMsg,
    hello: ?ServerHelloMsg = null,
    suite: ?*const CipherSuite12 = null,
    ecdhe_ok: bool = false,
    ec_sign_ok: bool = false,
    rsa_decrypt_ok: bool = false,
    rsa_sign_ok: bool = false,
    session_state: ?SessionState = null,
    finished_hash: ?FinishedHash = null,
    master_secret: ?[]const u8 = null,
    cert_chain: ?CertificateChain = null,

    pub fn init(conn: *Conn, client_hello: ClientHelloMsg) ServerHandshakeStateTls12 {
        return .{ .conn = conn, .client_hello = client_hello };
    }

    pub fn deinit(self: *ServerHandshakeStateTls12, allocator: mem.Allocator) void {
        self.client_hello.deinit(allocator);
        if (self.hello) |*hello| hello.deinit(allocator);
        if (self.finished_hash) |*fh| fh.deinit();
        if (self.cert_chain) |*cc| cc.deinit(allocator);
        if (self.master_secret) |s| allocator.free(s);
    }

    pub fn handshake(self: *ServerHandshakeStateTls12, allocator: mem.Allocator) !void {
        try self.processClientHello(allocator);

        // For an overview of TLS handshaking, see RFC 5246, Section 7.3.
        self.conn.buffering = true;
        if (self.checkForResumption()) {
            // TODO: implement
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

        const random = try generateRandom(allocator);
        // TODO: stop hardcoding field values.
        var hello = ServerHelloMsg{
            .vers = .v1_2,
            .random = random,
            .session_id = &[_]u8{0} ** 32,
            .cipher_suite = .TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // updated in doFullHandshake
            .compression_method = .none,
            .ocsp_stapling = false,
            .supported_version = .v1_2,
        };

        if (self.client_hello.secure_renegotiation.len > 0) {
            self.conn.sendAlert(.handshake_failure) catch {};
            return error.InitialHandshakeWithRenegotiation;
        }
        hello.secure_renegotiation_supported = self.client_hello.secure_renegotiation_supported;

        self.ecdhe_ok = supportedEcdHe(
            &self.conn.config,
            self.client_hello.supported_curves,
            self.client_hello.supported_points,
        );
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

        const certificate_chain = try allocator.dupe(
            []const u8,
            &[_][]const u8{testEd25519Certificate},
        );
        self.cert_chain = CertificateChain{
            .certificate_chain = certificate_chain,
            .private_key = .{ .raw = testEd25519PrivateKey },
        };
    }

    // checkForResumption reports whether we should perform resumption on this connection.
    fn checkForResumption(self: *const ServerHandshakeStateTls12) bool {
        _ = self;
        // TODO: implemnt
        return false;
    }

    pub fn pickCipherSuite(self: *ServerHandshakeStateTls12) !void {
        // TODO: stop hardcoding.
        const allocator = self.conn.allocator;
        var preference_list = try makeCipherPreferenceList12(
            allocator,
            self.conn.config.cipher_suites,
        );
        defer allocator.free(preference_list);
        self.suite = cipherSuite12ById(.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
    }

    pub fn doFullHandshake(self: *ServerHandshakeStateTls12, allocator: mem.Allocator) !void {
        self.hello.?.cipher_suite = self.suite.?.id;

        self.finished_hash = FinishedHash.new(allocator, self.conn.version.?, self.suite.?);

        if (false) { // TODO: stop hardcoding
            // No need to keep a full record of the handshake if client
            // certificates won't be used.
            self.finished_hash.?.discardHandshakeBuffer();
        }

        try self.finished_hash.?.write(try self.client_hello.marshal(allocator));
        const server_hello_bytes = try self.hello.?.marshal(allocator);
        try self.finished_hash.?.write(server_hello_bytes);
        try self.conn.writeRecord(allocator, .handshake, server_hello_bytes);

        {
            const certificates = try allocator.dupe(
                []const u8,
                &[_][]const u8{testEd25519Certificate},
            );
            var cert_msg = CertificateMsg{ .certificates = certificates };
            defer cert_msg.deinit(allocator);

            const cert_msg_bytes = try cert_msg.marshal(allocator);
            try self.finished_hash.?.write(cert_msg_bytes);
            try self.conn.writeRecord(allocator, .handshake, cert_msg_bytes);
        }

        if (self.hello.?.ocsp_stapling) {
            // TODO: implement
        }

        var key_agreement = self.suite.?.ka(self.conn.version.?);
        defer key_agreement.deinit(allocator);

        var skx = try key_agreement.generateServerKeyExchange(
            allocator,
            &self.cert_chain.?,
            &self.client_hello,
            &self.hello.?,
        );
        defer skx.deinit(allocator);

        const skx_bytes = try skx.marshal(allocator);
        try self.finished_hash.?.write(skx_bytes);
        try self.conn.writeRecord(allocator, .handshake, skx_bytes);

        var hello_done = ServerHelloDoneMsg{};
        defer hello_done.deinit(allocator);
        const hello_done_bytes = try hello_done.marshal(allocator);
        try self.finished_hash.?.write(hello_done_bytes);
        try self.conn.writeRecord(allocator, .handshake, hello_done_bytes);

        try self.conn.flush();

        var hs_msg = try self.conn.readHandshake(allocator);

        // Get client key exchange
        var ckx_msg = switch (hs_msg) {
            .ClientKeyExchange => |c| c,
            else => {
                // TODO: send alert
                return error.UnexpectedMessage;
            },
        };
        defer ckx_msg.deinit(allocator);
        try self.finished_hash.?.write(try ckx_msg.marshal(allocator));

        const pre_master_secret = try key_agreement.processClientKeyExchange(
            allocator,
            &self.cert_chain.?,
            &ckx_msg,
            self.conn.version.?,
        );
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

        // TODO: implement

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
                // TODO: send alert
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
            // TODO: send alert
            return error.IncorrectClientFinishedMessage;
        }

        try self.finished_hash.?.write(try client_finished_msg.marshal(allocator));
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
fn supportedEcdHe(
    c: *const Conn.Config,
    supported_curves: []const CurveId,
    supported_points: []const EcPointFormat,
) bool {
    const supports_curve = blk: {
        for (supported_curves) |curve| {
            if (c.supportsCurve(curve)) {
                break :blk true;
            }
        }
        break :blk false;
    };

    const supports_point_format = memx.containsScalar(
        EcPointFormat,
        supported_points,
        .uncompressed,
    );

    return supports_curve and supports_point_format;
}

const testing = std.testing;

test "supportedEcdHe" {
    const f = struct {
        fn f(
            want: bool,
            c: Conn.Config,
            supported_curves: []const CurveId,
            supported_points: []const EcPointFormat,
        ) !void {
            const got = supportedEcdHe(&c, supported_curves, supported_points);
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
