const std = @import("std");
const Conn = @import("conn.zig").Conn;
const ClientHelloMsg = @import("handshake_msg.zig").ClientHelloMsg;
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const EcdheParameters = @import("key_schedule.zig").EcdheParameters;
const CipherSuiteTls13 = @import("cipher_suites.zig").CipherSuiteTls13;

pub const ClientHandshakeStateTls13 = struct {
    conn: *Conn,
    hello: ClientHelloMsg,
    server_hello: ServerHelloMsg,
    ecdhe_params: EcdheParameters,

    suite: ?*const CipherSuiteTls13 = null,
    master_secret: ?[]const u8 = null,
};
