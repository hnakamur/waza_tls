const std = @import("std");
const ServerHelloMsg = @import("handshake_msg.zig").ServerHelloMsg;
const CertificateMsg = @import("handshake_msg.zig").CertificateMsg;
const ServerKeyExchangeMsg = @import("handshake_msg.zig").ServerKeyExchangeMsg;
const ServerHelloDoneMsg = @import("handshake_msg.zig").ServerHelloDoneMsg;

pub const FakeConnection = struct {
    server_hello_msg: ?ServerHelloMsg = null,
    cert_msg: ?CertificateMsg = null,
    skx_msg: ?ServerKeyExchangeMsg = null,
    hello_done_msg: ?ServerHelloDoneMsg = null,
};
