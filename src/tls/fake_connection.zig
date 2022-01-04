const std = @import("std");
const mem = std.mem;
const CertificateMsg = @import("handshake_msg.zig").CertificateMsg;
const ServerKeyExchangeMsg = @import("handshake_msg.zig").ServerKeyExchangeMsg;
const ServerHelloDoneMsg = @import("handshake_msg.zig").ServerHelloDoneMsg;
const ClientKeyExchangeMsg = @import("handshake_msg.zig").ClientKeyExchangeMsg;
const KeyAgreement = @import("key_agreement.zig").KeyAgreement;

pub const FakeConnection = struct {
    cert_msg: ?CertificateMsg = null,
    skx_msg: ?ServerKeyExchangeMsg = null,
    hello_done_msg: ?ServerHelloDoneMsg = null,
    ckx_msg: ?ClientKeyExchangeMsg = null,
    server_key_agreement: ?KeyAgreement = null,

    pub fn deinit(self: *FakeConnection, allocator: mem.Allocator) void {
        if (self.cert_msg) |*m| m.deinit(allocator);
        if (self.skx_msg) |*m| m.deinit(allocator);
        if (self.hello_done_msg) |*m| m.deinit(allocator);
        if (self.ckx_msg) |*m| m.deinit(allocator);
    }
};
