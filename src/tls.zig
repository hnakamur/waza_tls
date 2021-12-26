const std = @import("std");

const hs_msg = @import("tls/handshake_msg.zig");
const ClientHelloMsg = hs_msg.ClientHelloMsg;
const CipherSuite = hs_msg.CipherSuite;
const CompressionMethod = hs_msg.CompressionMethod;
const CurveId = hs_msg.CurveId;
const EcPointFormat = hs_msg.EcPointFormat;
const SignatureScheme = hs_msg.SignatureScheme;
const ProtocolVersion = hs_msg.ProtocolVersion;
const KeyShare = hs_msg.KeyShare;
const PskIdentity = hs_msg.PskIdentity;
const PskMode = hs_msg.PskMode;

comptime {
    std.testing.refAllDecls(@This());
}
