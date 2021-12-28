const std = @import("std");
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;

// sessionState contains the information that is serialized into a session
// ticket in order to later resume a connection.
pub const SessionState = struct {
    vers: ?ProtocolVersion = null,
    cipher_suite: ?CipherSuiteId = null,
    created_at: ?u16 = null,
    master_secret: ?[]const u8 = null, // opaque master_secret<1..2^16-1>;

    // struct { opaque certificate<1..2^24-1> } Certificate;
    certificates: ?[]const []const u8 = null, // Certificate certificate_list<0..2^24-1>;

    // usedOldKey is true if the ticket from which this session came from
    // was encrypted with an older key and thus should be refreshed.
    used_old_key: bool = false,
};

test "SessionState" {
    var s = SessionState{};
    std.debug.print("SessionState={}\n", .{s});
}
