const std = @import("std");
const fifo = std.fifo;
const mem = std.mem;
const net = std.net;
const CipherSuite = @import("cipher_suites.zig").CipherSuite;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const RecordType = @import("record.zig").RecordType;

const max_plain_text = 16384; // maximum plaintext payload length

pub const Conn = struct {
    stream: net.Stream,
    in: HalfConn,
    out: HalfConn,
    version: ?ProtocolVersion = null,

    pub fn writeRecord(self: *Conn, record_type: RecordType, data: []const u8) !void {
        _ = record_type;
        _ = data;
        var n: usize = 0;
        _ = n;
        var rest = data;
        while (rest.len > 0) {
            const m = data.len;
            const vers = if (self.version) |vers| blk: {
                // TLS 1.3 froze the record layer version to 1.2.
                // See RFC 8446, Section 5.1.
                break :blk if (vers == .v1_3) .v1_2 else vers;
            } else blk: {
                // Some TLS servers fail if the record version is
                // greater than TLS 1.0 for the initial ClientHello.
                break :blk .v1_0;
            };
            _ = m;
            _ = vers;
        }
    }

    fn maxPayloadSizeForWrite(record_type: RecordType) usize {
        if (record_type != .application_data) {
            return max_plain_text;
        }
        @panic("not implemented yet");
    }
};

const HalfConn = struct {
    cipher: ?CipherSuite = null,

    fn encrypt(
        self: *HalfConn,
        allocator: mem.Allocator,
        record: *std.ArrayListUnmanaged(u8),
        payload: []const u8,
    ) !void {
        if (self.cipher) |_| {} else {
            try record.appendSlice(allocator, payload);
            return;
        }

        @panic("not implemented yet");
    }
};

const testing = std.testing;

test "HalfConn.encrypt" {
    const allocator = testing.allocator;

    var record = std.ArrayListUnmanaged(u8){};
    defer record.deinit(allocator);

    try record.appendSlice(allocator, "hello, ");

    var hc = HalfConn{};
    try hc.encrypt(allocator, &record, "world");
    try testing.expectEqualStrings("hello, world", record.items);
}
