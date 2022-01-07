const std = @import("std");
const fifo = std.fifo;
const math = std.math;
const mem = std.mem;
const net = std.net;
const CipherSuite = @import("cipher_suites.zig").CipherSuite;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const RecordType = @import("record.zig").RecordType;

const max_plain_text = 16384; // maximum plaintext payload length
const record_header_len = 5;

pub const Conn = struct {
    stream: net.Stream,
    in: HalfConn,
    out: HalfConn,
    version: ?ProtocolVersion = null,
    buffering: bool = false,
    send_buf: std.ArrayListUnmanaged(u8) = .{},
    bytes_sent: usize = 0,

    pub fn writeRecord(
        self: *Conn,
        allocator: mem.Allocator,
        record_type: RecordType,
        data: []const u8,
    ) !void {
        var out_buf = try std.ArrayListUnmanaged(u8).initCapacity(allocator, record_header_len);
        defer out_buf.deinit(allocator);

        var n: usize = 0;
        var rest = data;
        while (rest.len > 0) {
            out_buf.clearRetainingCapacity();
            var writer = out_buf.writer();
            try writer.writeByte(@enumToInt(record_type));

            const vers = if (self.version) |vers| blk: {
                // TLS 1.3 froze the record layer version to 1.2.
                // See RFC 8446, Section 5.1.
                break :blk if (vers == .v1_3) .v1_2 else vers;
            } else blk: {
                // Some TLS servers fail if the record version is
                // greater than TLS 1.0 for the initial ClientHello.
                break :blk .v1_0;
            };
            try writer.writeIntBig(u16, @enumToInt(vers));

            const m = math.min(rest.len, self.maxPayloadSizeForWrite(record_type));
            try writer.writeIntBig(u16, @intCast(u16, m));

            try self.out.encrypt(allocator, &out_buf, rest[0..m]);
            try self.write(allocator, out_buf.items);
            n += m;
            rest = rest[m..];
        }

        if (record_type == .change_cipher_spec and self.version != .v1_3) {
            // TODO: implement
        }
    }

    fn maxPayloadSizeForWrite(self: *Conn, record_type: RecordType) usize {
        if (record_type != .application_data) {
            return max_plain_text;
        }
        _ = self;
        @panic("not implemented yet");
    }

    fn write(self: *Conn, allocator: mem.Allocator, data: []const u8) !void {
        if (self.buffering) {
            try self.send_buf.append(allocator, data);
            return;
        }

        try self.stream.writer().writeAll(self.send_buf.items);
        self.bytes_sent += self.send_buf.items.len;
    }

    fn flush(self: *Conn) !void {
        if (self.send_buf.items.len == 0) {
            return;
        }

        try self.stream.writer().writeAll(self.send_buf.items);
        self.bytes_sent += self.send_buf.items.len;
        self.send_buf.clearRetainingCapacity();
        self.buffering = false;
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
