const std = @import("std");
const mem = std.mem;
const asn1 = @import("asn1.zig");
const pem = @import("pem.zig");
const fmtx = @import("../fmtx.zig");
const CurveId = @import("handshake_msg.zig").CurveId;

const ec_priv_key_version = 1;

pub const EcPrivateKey = struct {
    private_key: []const u8 = "",
    named_curve_id: CurveId, // optional
    public_key: []const u8 = "", // optional

    pub fn parse(allocator: mem.Allocator, der: []const u8) !EcPrivateKey {
        std.log.debug("EcPrivateKey.parse start, der={}, len={}", .{ fmtx.fmtSliceHexColonLower(der), der.len });
        var input = asn1.String.init(der);
        var s = try input.readAsn1(.sequence);

        const version = try s.readAsn1Uint64();
        if (version != ec_priv_key_version) {
            return error.UnsupportedEcPrivateKeyVersion;
        }

        var tag: asn1.TagAndClass = undefined;
        var s2 = try s.readAnyAsn1(&tag);
        const private_key = try allocator.dupe(u8, s2.bytes);
        errdefer allocator.free(private_key);
        std.log.debug("#2 tag={}, s2.bytes={}, s2.bytes.len={}", .{ tag, fmtx.fmtSliceHexColonLower(s2.bytes), s2.bytes.len });

        s2 = try s.readAnyAsn1(&tag);
        std.log.debug("#3 tag={}, s2.bytes={}, s2.bytes.len={}", .{ tag, fmtx.fmtSliceHexColonLower(s2.bytes), s2.bytes.len });
        var oid = try asn1.ObjectIdentifier.parse(allocator, &s2);
        defer oid.deinit(allocator);
        std.log.debug("oid={}", .{oid});
        const curve_id = CurveId.fromOid(oid) orelse return error.UnsupportedEcPriveteKeyCurveOid;
        std.log.debug("curve_id={}", .{curve_id});

        s2 = try s.readAnyAsn1(&tag);
        std.log.debug("#4 tag={}, s2.bytes={}, s2.bytes.len={}", .{ tag, fmtx.fmtSliceHexColonLower(s2.bytes), s2.bytes.len });
        const public_key = try allocator.dupe(u8, s2.bytes);

        return EcPrivateKey{
            .private_key = private_key,
            .named_curve_id = curve_id,
            .public_key = public_key,
        };
    }

    pub fn deinit(self: *EcPrivateKey, allocator: mem.Allocator) void {
        allocator.free(self.private_key);
        allocator.free(self.public_key);
    }

    pub fn format(
        self: EcPrivateKey,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "EcPrivateKey{{ curve = {}, priv = {}, pub = {} }}", .{
            self.named_curve_id,
            fmtx.fmtSliceHexColonLower(self.private_key),
            fmtx.fmtSliceHexColonLower(self.public_key),
        });
    }
};

const testing = std.testing;

test "EcPrivateKey.parse" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    const key_pem = @embedFile("../../tests/p256-self-signed.key.pem");
    var offset: usize = 0;
    var key_block = try pem.Block.decode(allocator, key_pem, &offset);
    defer key_block.deinit(allocator);
    var key_der = key_block.bytes;
    std.log.debug("key_der={}", .{fmtx.fmtSliceHexColonLower(key_der)});
    // \x30\x77\x02\x01\x01\x04\x20\xc6\xae\x58\x08\xbb\xcd\xb5\xae\x76\x25\x07\x8b\x6c\xef\x4d\xb0\xf4\x86\xb4\x79\x0a\xf7\x74\x97\x1f\xc0\xff\xfc\x50\x63\xc6\x86\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\xa1\x44\x03\x42\x00\x04\x08\x34\x33\x5c\x0b\x0b\x4b\xb8\xc0\x0d\x27\x93\x84\x23\x85\xca\x63\x2b\x11\x58\x73\x2c\x94\xc0\x62\x16\x5e\x12\xf6\xb9\xb5\x23\x05\x45\xf7\xc5\x07\x83\x2e\x7e\xe8\x03\x8e\xd0\x08\x91\x46\xaa\xcc\xfe\x36\x55\x34\xe1\x88\x50\xd3\xb1\x8d\x5c\x37\xa3\xf2\xe3
    var key = try EcPrivateKey.parse(allocator, key_der);
    defer key.deinit(allocator);
    std.log.debug("key={}", .{key});
}
