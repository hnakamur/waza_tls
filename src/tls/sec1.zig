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

        s2 = try s.readAnyAsn1(&tag);
        var oid = try asn1.ObjectIdentifier.parse(allocator, &s2);
        defer oid.deinit(allocator);
        const curve_id = CurveId.fromOid(oid) orelse return error.UnsupportedEcPriveteKeyCurveOid;

        s2 = try s.readAnyAsn1(&tag);
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
    var key = try EcPrivateKey.parse(allocator, key_der);
    defer key.deinit(allocator);
    std.log.debug("key={}", .{key});
}
