const std = @import("std");
const mem = std.mem;
const asn1 = @import("asn1.zig");
const x509 = @import("x509.zig");

const RdnSequence = struct {
    names: []const RelativeDistinguishedName,

    fn parse(raw: *asn1.String, allocator: mem.Allocator) !RdnSequence {
        _ = raw;
        _ = allocator;
        // var s = try raw.readAsn1(.sequence);
        // while (!s.empty()) {
        //     var set = s.readAsn1(.set) catch return error.X509InvalidRdnSequence;
        //     while (!set.empty()) {
        //         var atav = set.readAsn1(.sequecne) catch return error.X509InvalidRdnSequence;
        //         var attr_type = atav.readAsn1ObjectIdentifier() catch
        //             return error.X509InvalidRdnSequence;
        //         var value_tag: asn1.Tag = undefined;
        //         var raw_value = atav.readAnyAsn1(&value_tag) catch
        //             return error.X509InvalidRdnSequence;
        //     }
        // }
        @panic("not implemented yet");
    }

    pub fn deinit(self: *RdnSequence, allocator: mem.Allocator) void {
        allocator.free(self.names);
    }
};

const RelativeDistinguishedName = struct {
    attributes: []const AttributeTypeAndValue,
};

// AttributeTypeAndValue mirrors the ASN.1 structure of the same name in
// RFC 5280, Section 4.1.2.4.
const AttributeTypeAndValue = struct {
    @"type": asn1.ObjectIdentifier,
    value: anyopaque,
};

// AlgorithmIdentifier represents the ASN.1 structure of the same name. See RFC
// 5280, section 4.1.1.2.
pub const AlgorithmIdentifier = struct {
    algorithm: asn1.ObjectIdentifier,
    parameters: ?asn1.RawValue = null,

    pub fn deinit(self: *AlgorithmIdentifier, allocator: mem.Allocator) void {
        self.algorithm.deinit(allocator);
        if (self.parameters) |*params| params.deinit(allocator);
    }
};

pub fn readAlgorithmIdentifier(self: *asn1.String, allocator: mem.Allocator) !AlgorithmIdentifier {
    var algorithm = try asn1.readAsn1ObjectIdentifier(self, allocator);
    errdefer algorithm.deinit(allocator);

    if (self.empty()) {
        return AlgorithmIdentifier{ .algorithm = algorithm };
    }

    var tag: asn1.Tag = undefined;
    var params = try self.readAnyAsn1Element(&tag);
    return AlgorithmIdentifier{
        .algorithm = algorithm,
        .parameters = .{ .tag = tag, .full_bytes = try allocator.dupe(u8, params.data) },
    };
}
