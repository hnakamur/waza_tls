const std = @import("std");

pub const IpAddressNet = union(enum) {
    in: Ip4AddressNet,
    in6: Ip6AddressNet,
};

pub const Ip4AddressNet = struct {
    ip: std.net.Ip4Address,
    mask: [4]u8,
};

pub const Ip6AddressNet = struct {
    ip: std.net.Ip6Address,
    mask: [16]u8,
};
