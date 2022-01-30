const std = @import("std");

pub const ipv4_address_byte_len = 4;
pub const ipv6_address_byte_len = 16;

pub const IpAddressNet = union(enum) {
    in: Ip4AddressNet,
    in6: Ip6AddressNet,
};

pub const Ip4AddressNet = struct {
    ip: std.net.Ip4Address,
    mask: [ipv4_address_byte_len]u8,
};

pub const Ip6AddressNet = struct {
    ip: std.net.Ip6Address,
    mask: [ipv6_address_byte_len]u8,
};

pub fn addressFromBytes(ip_data: []const u8) !std.net.Address {
    return switch (ip_data.len) {
        ipv4_address_byte_len => std.net.Address.initIp4(ip_data[0..ipv4_address_byte_len].*, 0),
        ipv6_address_byte_len => std.net.Address.initIp6(
            ip_data[0..ipv6_address_byte_len].*,
            0,
            0,
            0,
        ),
        else => error.InvalidIpAddressBytes,
    };
}
