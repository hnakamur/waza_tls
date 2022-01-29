const std = @import("std");
const ascii = std.ascii;
const mem = std.mem;
const os = std.os;
const fmtx = @import("../fmtx.zig");
const memx = @import("../memx.zig");
const netx = @import("../netx.zig");

fn matchIpConstraint(ip: std.net.Address, constraint: netx.IpAddressNet) !bool {
    switch (ip.any.family) {
        os.AF.INET => {
            switch (constraint) {
                .in => |constraint_in| {
                    const mask = mem.readIntBig(u32, &constraint_in.mask);
                    const ip_addr = mem.nativeToBig(u32, ip.in.sa.addr);
                    const constraint_addr = mem.nativeToBig(u32, constraint_in.ip.sa.addr);
                    std.log.debug(
                        "mask=0x{x}, ip_addr=0x{x}, constraint_addr=0x{x}",
                        .{ mask, ip_addr, constraint_addr },
                    );
                    return ip_addr & mask == constraint_addr & mask;
                },
                else => return false,
            }
        },
        os.AF.INET6 => {
            switch (constraint) {
                .in6 => |constraint_in6| {
                    std.log.debug("mask={}, ip={}, constraint={}", .{
                        fmtx.fmtSliceHexEscapeLower(&constraint_in6.mask),
                        fmtx.fmtSliceHexEscapeLower(&ip.in6.sa.addr),
                        fmtx.fmtSliceHexEscapeLower(&constraint_in6.ip.sa.addr),
                    });
                    for (constraint_in6.mask) |mask, i| {
                        if (ip.in6.sa.addr[i] & mask != constraint_in6.ip.sa.addr[i] & mask) {
                            return false;
                        }
                    }
                    return true;
                },
                else => return false,
            }
        },
        else => return false,
    }
}

const testing = std.testing;

test "matchIpConstraint" {
    testing.log_level = .debug;

    const f = struct {
        fn f(
            want: bool,
            ip_str: []const u8,
            constraint_ip_str: []const u8,
            constraint_mask_bytes: []const u8,
        ) !void {
            const ip = try std.net.Address.parseIp(ip_str, 0);
            const constraint_ip = try std.net.Address.parseIp(constraint_ip_str, 0);
            const constraint = switch (constraint_ip.any.family) {
                os.AF.INET => netx.IpAddressNet{
                    .in = .{ .ip = constraint_ip.in, .mask = constraint_mask_bytes[0..4].* },
                },
                os.AF.INET6 => netx.IpAddressNet{
                    .in6 = .{ .ip = constraint_ip.in6, .mask = constraint_mask_bytes[0..16].* },
                },
                else => unreachable,
            };
            try testing.expectEqual(want, try matchIpConstraint(ip, constraint));
        }
    }.f;

    try f(true, "192.0.2.1", "192.0.2.0", "\xff\xff\xff\x80");
    try f(false, "192.0.2.128", "192.0.2.0", "\xff\xff\xff\x80");
    try f(true, "2001:db8::1", "2001:db8::0", "\xff" ** 8 ++ "\x80" ++ "\x00" ** 7);
    try f(false, "2001:db8:0:0:8000::1", "2001:db8::0", "\xff" ** 8 ++ "\x80" ++ "\x00" ** 7);
}

fn matchDomainConstraint(
    allocator: mem.Allocator,
    domain: []const u8,
    constraint: []const u8,
) !bool {
    // The meaning of zero length constraints is not specified, but this
    // code follows NSS and accepts them as matching everything.
    if (constraint.len == 0) {
        return true;
    }

    var domain_labels = domainToReverseLabels(allocator, domain) catch return error.InternalError;
    defer memx.freeElemsAndFreeSlice([]const u8, domain_labels, allocator);

    // RFC 5280 says that a leading period in a domain name means that at
    // least one label must be prepended, but only for URI and email
    // constraints, not DNS constraints. The code also supports that
    // behaviour for DNS constraints.
    const must_have_subdomains = constraint[0] == '.';
    var constraint_labels = domainToReverseLabels(
        allocator,
        if (constraint[0] == '.') constraint[1..] else constraint,
    ) catch return error.InternalError;
    defer memx.freeElemsAndFreeSlice([]const u8, constraint_labels, allocator);

    if ((domain_labels.len < constraint_labels.len) or
        (must_have_subdomains and domain_labels.len == constraint_labels.len))
    {
        return false;
    }

    for (constraint_labels) |constraint_label, i| {
        if (!ascii.eqlIgnoreCase(constraint_label, domain_labels[i])) {
            return false;
        }
    }
    return true;
}

// domainToReverseLabels converts a textual domain name like foo.example.com to
// the list of labels in reverse order, e.g. ["com", "example", "foo"].
pub fn domainToReverseLabels(allocator: mem.Allocator, domain: []const u8) ![][]const u8 {
    var reverse_labels = std.ArrayListUnmanaged([]const u8){};
    errdefer memx.freeElemsAndDeinitArrayList([]const u8, &reverse_labels, allocator);
    var rest = domain;
    while (rest.len > 0) {
        if (mem.lastIndexOfScalar(u8, rest, '.')) |i| {
            try reverse_labels.append(allocator, try allocator.dupe(u8, rest[i + 1 ..]));
            rest = rest[0..i];
        } else {
            try reverse_labels.append(allocator, try allocator.dupe(u8, rest));
            break;
        }
    }

    if (reverse_labels.items.len > 0 and reverse_labels.items[0].len == 0) {
        // An empty label at the end indicates an absolute value.
        return error.InvalidDomain;
    }

    for (reverse_labels.items) |label| {
        if (label.len == 0) {
            // Empty labels are otherwise invalid.
            return error.InvalidDomain;
        }

        for (label) |c| {
            if (c < 33 or c > 126) {
                // Invalid character.
                return error.InvalidDomain;
            }
        }
    }

    return reverse_labels.toOwnedSlice(allocator);
}

test "uri.parse" {
    const uri = @import("uri");

    var u = try uri.parse("https://[2001:db8::1]:8443/foo");
    try testing.expectEqualStrings("https", u.scheme.?);
    try testing.expectEqualStrings("[2001:db8::1]", u.host.?);
    try testing.expectEqual(@as(u16, 8443), u.port.?);
    try testing.expectEqualStrings("/foo", u.path);
}
