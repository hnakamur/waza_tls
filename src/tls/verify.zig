const std = @import("std");
const ascii = std.ascii;
const mem = std.mem;
const os = std.os;
const TimestampSeconds = @import("../timestamp.zig").TimestampSeconds;
const fmtx = @import("../fmtx.zig");
const memx = @import("../memx.zig");
const netx = @import("../netx.zig");
const Uri = @import("../urix.zig").Uri;
const asn1 = @import("asn1.zig").Uri;
const x509 = @import("x509.zig");
const Rfc2821Mailbox = @import("mailbox.zig").Rfc2821Mailbox;
const CertPool = @import("cert_pool.zig").CertPool;

pub const VerifyOptions = struct {
    dns_name: []const u8 = "",
    intermediates: ?*const CertPool = null,
    roots: *const CertPool,
    current_time: ?TimestampSeconds = null,
    key_usages: []const x509.ExtKeyUsage = &[_]x509.ExtKeyUsage{},
    max_constraint_comparisons: ?usize = null,
};

pub const VerifiedCertChains = struct {
    // `chains` does not have ownership of `Certificates`.
    chains: []const []*const x509.Certificate,

    pub fn init(chains: []const []*const x509.Certificate) VerifiedCertChains {
        return .{ .chains = chains };
    }

    pub fn deinit(self: *VerifiedCertChains, allocator: mem.Allocator) void {
        for (self.chains) |chain| {
            allocator.free(chain);
        }
        allocator.free(self.chains);
    }
};

pub fn verifyEmailSan(
    c: *const x509.Certificate,
    allocator: mem.Allocator,
    count: *usize,
    max_constraint_comparisons: usize,
    san_der: []const u8,
) !void {
    const email = san_der;
    var mailbox = try Rfc2821Mailbox.parse(allocator, email);
    defer mailbox.deinit(allocator);

    try checkNameConstraints(
        allocator,
        count,
        max_constraint_comparisons,
        Rfc2821Mailbox,
        mailbox,
        []const u8,
        matchEmailConstraint,
        c.permitted_email_addresses,
        c.excluded_email_addresses,
    );
}

pub fn verifyDnsSan(
    c: *const x509.Certificate,
    allocator: mem.Allocator,
    count: *usize,
    max_constraint_comparisons: usize,
    san_der: []const u8,
) !void {
    const name = san_der;
    if (domainToReverseLabels(allocator, name)) |reverse_labels| {
        memx.freeElemsAndFreeSlice([]const u8, reverse_labels, allocator);
    } else |_| {
        return error.CannotParseDnsName;
    }

    try checkNameConstraints(
        allocator,
        count,
        max_constraint_comparisons,
        []const u8,
        name,
        []const u8,
        matchDomainConstraint,
        c.permitted_dns_domains,
        c.excluded_dns_domains,
    );
}

pub fn verifyUriSan(
    c: *const x509.Certificate,
    allocator: mem.Allocator,
    count: *usize,
    max_constraint_comparisons: usize,
    san_der: []const u8,
) !void {
    const name = san_der;
    var uri = try Uri.parse(allocator, name);
    defer uri.deinit(allocator);

    try checkNameConstraints(
        allocator,
        count,
        max_constraint_comparisons,
        Uri,
        uri,
        []const u8,
        matchUriConstraint,
        c.permitted_uri_domains,
        c.excluded_uri_domains,
    );
}

pub fn verifyIpSan(
    c: *const x509.Certificate,
    allocator: mem.Allocator,
    count: *usize,
    max_constraint_comparisons: usize,
    san_der: []const u8,
) !void {
    const ip_data = san_der;
    var ip = netx.addressFromBytes(ip_data) catch return error.InvalidIpSan;
    try checkNameConstraints(
        allocator,
        count,
        max_constraint_comparisons,
        std.net.Address,
        ip,
        netx.IpAddressNet,
        matchIpConstraint,
        c.permitted_ip_ranges,
        c.excluded_ip_ranges,
    );
}

// checkNameConstraints checks that c permits a child certificate to claim the
// given name, of type nameType. The argument parsedName contains the parsed
// form of name, suitable for passing to the match function. The total number
// of comparisons is tracked in the given count and should not exceed the given
// limit.
fn checkNameConstraints(
    allocator: mem.Allocator,
    count: *usize,
    max_constraint_comparisons: usize,
    comptime ParsedNameType: type,
    parsed_name: ParsedNameType,
    comptime ConstraintType: type,
    match: fn (
        allocator: mem.Allocator,
        parse_name: ParsedNameType,
        constraint: ConstraintType,
    ) anyerror!bool,
    permitted: []const ConstraintType,
    excluded: []const ConstraintType,
) !void {
    count.* += excluded.len;
    if (count.* > max_constraint_comparisons) {
        return error.InvalidCertificate;
    }
    for (excluded) |constraint| {
        if (match(allocator, parsed_name, constraint)) |matched| {
            if (matched) {
                return error.InvalidCertificate;
            }
        } else |_| {
            return error.InvalidCertificate;
        }
    }

    count.* += permitted.len;
    if (count.* > max_constraint_comparisons) {
        return error.InvalidCertificate;
    }
    for (permitted) |constraint| {
        if (match(allocator, parsed_name, constraint)) |matched| {
            if (matched) {
                return;
            }
        } else |_| {
            return error.InvalidCertificate;
        }
    }
    return error.InvalidCertificate;
}

fn matchEmailConstraint(
    allocator: mem.Allocator,
    mailbox: Rfc2821Mailbox,
    constraint: []const u8,
) !bool {
    // If the constraint contains an @, then it specifies an exact mailbox
    // name.
    if (memx.containsScalar(u8, constraint, '@')) {
        if (Rfc2821Mailbox.parse(allocator, constraint)) |*constraint_mailbox| {
            defer constraint_mailbox.deinit(allocator);
            return mem.eql(u8, mailbox.local, constraint_mailbox.local) and
                ascii.eqlIgnoreCase(mailbox.domain, constraint_mailbox.domain);
        } else |_| {
            return error.CannotParseEmailConstraint;
        }
    }

    // Otherwise the constraint is like a DNS constraint of the domain part
    // of the mailbox.
    return try matchDomainConstraint(allocator, mailbox.domain, constraint);
}

fn matchUriConstraint(
    allocator: mem.Allocator,
    uri: Uri,
    constraint: []const u8,
) !bool {
    // From RFC 5280, Section 4.2.1.10:
    // “a uniformResourceIdentifier that does not include an authority
    // component with a host name specified as a fully qualified domain
    // name (e.g., if the URI either does not include an authority
    // component or includes an authority component in which the host name
    // is specified as an IP address), then the application MUST reject the
    // certificate.”
    if (uri.components.host) |host| {
        if ((mem.startsWith(u8, host, "[") and mem.endsWith(u8, host, "]")) or
            parsableAsIpAddress(host))
        {
            return error.CannotMatchUriConstraintForIpAddress;
        }
        return try matchDomainConstraint(allocator, host, constraint);
    } else return error.CannotMatchUriConstraintForEmptyHostUri;
}

fn parsableAsIpAddress(address: []const u8) bool {
    return if (std.net.Address.parseIp(address, 0)) |_| true else |_| false;
}

fn matchIpConstraint(
    allocator: mem.Allocator,
    ip: std.net.Address,
    constraint: netx.IpAddressNet,
) !bool {
    _ = allocator;
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

pub fn validHostnamePattern(host: []const u8) bool {
    return validHostname(host, true);
}

pub fn validHostnameInput(host: []const u8) bool {
    return validHostname(host, false);
}

// validHostname reports whether host is a valid hostname that can be matched or
// matched against according to RFC 6125 2.2, with some leniency to accommodate
// legacy values.
fn validHostname(host: []const u8, is_pattern: bool) bool {
    const host2 = if (is_pattern) host else mem.trimRight(u8, host, ".");
    if (host2.len == 0) {
        return false;
    }

    var it = mem.split(u8, host2, ".");
    var i: usize = 0;
    while (true) : (i += 1) {
        const part = if (it.next()) |p| p else break;
        if (part.len == 0) {
            // Empty label.
            return false;
        }
        if (is_pattern and i == 0 and mem.eql(u8, part, "*")) {
            // Only allow full left-most wildcards, as those are the only ones
            // we match, and matching literal '*' characters is probably never
            // the expected behavior.
            continue;
        }
        for (part) |c, j| {
            switch (c) {
                'a'...'z', '0'...'9', 'A'...'Z' => continue,
                '-' => if (j != 0) continue,
                '_' => {
                    // Not a valid character in hostnames, but commonly
                    // found in deployments outside the WebPKI.
                    continue;
                },
                else => {},
            }
            return false;
        }
    }
    return true;
}

pub fn matchExactly(host_a: []const u8, host_b: []const u8) bool {
    if (host_a.len == 0 or mem.eql(u8, host_a, ".") or host_b.len == 0 or mem.eql(u8, host_b, ".")) {
        return false;
    }
    return ascii.eqlIgnoreCase(host_a, host_b);
}

pub fn matchHostnames(pattern: []const u8, host: []const u8) bool {
    if (pattern.len == 0 or host.len == 0) {
        return false;
    }

    var pattern_it = mem.split(u8, pattern, ".");
    var host_it = mem.split(u8, host, ".");
    var i: usize = 0;
    while (true) : (i += 1) {
        const pattern_part = pattern_it.next();
        const host_part = host_it.next();
        if (pattern_part == null and host_part == null) {
            return true;
        } else if (pattern_part == null or host_part == null) {
            return false;
        }

        if (i == 0 and mem.eql(u8, pattern_part.?, "*")) {
            continue;
        }
        if (!ascii.eqlIgnoreCase(pattern_part.?, host_part.?)) {
            return false;
        }
    }
}

pub fn checkChainForKeyUsage(
    allocator: mem.Allocator,
    chain: []*const x509.Certificate,
    key_usages: []const x509.ExtKeyUsage,
) !bool {
    if (chain.len == 0) {
        return false;
    }

    var usages = try allocator.alloc(?x509.ExtKeyUsage, key_usages.len);
    defer allocator.free(usages);
    for (key_usages) |usage, i| {
        usages[i] = usage;
    }

    // We walk down the list and cross out any usages that aren't supported
    // by each certificate. If we cross out all the usages, then the chain
    // is unacceptable.

    var usages_remaining = key_usages.len;
    var i: usize = 0;
    while (i < chain.len) : (i += 1) {
        const cert = chain[chain.len - 1 - i];
        if (cert.ext_key_usages.len == 0 and cert.unknown_usages.len == 0) {
            // The certificate doesn't have any extended key usage specified.
            continue;
        }

        if (memx.containsScalar(x509.ExtKeyUsage, cert.ext_key_usages, .any)) {
            // The certificate is explicitly good for any usage.
            continue;
        }

        for (usages) |requested_usage, j| {
            if (requested_usage) |req_usage| {
                if (memx.containsScalar(x509.ExtKeyUsage, cert.ext_key_usages, req_usage)) {
                    continue;
                }

                usages[j] = null;
                usages_remaining -= 1;
                if (usages_remaining == 0) {
                    return false;
                }
            } else {
                continue;
            }
        }
    }
    return true;
}

const testing = std.testing;

test "mem.split" {
    var it = mem.split(u8, "abc|def||ghi", "|");
    try testing.expect(mem.eql(u8, it.next().?, "abc"));
    try testing.expect(mem.eql(u8, it.next().?, "def"));
    try testing.expect(mem.eql(u8, it.next().?, ""));
    try testing.expect(mem.eql(u8, it.next().?, "ghi"));
    try testing.expect(it.next() == null);
    try testing.expect(it.rest().len == 0);
}

test "matchIpConstraint" {
    testing.log_level = .err;

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
            const allocator = testing.allocator;
            try testing.expectEqual(want, try matchIpConstraint(allocator, ip, constraint));
        }
    }.f;

    try f(true, "192.0.2.1", "192.0.2.0", "\xff\xff\xff\x80");
    try f(false, "192.0.2.128", "192.0.2.0", "\xff\xff\xff\x80");
    try f(true, "2001:db8::1", "2001:db8::0", "\xff" ** 8 ++ "\x80" ++ "\x00" ** 7);
    try f(false, "2001:db8:0:0:8000::1", "2001:db8::0", "\xff" ** 8 ++ "\x80" ++ "\x00" ** 7);
}

test "uri.parse" {
    const uri = @import("uri");

    var u = try uri.parse("https://[2001:db8::1]:8443/foo");
    try testing.expectEqualStrings("https", u.scheme.?);
    try testing.expectEqualStrings("[2001:db8::1]", u.host.?);
    try testing.expectEqual(@as(u16, 8443), u.port.?);
    try testing.expectEqualStrings("/foo", u.path);

    const host = u.host.?;
    var ip = try std.net.Address.parseIp(mem.trim(u8, host, "[]"), u.port.?);
    var want = std.net.Address.initIp6(
        ("\x20\x01\x0d\xb8" ++ "\x00" ** 11 ++ "\x01")[0..16].*,
        8443,
        0,
        0,
    );
    try testing.expectEqual(want.in6, ip.in6);
}
