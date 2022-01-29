const std = @import("std");
const mem = std.mem;
const memx = @import("../memx.zig");
const domainToReverseLabels = @import("verify.zig").domainToReverseLabels;

// Rfc2821Mailbox represents a “mailbox” (which is an email address to most
// people) by breaking it into the “local” (i.e. before the '@') and “domain”
// parts.
pub const Rfc2821Mailbox = struct {
    local: []const u8 = "",
    domain: []const u8 = "",

    pub fn deinit(self: *Rfc2821Mailbox, allocator: mem.Allocator) void {
        if (self.local.len > 0) allocator.free(self.local);
        if (self.domain.len > 0) allocator.free(self.domain);
    }

    // parse parses an email address into local and domain parts,
    // based on the ABNF for a “Mailbox” from RFC 2821. According to RFC 5280,
    // Section 4.2.1.6 that's correct for an rfc822Name from a certificate: “The
    // format of an rfc822Name is a "Mailbox" as defined in RFC 2821, Section 4.1.2”.
    pub fn parse(allocator: mem.Allocator, input: []const u8) !Rfc2821Mailbox {
        var in = input;
        if (in.len == 0) {
            return error.InvalidMailbox;
        }
        var local_part = try std.ArrayListUnmanaged(u8).initCapacity(allocator, in.len / 2);
        errdefer local_part.deinit(allocator);

        if (in[0] == '"') {
            // Quoted-string = DQUOTE *qcontent DQUOTE
            // non-whitespace-control = %d1-8 / %d11 / %d12 / %d14-31 / %d127
            // qcontent = qtext / quoted-pair
            // qtext = non-whitespace-control /
            //         %d33 / %d35-91 / %d93-126
            // quoted-pair = ("\" text) / obs-qp
            // text = %d1-9 / %d11 / %d12 / %d14-127 / obs-text
            //
            // (Names beginning with “obs-” are the obsolete syntax from RFC 2822,
            // Section 4. Since it has been 16 years, we no longer accept that.)
            in = in[1..];
            while (true) {
                if (in.len == 0) {
                    return error.InvalidMailbox;
                }
                const c = in[0];
                in = in[1..];
                if (c == '"') {
                    break;
                } else if (c == '\\') {
                    // quoted-pair
                    if (in.len == 0) {
                        return error.InvalidMailbox;
                    }
                    if (in[0] == 11 or in[0] == 12 or
                        (1 <= in[0] and in[0] <= 9) or
                        (14 <= in[0] and in[0] <= 127))
                    {
                        try local_part.append(allocator, in[0]);
                        in = in[1..];
                    } else {
                        return error.InvalidMailbox;
                    }
                } else if (c == 11 or c == 12 or
                    // Space (char 32) is not allowed based on the
                    // BNF, but RFC 3696 gives an example that
                    // assumes that it is. Several “verified”
                    // errata continue to argue about this point.
                    // We choose to accept it.
                    c == 32 or c == 33 or c == 127 or
                    (1 <= c and c <= 8) or
                    (14 <= c and c <= 31) or
                    (35 <= c and c <= 91) or
                    (93 <= c and c <= 126))
                {
                    // qtext
                    try local_part.append(allocator, c);
                } else {
                    return error.InvalidMailbox;
                }
            }
        } else {
            // Atom ("." Atom)*
            while (in.len > 0) {
                const c = in[0];
                if (c == '\\') {
                    // Examples given in RFC 3696 suggest that
                    // escaped characters can appear outside of a
                    // quoted string. Several “verified” errata
                    // continue to argue the point. We choose to
                    // accept it.
                    in = in[1..];
                    if (in.len == 0) {
                        return error.InvalidMailbox;
                    }
                }
                if (('0' <= c and c <= '9') or
                    ('a' <= c and c <= 'z') or
                    ('A' <= c and c <= 'Z') or
                    c == '!' or c == '#' or c == '$' or c == '%' or
                    c == '&' or c == '\'' or c == '*' or c == '+' or
                    c == '-' or c == '/' or c == '=' or c == '?' or
                    c == '^' or c == '_' or c == '`' or c == '{' or
                    c == '|' or c == '}' or c == '~' or c == '.')
                {
                    try local_part.append(allocator, in[0]);
                    in = in[1..];
                } else {
                    break;
                }
            }
        }

        if (in.len == 0 or in[0] != '@') {
            return error.InvalidMailbox;
        }
        in = in[1..];

        // The RFC species a format for domains, but that's known to be
        // violated in practice so we accept that anything after an '@' is the
        // domain part.
        if (domainToReverseLabels(allocator, in)) |reverse_labels| {
            memx.freeElemsAndFreeSlice([]const u8, reverse_labels, allocator);
        } else |_| {
            return error.InvalidMailbox;
        }

        return Rfc2821Mailbox{
            .local = local_part.toOwnedSlice(allocator),
            .domain = try allocator.dupe(u8, in),
        };
    }
};
