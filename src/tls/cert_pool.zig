const std = @import("std");
const mem = std.mem;
const x509 = @import("x509.zig");
const pem = @import("pem.zig");
const memx = @import("../memx.zig");

pub const CertPool = struct {
    const StringIndexListMap = std.StringHashMap(std.ArrayListUnmanaged(usize));
    const Sha224 = std.crypto.hash.sha2.Sha224;

    allocator: mem.Allocator,
    by_name: StringIndexListMap,
    certs: std.ArrayListUnmanaged(x509.Certificate),
    have_sum: std.BufSet,
    system_pool: bool,

    pub fn init(allocator: mem.Allocator, system_pool: bool) !CertPool {
        const by_name = StringIndexListMap.init(allocator);
        errdefer by_name.deinit();
        const have_sum = std.BufSet.init(allocator);
        errdefer have_sum.deinit();
        return CertPool{
            .allocator = allocator,
            .by_name = by_name,
            .certs = std.ArrayListUnmanaged(x509.Certificate){},
            .have_sum = have_sum,
            .system_pool = system_pool,
        };
    }

    pub fn deinit(self: *CertPool) void {
        const allocator = self.allocator;
        while (true) {
            if (self.by_name.iterator().next()) |*entry| {
                entry.value_ptr.deinit(allocator);
                _ = self.by_name.remove(entry.key_ptr.*);
            } else {
                break;
            }
        }
        self.by_name.deinit();
        memx.deinitArrayListAndElems(x509.Certificate, &self.certs, self.allocator);
        self.have_sum.deinit();
    }

    pub fn len(self: *const CertPool) usize {
        return self.by_name.count();
    }

    pub fn appendCertsFromPem(self: *CertPool, pem_certs: []const u8) !void {
        const allocator = self.allocator;

        var offset: usize = 0;
        while (offset < pem_certs.len) {
            var block = try pem.Block.decode(allocator, pem_certs, &offset);
            defer block.deinit(allocator);
            if (!mem.eql(u8, block.label, pem.Block.certificate_label)) {
                continue;
            }

            var cert = try x509.Certificate.parse(allocator, block.bytes);
            try self.addCert(&cert);
        }
    }

    // ownership of cert is transferred to self.
    pub fn addCert(self: *CertPool, cert: *x509.Certificate) !void {
        var sum: [Sha224.digest_length]u8 = undefined;
        Sha224.hash(cert.raw, &sum, .{});
        if (self.have_sum.contains(&sum)) {
            std.log.debug("CertPool.addCert sum already contained", .{});
            cert.deinit(self.allocator);
            return;
        }

        const index = blk: {
            errdefer cert.deinit(self.allocator);

            try self.have_sum.insert(&sum);

            const i = self.certs.items.len;
            try self.certs.append(self.allocator, cert.*);
            break :blk i;
        };

        errdefer {
            self.certs.items[index].deinit(self.allocator);
            self.certs.resize(self.allocator, index) catch unreachable;
        }
        var gop = try self.by_name.getOrPut(cert.raw_subject);
        if (!gop.found_existing) {
            var indexes = std.ArrayListUnmanaged(usize){};
            gop.value_ptr.* = indexes;
        }
        try gop.value_ptr.*.append(self.allocator, index);
    }

    pub fn contains(self: *const CertPool, cert: *const x509.Certificate) bool {
        var sum: [Sha224.digest_length]u8 = undefined;
        Sha224.hash(cert.raw, &sum, .{});
        return self.have_sum.contains(&sum);
    }

    pub const FindPotentialParentsError = error{
        OutOfMemory,
    };

    // findPotentialParents returns the indexes of certificates in self which might
    // have signed cert.
    pub fn findPotentialParents(
        self: *const CertPool,
        cert: *const x509.Certificate,
        allocator: mem.Allocator,
    ) FindPotentialParentsError![]*const x509.Certificate {
        // consider all candidates where cert.Issuer matches cert.Subject.
        // when picking possible candidates the list is built in the order
        // of match plausibility as to save cycles in buildChains:
        //   AKID and SKID match
        //   AKID present, SKID missing / AKID missing, SKID present
        //   AKID and SKID don't match
        var matching_key_id = std.ArrayListUnmanaged(*const x509.Certificate){};
        defer matching_key_id.deinit(allocator);
        var one_key_id = std.ArrayListUnmanaged(*const x509.Certificate){};
        defer one_key_id.deinit(allocator);
        var mismatch_key_id = std.ArrayListUnmanaged(*const x509.Certificate){};
        defer mismatch_key_id.deinit(allocator);
        if (self.by_name.get(cert.raw_issuer)) |index_list| {
            for (index_list.items) |i| {
                const candidate = &self.certs.items[i];
                if (mem.eql(u8, candidate.subject_key_id, cert.authority_key_id)) {
                    try matching_key_id.append(allocator, candidate);
                } else if ((candidate.subject_key_id.len == 0 and cert.authority_key_id.len > 0) or
                    (candidate.subject_key_id.len > 0 and cert.authority_key_id.len == 0))
                {
                    try one_key_id.append(allocator, candidate);
                } else {
                    try mismatch_key_id.append(allocator, candidate);
                }
            }
        }
        const found = matching_key_id.items.len + one_key_id.items.len + mismatch_key_id.items.len;
        if (found == 0) {
            return &[_]*const x509.Certificate{};
        }
        var candidates = try std.ArrayListUnmanaged(*const x509.Certificate).initCapacity(
            allocator,
            found,
        );
        try candidates.appendSlice(allocator, matching_key_id.items);
        try candidates.appendSlice(allocator, one_key_id.items);
        try candidates.appendSlice(allocator, mismatch_key_id.items);
        return candidates.toOwnedSlice(allocator);
    }

    pub fn subjects(
        self: *const CertPool,
        allocator: mem.Allocator,
    ) ![]const []const u8 {
        var ret = try allocator.alloc([]const u8, self.by_name.count());
        var i: usize = 0;
        errdefer memx.freeElemsAndFreeSliceInError([]const u8, ret, allocator, i);
        var it = self.by_name.keyIterator();
        while (it.next()) |name| {
            ret[i] = try allocator.dupe(u8, name.*);
            i += 1;
        }
        return ret;
    }
};

const testing = std.testing;

test "CertPool" {
    testing.log_level = .debug;

    const allocator = testing.allocator;

    var pool = try CertPool.init(allocator, true);
    defer pool.deinit();

    try testing.expectEqual(@as(usize, 0), pool.len());

    const max_bytes = 1024 * 1024 * 1024;
    const pem_certs = try std.fs.cwd().readFileAlloc(
        allocator,
        "/etc/ssl/certs/ca-certificates.crt",
        max_bytes,
    );
    defer allocator.free(pem_certs);

    try pool.appendCertsFromPem(pem_certs);

    var subjects = try pool.subjects(allocator);
    defer memx.freeElemsAndFreeSlice([]const u8, subjects, allocator);
    // for (subjects) |subject| {
    //     std.log.debug("subject={s}", .{subject});
    // }
}
