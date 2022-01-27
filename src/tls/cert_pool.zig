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
        while (true) {
            if (self.by_name.iterator().next()) |*entry| {
                entry.value_ptr.deinit(self.allocator);
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
}
