const std = @import("std");
const mem = std.mem;
const Datetime = @import("datetime").datetime.Datetime;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const CertificateChain = @import("certificate_chain.zig").CertificateChain;

pub const ClientSessionState = struct {
    session_ticket: []const u8 = "",
    ver: ProtocolVersion = undefined,
    cipher_suite: CipherSuiteId = undefined,
    master_secret: []const u8 = "",
    server_certificates: []*CertificateChain = &.{},
    verified_chains: [][]*CertificateChain = &.{},
    received_at: Datetime = undefined,
    ocsp_response: []const u8 = "",
    scts: [][]const u8 = &.{},

    // TLS 1.3 fields
    nonce: []const u8 = "",
    used_by: ?Datetime = null,
    age_add: u32 = 0,

    pub fn deinit(self: *ClientSessionState, allocator: mem.Allocator) void {
        if (self.session_ticket.len > 0) allocator.free(self.session_ticket);
        if (self.master_secret.len > 0) allocator.free(self.master_secret);
        if (self.server_certificates.len > 0) {
            for (self.server_certificates) |cert| cert.deinit(allocator);
            allocator.free(self.server_certificates);
        }
        if (self.verified_chains.len > 0) {
            for (self.verified_chains) |chain| {
                for (chain) |cert| cert.deinit(allocator);
                allocator.free(chain);
            }
            allocator.free(self.verified_chains);
        }
        if (self.ocsp_response.len > 0) allocator.free(self.ocsp_response);
        if (self.scts.len > 0) {
            for (self.scts) |sct| allocator.free(sct);
            allocator.free(self.scts);
        }
        if (self.nonce.len > 0) allocator.free(self.nonce);
    }
};

const LruSessionCache = struct {
    const Self = @This();
    pub const Queue = std.TailQueue(ClientSessionState);
    pub const Node = Queue.Node;
    // It is safe to use Node instead of *Node here
    // because this Map is never expanded from the initial capacity.
    pub const Map = std.StringHashMap(Node);
    pub const default_capacity = 64;
    map: Map,
    queue: Queue,
    capacity: Map.Size,

    pub fn init(allocator: mem.Allocator, capacity: ?Map.Size) !Self {
        const cap = capacity orelse default_capacity;
        var cache = Self{
            .map = Map.init(allocator),
            .queue = .{},
            .capacity = cap,
        };
        errdefer cache.deinit();
        try cache.map.ensureTotalCapacity(cap);
        return cache;
    }

    pub fn deinit(self: *Self) void {
        var it = self.map.valueIterator();
        while (it.next()) |value_ptr| {
            self.removeHelper(value_ptr);
        }
        self.map.deinit();
    }

    // LruSessionCache take ownership of cs.
    // cs must be created with the allocator which was passed to init.
    pub fn put(self: *Self, session_key: []const u8, cs: ClientSessionState) !void {
        var result = try self.map.getOrPut(session_key);
        if (result.found_existing) {
            self.queue.remove(result.value_ptr);
            self.removeHelper(result.value_ptr);
            try self.putHelper(result, cs);
            return;
        }

        if (self.queue.len < self.capacity) {
            try self.putHelper(result, cs);
            return;
        }

        const oldest_value_ptr = self.queue.pop().?;
        const map_index = self.getMapIndexFromValuePtr(oldest_value_ptr);
        const oldest_key = self.getMapKeys()[map_index];
        self.removeHelper(oldest_value_ptr);
        _ = self.map.remove(oldest_key);
        try self.putHelper(result, cs);
    }

    pub fn remove(self: *Self, session_key: []const u8) void {
        if (self.map.get(session_key)) |*node_ptr| {
            _ = self.map.remove(session_key);
            self.queue.remove(node_ptr);
            self.removeHelper(node_ptr);
        }
    }

    // LruSessionCache owns the memory for the returned value.
    pub fn get(self: *Self, session_key: []const u8) ?ClientSessionState {
        if (self.map.get(session_key)) |*node_ptr| {
            self.queue.remove(node_ptr);
            self.queue.prepend(node_ptr);
            return node_ptr.data;
        } else {
            return null;
        }
    }

    fn putHelper(
        self: *Self,
        result: Map.GetOrPutResult,
        cs: ClientSessionState,
    ) !void {
        result.value_ptr.* = .{
            .data = cs,
        };
        self.queue.prepend(result.value_ptr);
    }

    fn removeHelper(self: *Self, node: *Node) void {
        const allocator = self.map.allocator;
        node.data.deinit(allocator);
    }

    const MapHeader = packed struct {
        values: [*]Node,
        keys: [*][]const u8,
        capacity: Map.Size,
    };

    fn getMapHeader(self: *const Self) *MapHeader {
        return @ptrCast(*MapHeader, @ptrCast([*]MapHeader, self.map.unmanaged.metadata.?) - 1);
    }

    fn getMapKeys(self: *const Self) [*][]const u8 {
        return self.getMapHeader().keys;
    }

    fn getMapValues(self: *const Self) [*]Node {
        return self.getMapHeader().values;
    }

    fn getMapIndexFromValuePtr(self: *const Self, value_ptr: *const Node) usize {
        return (@ptrToInt(value_ptr) - @ptrToInt(self.getMapValues())) / @sizeOf(Node);
    }
};

const testing = std.testing;

test "ClientSessionState" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    var s = ClientSessionState{
        .ver = .v1_3,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .received_at = Datetime.now(),
    };
    defer s.deinit(allocator);
    std.log.debug("state={}", .{s});
}

test "LruSessionCache" {
    testing.log_level = .debug;
    const allocator = testing.allocator;
    var cache = try LruSessionCache.init(allocator, 2);
    defer cache.deinit();

    {
        var ticket1 = try allocator.dupe(u8, "ticket1");
        errdefer allocator.free(ticket1);
        try cache.put("key1", .{
            .session_ticket = ticket1,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        });
    }

    {
        var ticket2 = try allocator.dupe(u8, "ticket2");
        errdefer allocator.free(ticket2);
        try cache.put("key1", .{
            .session_ticket = ticket2,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        });
    }

    {
        var ticket3 = try allocator.dupe(u8, "ticket3");
        errdefer allocator.free(ticket3);
        try cache.put("key2", .{
            .session_ticket = ticket3,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        });
    }

    var cs = cache.get("key2");
    std.log.debug("cs for key2={}", .{cs});
    try testing.expect(cs != null);

    {
        var ticket3 = try allocator.dupe(u8, "ticket3");
        errdefer allocator.free(ticket3);
        try cache.put("key2", .{
            .session_ticket = ticket3,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        });
    }

    {
        var ticket3 = try allocator.dupe(u8, "ticket3");
        errdefer allocator.free(ticket3);
        try cache.put("key3", .{
            .session_ticket = ticket3,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        });
    }

    {
        var ticket3 = try allocator.dupe(u8, "ticket3");
        errdefer allocator.free(ticket3);
        try cache.put("key4", .{
            .session_ticket = ticket3,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        });
    }

    cs = cache.get("key2");
    try testing.expect(cs == null);

    cache.remove("key1");
}
