const std = @import("std");
const mem = std.mem;
const Datetime = @import("datetime").datetime.Datetime;
const ProtocolVersion = @import("handshake_msg.zig").ProtocolVersion;
const CipherSuiteId = @import("handshake_msg.zig").CipherSuiteId;
const x509 = @import("x509.zig");

pub const ClientSessionState = struct {
    const AtomicUsize = std.atomic.Atomic(usize);
    ref_count: AtomicUsize = AtomicUsize.init(1),

    session_ticket: []const u8 = "",
    ver: ProtocolVersion = undefined,
    cipher_suite: CipherSuiteId = undefined,
    master_secret: []const u8 = "",
    server_certificates: []x509.Certificate = &.{},
    verified_chains: [][]x509.Certificate = &.{},
    received_at: Datetime = undefined,
    ocsp_response: []const u8 = "",
    scts: []const []const u8 = &.{},

    // TLS 1.3 fields
    nonce: []const u8 = "",
    use_by: ?Datetime = null,
    age_add: u32 = 0,

    pub fn addRef(self: *ClientSessionState) void {
        const old_count = self.ref_count.fetchAdd(1, .SeqCst);
        std.log.warn(
            "ClientSessionState.addRef self=0x{x}, new_count={}",
            .{ @ptrToInt(self), old_count + 1 },
        );
    }

    pub fn decRef(self: *ClientSessionState, allocator: mem.Allocator) void {
        const old_count = self.ref_count.fetchSub(1, .SeqCst);
        std.log.warn(
            "ClientSessionState.decRef self=0x{x}, new_count={}",
            .{ @ptrToInt(self), old_count - 1 },
        );
        if (old_count == 1) {
            self.deinit(allocator);
            allocator.destroy(self);
        }
    }

    pub fn deinit(self: *ClientSessionState, allocator: mem.Allocator) void {
        allocator.free(self.session_ticket);
        allocator.free(self.master_secret);

        for (self.server_certificates) |*cert| cert.deinit(allocator);
        allocator.free(self.server_certificates);

        for (self.verified_chains) |chain| {
            for (chain) |*cert| cert.deinit(allocator);
            allocator.free(chain);
        }
        allocator.free(self.verified_chains);

        allocator.free(self.ocsp_response);

        for (self.scts) |sct| allocator.free(sct);
        allocator.free(self.scts);

        allocator.free(self.nonce);
    }
};

pub const LoadSessionResult = struct {
    cache_key: []const u8 = "",
    session: ?*ClientSessionState = null,
    early_secret: []const u8 = "",
    binder_key: []const u8 = "",

    pub fn deinit(self: *LoadSessionResult, allocator: mem.Allocator) void {
        allocator.free(self.cache_key);
        if (self.session) |session| {
            std.log.warn("LoadSessionResult.deinit decRef cs=0x{x}", .{@ptrToInt(session)});
            session.decRef(allocator);
        }
        allocator.free(self.early_secret);
        allocator.free(self.binder_key);
    }
};

pub const LruSessionCache = struct {
    const Self = @This();
    const Queue = std.TailQueue(*ClientSessionState);
    const Node = Queue.Node;
    // It is safe to use Node instead of *Node here
    // because this Map is never expanded from the initial capacity.
    const Map = std.StringHashMap(Node);
    pub const Size = Map.Size;
    pub const default_capacity = 64;

    map: Map,
    queue: Queue,
    capacity: Size,

    pub fn init(allocator: mem.Allocator, capacity: ?Size) !Self {
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
        std.log.debug("LruSessionCache.deinit self=0x{x}", .{@ptrToInt(self)});
        var it = self.map.iterator();
        while (it.next()) |entry| {
            std.log.warn(
                "LruSessionCache.deinit self=0x{x}, key_ptr.*={s}, value_ptr=0x{x}",
                .{ @ptrToInt(self), entry.key_ptr.*, @ptrToInt(entry.value_ptr) },
            );
            self.map.allocator.free(entry.key_ptr.*);
            self.removeHelper(entry.value_ptr);
        }
        self.map.deinit();
    }

    // LruSessionCache take ownership of cs.
    // cs must be created with the allocator which was passed to init.
    // caller owns session_key.
    pub fn put(self: *Self, session_key: []const u8, cs: *ClientSessionState) !void {
        std.log.warn("LruSessionCache.put start, self=0x{x}, session_key={s}, cs=0x{x}", .{
            @ptrToInt(self),
            session_key,
            @ptrToInt(cs),
        });
        var result = try self.map.getOrPut(session_key);
        if (result.found_existing) {
            if (&result.value_ptr.data.* == cs) {
                std.log.warn("LruSessionCache.put just touch value, self=0x{x}, session_key={s}, cs=0x{x}", .{
                    @ptrToInt(self),
                    session_key,
                    @ptrToInt(cs),
                });
                self.queue.remove(result.value_ptr);
                self.queue.append(result.value_ptr);
                return;
            }
            std.log.warn("LruSessionCache.put found different value, self=0x{x}, session_key={s}, cs=0x{x}", .{
                @ptrToInt(self),
                session_key,
                @ptrToInt(cs),
            });
            self.queue.remove(result.value_ptr);
            self.removeHelper(result.value_ptr);
            try self.putHelper(result, cs);
            return;
        }

        const allocator = self.map.allocator;
        result.key_ptr.* = allocator.dupe(u8, session_key) catch |err| {
            _ = self.map.remove(session_key);
            return err;
        };

        std.log.warn("LruSessionCache.put put new value, self=0x{x}, queue.len={}, capacity={}", .{ @ptrToInt(self), self.queue.len, self.capacity });
        if (self.queue.len < self.capacity) {
            std.log.warn("LruSessionCache.put put new value, self=0x{x}, session_key={s}, cs=0x{x}", .{
                @ptrToInt(self),
                session_key,
                @ptrToInt(cs),
            });
            try self.putHelper(result, cs);
            return;
        }

        const oldest_value_ptr = self.queue.popFirst().?;
        const map_index = self.getMapIndexFromValuePtr(oldest_value_ptr);
        const oldest_key = self.getMapKeys()[map_index];
        std.log.warn("LruSessionCache.put remove oldest, self=0x{x}, oldest_key={s}, cs=0x{x}", .{
            @ptrToInt(self),
            oldest_key,
            @ptrToInt(oldest_value_ptr.data),
        });
        self.removeHelper(oldest_value_ptr);
        const kv = self.map.fetchRemove(oldest_key).?;
        self.map.allocator.free(kv.key);

        try self.putHelper(result, cs);
    }

    pub fn remove(self: *Self, session_key: []const u8) void {
        std.log.warn("LruSessionCache.remove start, self=0x{x}, session_key={s}", .{
            @ptrToInt(self),
            session_key,
        });
        if (self.map.getPtr(session_key)) |node_ptr| {
            std.log.warn("LruSessionCache.remove, self=0x{x}, session_key={s}, removed 0x{x}", .{
                @ptrToInt(self),
                session_key,
                @ptrToInt(node_ptr.data),
            });
            self.queue.remove(node_ptr);
            self.removeHelper(node_ptr);
            const kv = self.map.fetchRemove(session_key).?;
            self.map.allocator.free(kv.key);
            std.log.debug("LruSessionCache.remove, self=0x{x}, session_key={s}, removed queue.len={}", .{
                @ptrToInt(self),
                session_key,
                self.queue.len,
            });
        }
    }

    // LruSessionCache owns the memory for the returned value.
    pub fn getPtr(self: *Self, session_key: []const u8) ?*ClientSessionState {
        if (self.map.getPtr(session_key)) |node_ptr| {
            self.queue.remove(node_ptr);
            self.queue.append(node_ptr);
            std.log.warn("LruSessionCache.getPtr, self=0x{x}, session_key={s}, ret=0x{x}", .{
                @ptrToInt(self),
                session_key,
                @ptrToInt(node_ptr.data),
            });
            node_ptr.data.addRef();
            return node_ptr.data;
        } else {
            std.log.warn("LruSessionCache.getPtr, self=0x{x}, session_key={s}, ret=null", .{
                @ptrToInt(self),
                session_key,
            });
            return null;
        }
    }

    fn putHelper(
        self: *Self,
        result: Map.GetOrPutResult,
        cs: *ClientSessionState,
    ) !void {
        cs.addRef();
        result.value_ptr.data = cs;
        self.queue.append(result.value_ptr);
        std.log.debug("LruSessionCache.putHelper, &node.data=0x{x}, queue.len={}", .{
            @ptrToInt(&result.value_ptr.data),
            self.queue.len,
        });
    }

    fn removeHelper(self: *Self, node: *Node) void {
        const allocator = self.map.allocator;
        std.log.warn("LruSessionCache.removeHelper, node.data=0x{x}", .{@ptrToInt(node.data)});
        node.data.decRef(allocator);
    }

    fn debugLogKeys(self: *const Self) void {
        std.log.debug("LruSessionCache.debugLogKeys start", .{});
        var it = self.queue.first;
        while (it) |node_ptr| : (it = node_ptr.next) {
            const map_index = self.getMapIndexFromValuePtr(node_ptr);
            const key = self.getMapKeys()[map_index];
            std.log.debug("key={s}", .{key});
        }
        std.log.debug("LruSessionCache.debugLogKeys exit", .{});
    }

    const MapHeader = packed struct {
        values: [*]Node,
        keys: [*][]const u8,
        capacity: Size,
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
    testing.log_level = .err;
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
    testing.log_level = .err;
    const allocator = testing.allocator;
    var cache = try LruSessionCache.init(allocator, 2);
    defer cache.deinit();

    {
        var ticket1 = try allocator.dupe(u8, "ticket1");
        errdefer allocator.free(ticket1);
        var value1 = try allocator.create(ClientSessionState);
        value1.* = .{
            .session_ticket = ticket1,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        };
        try cache.put("key1", value1);
        cache.debugLogKeys();
    }

    {
        var ticket2 = try allocator.dupe(u8, "ticket2");
        var value2 = try allocator.create(ClientSessionState);
        value2.* = .{
            .session_ticket = ticket2,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        };
        try cache.put("key1", value2);
        cache.debugLogKeys();
    }

    const value3 = blk: {
        var ticket3 = try allocator.dupe(u8, "ticket3");
        errdefer allocator.free(ticket3);

        var v = try allocator.create(ClientSessionState);
        v.* = ClientSessionState{
            .session_ticket = ticket3,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        };
        break :blk v;
    };

    {
        try cache.put("key2", value3);
        cache.debugLogKeys();
    }

    var cs = cache.getPtr("key1");
    try testing.expect(cs != null);
    std.log.debug("cs for key1={}", .{cs.?.*});
    cs.?.decRef(allocator);
    cache.debugLogKeys();

    {
        std.log.info("put again same value3 with same key2 ===============", .{});
        try cache.put("key2", value3);
        cache.debugLogKeys();
    }

    {
        var ticket4 = try allocator.dupe(u8, "ticket4");
        var value4 = try allocator.create(ClientSessionState);
        value4.* = .{
            .session_ticket = ticket4,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        };
        try cache.put("key3", value4);
        cache.debugLogKeys();
    }

    {
        var ticket5 = try allocator.dupe(u8, "ticket5");
        var value5 = try allocator.create(ClientSessionState);
        value5.* = .{
            .session_ticket = ticket5,
            .ver = .v1_3,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .received_at = Datetime.now(),
        };
        try cache.put("key4", value5);
        cache.debugLogKeys();
    }

    cs = cache.getPtr("key2");
    try testing.expect(cs == null);

    cache.remove("key1");
}
