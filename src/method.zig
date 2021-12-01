const std = @import("std");
const isTokenChar = @import("token_char.zig").isTokenChar;

pub const MethodType = enum(u4) {
    // https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-semantics-19#section-9
    get,
    head,
    post,
    put,
    delete,
    connect,
    options,
    trace,

    custom,
};

pub const Method = union(MethodType) {
    get: void,
    head: void,
    post: void,
    put: void,
    delete: void,
    connect: void,
    options: void,
    trace: void,
    custom: []const u8,

    const Error = error{
        InvalidInput,
    };

    pub fn toBytes(self: Method) []const u8 {
        return switch (self) {
            .get => "GET",
            .head => "HEAD",
            .post => "POST",
            .put => "PUT",
            .delete => "DELETE",
            .connect => "CONNECT",
            .options => "OPTIONS",
            .trace => "TRACE",
            .custom => |name| name,
        };
    }

    // caller owns the memory for `value`.
    pub fn custom(value: []const u8) Error!Method {
        for (value) |char| {
            if (!isTokenChar(char)) {
                return error.InvalidInput;
            }
        }
        return Method{ .custom = value };
    }

    pub fn fromBytes(value: []const u8) Error!Method {
        switch (value.len) {
            3 => {
                if (std.mem.eql(u8, value, "GET")) return .get;
                if (std.mem.eql(u8, value, "PUT")) return .put;
            },
            4 => {
                if (std.mem.eql(u8, value, "HEAD")) return .head;
                if (std.mem.eql(u8, value, "POST")) return .post;
            },
            5 => {
                if (std.mem.eql(u8, value, "TRACE")) return .trace;
            },
            6 => {
                if (std.mem.eql(u8, value, "DELETE")) return .delete;
            },
            7 => {
                if (std.mem.eql(u8, value, "CONNECT")) return .connect;
                if (std.mem.eql(u8, value, "OPTIONS")) return .options;
            },
            else => {},
        }
        return try Method.custom(value);
    }
};

const testing = std.testing;

test "Convert to Text" {
    try testing.expectEqualStrings((Method{ .get = undefined }).toBytes(), "GET");
    try testing.expectEqualStrings((Method{ .head = undefined }).toBytes(), "HEAD");
    try testing.expectEqualStrings((Method{ .post = undefined }).toBytes(), "POST");
    try testing.expectEqualStrings((Method{ .put = undefined }).toBytes(), "PUT");
    try testing.expectEqualStrings((Method{ .delete = undefined }).toBytes(), "DELETE");
    try testing.expectEqualStrings((Method{ .options = undefined }).toBytes(), "OPTIONS");
    try testing.expectEqualStrings((Method{ .connect = undefined }).toBytes(), "CONNECT");
    try testing.expectEqualStrings((Method{ .trace = undefined }).toBytes(), "TRACE");
    try testing.expectEqualStrings((Method{ .custom = "PURGE_ALL" }).toBytes(), "PURGE_ALL");
}

test "FromText - Success" {
    try testing.expectEqual(Method.get, try Method.fromBytes("GET"));
    try testing.expectEqual(Method.head, try Method.fromBytes("HEAD"));
    try testing.expectEqual(Method.post, try Method.fromBytes("POST"));
    try testing.expectEqual(Method.put, try Method.fromBytes("PUT"));
    try testing.expectEqual(Method.delete, try Method.fromBytes("DELETE"));
    try testing.expectEqual(Method.options, try Method.fromBytes("OPTIONS"));
    try testing.expectEqual(Method.connect, try Method.fromBytes("CONNECT"));
    try testing.expectEqual(Method.trace, try Method.fromBytes("TRACE"));
    try testing.expectEqualStrings("PURGE_ALL", (try Method.fromBytes("PURGE_ALL")).custom);
}

test "FromText - Invalid character" {
    try testing.expectError(error.InvalidInput, Method.fromBytes("PURGE\r\nALL"));
    try testing.expectError(error.InvalidInput, Method.fromBytes("PURGE ALL"));
}
