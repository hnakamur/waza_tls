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

    pub fn toText(self: Method) []const u8 {
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

    pub fn custom(value: []const u8) Error!Method {
        for (value) |char| {
            if (!isTokenChar(char)) {
                return error.InvalidInput;
            }
        }
        return Method{ .custom = value };
    }

    pub fn fromText(value: []const u8) Error!Method {
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
    try testing.expectEqualStrings((Method{ .get = undefined }).toText(), "GET");
    try testing.expectEqualStrings((Method{ .head = undefined }).toText(), "HEAD");
    try testing.expectEqualStrings((Method{ .post = undefined }).toText(), "POST");
    try testing.expectEqualStrings((Method{ .put = undefined }).toText(), "PUT");
    try testing.expectEqualStrings((Method{ .delete = undefined }).toText(), "DELETE");
    try testing.expectEqualStrings((Method{ .options = undefined }).toText(), "OPTIONS");
    try testing.expectEqualStrings((Method{ .connect = undefined }).toText(), "CONNECT");
    try testing.expectEqualStrings((Method{ .trace = undefined }).toText(), "TRACE");
    try testing.expectEqualStrings((Method{ .custom = "PURGE_ALL" }).toText(), "PURGE_ALL");
}

test "FromText - Success" {
    try testing.expectEqual(Method.get, try Method.fromText("GET"));
    try testing.expectEqual(Method.head, try Method.fromText("HEAD"));
    try testing.expectEqual(Method.post, try Method.fromText("POST"));
    try testing.expectEqual(Method.put, try Method.fromText("PUT"));
    try testing.expectEqual(Method.delete, try Method.fromText("DELETE"));
    try testing.expectEqual(Method.options, try Method.fromText("OPTIONS"));
    try testing.expectEqual(Method.connect, try Method.fromText("CONNECT"));
    try testing.expectEqual(Method.trace, try Method.fromText("TRACE"));
    try testing.expectEqualStrings("PURGE_ALL", (try Method.fromText("PURGE_ALL")).custom);
}

test "FromText - Invalid character" {
    try testing.expectError(error.InvalidInput, Method.fromText("PURGE\r\nALL"));
    try testing.expectError(error.InvalidInput, Method.fromText("PURGE ALL"));
}
