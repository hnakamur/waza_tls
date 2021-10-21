const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Field = @import("../fields.zig").Field;

const crlf_crlf = "\r\n\r\n";
const crlf = "\r\n";

pub const FieldsEditor = struct {
    buf: []u8,
    len: usize,
    allocator: *Allocator,

    /// FieldsEditor takes ownership of the passed in slice. The slice must have been
    /// allocated with `allocator`.
    /// Deinitialize with `deinit` or use `toOwnedSlice`.
    pub fn newFromOwnedSlice(allocator: *Allocator, buf: []u8) !FieldsEditor {
        var editor = FieldsEditor{
            .buf = buf,
            .len = 0,
            .allocator = allocator,
        };
        const new_capacity = crlf.len;
        try editor.ensureTotalCapacity(new_capacity);
        editor.append_bytes(crlf);
        return editor;
    }

    /// Release all allocated memory.
    pub fn deinit(self: FieldsEditor) void {
        if (self.buf.len > 0) {
            self.allocator.free(self.buf);
        }
    }

    /// The caller owns the returned memory.
    /// This FieldsEditor must not be used after calling `toOwnedSlice`.
    pub fn toOwnedSlice(self: *FieldsEditor) []u8 {
        const allocator = self.allocator;
        const result = allocator.shrink(self.buf, self.len);
        self.buf = &[_]u8{};
        return result;
    }

    /// FieldsEditor owns the returned memory. The returned slice is valid for use
    /// only until the next modification of this FieldsEditor.
    pub fn view(self: *const FieldsEditor) []const u8 {
        return self.buf[0..self.len];
    }

    pub fn append(self: *FieldsEditor, name: []const u8, value: []const u8) !void {
        const new_capacity = self.len + name.len + ": ".len + value.len + crlf.len;
        try self.ensureTotalCapacity(new_capacity);
        self.len -= crlf.len;
        self.append_bytes(name);
        self.append_bytes(": ");
        self.append_bytes(value);
        self.append_bytes(crlf_crlf);
    }

    fn ensureTotalCapacity(self: *FieldsEditor, new_capacity: usize) !void {
        if (self.capacity() < new_capacity) {
            self.buf = try self.allocator.reallocAtLeast(self.buf, new_capacity);
        }
    }

    inline fn capacity(self: *const FieldsEditor) usize {
        return self.buf.len;
    }

    inline fn append_bytes(self: *FieldsEditor, b: []const u8) void {
        std.mem.copy(u8, self.buf[self.len..], b);
        self.len += b.len;
    }
};

const testing = std.testing;

test "FieldsEditor append" {
    var buf = try testing.allocator.alloc(u8, 32);
    var editor = try FieldsEditor.newFromOwnedSlice(testing.allocator, buf);
    defer editor.deinit();
    try testing.expectEqualStrings("\r\n", editor.view());

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "\r\n", editor.view());

    try editor.append("Server", "Apache");
    buf = editor.toOwnedSlice();
    defer testing.allocator.free(buf);
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n", buf);
}
