const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Field = @import("../fields.zig").Field;

const crlf_crlf = "\r\n\r\n";
const crlf = "\r\n";

pub const FieldsEditor = struct {
    buf: []u8,
    len: usize,
    line_count: usize,
    allocator: *Allocator,

    /// FieldsEditor takes ownership of the passed in slice. The slice must have been
    /// allocated with `allocator`.
    /// Deinitialize with `deinit` or use `toOwnedSlice`.
    pub fn newFromOwnedSlice(allocator: *Allocator, buf: []u8) !FieldsEditor {
        var editor = FieldsEditor{
            .buf = buf,
            .len = 0,
            .line_count = 0,
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

    pub fn lineCount(self: *const FieldsEditor) usize {
        return self.line_count;
    }

    pub fn delete(self: *FieldsEditor, i: usize) !void {
        if (i >= self.line_count) {
            return error.OutOfBounds;
        }
        const pos = self.posForLineIndex(i);
        const next_pos = self.nextLinePos(pos);
        const line_len = next_pos - pos;
        const new_len = self.len - line_len;
        std.mem.copy(u8, self.buf[pos..new_len], self.buf[next_pos..self.len]);
        self.len = new_len;
        self.line_count -= 1;
    }

    pub fn append(self: *FieldsEditor, name: []const u8, value: []const u8) !void {
        const new_capacity = self.len + name.len + ": ".len + value.len + crlf.len;
        try self.ensureTotalCapacity(new_capacity);
        self.len -= crlf.len;
        self.append_bytes(name);
        self.append_bytes(": ");
        self.append_bytes(value);
        self.append_bytes(crlf_crlf);
        self.line_count += 1;
    }

    fn ensureTotalCapacity(self: *FieldsEditor, new_capacity: usize) !void {
        if (self.capacity() < new_capacity) {
            self.buf = try self.allocator.reallocAtLeast(self.buf, new_capacity);
        }
    }

    fn posForLineIndex(self: *const FieldsEditor, line_index: usize) usize {
        var pos: usize = 0;
        var i = line_index;
        while (i > 0) : (i -= 1) {
            pos = self.nextLinePos(pos);
        }
        return pos;
    }

    inline fn nextLinePos(self: *const FieldsEditor, pos: usize) usize {
        return std.mem.indexOfPos(u8, self.buf, pos, crlf).? + crlf.len;
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
    try testing.expectEqual(@as(usize, 0), editor.lineCount());

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "\r\n", editor.view());
    try testing.expectEqual(@as(usize, 1), editor.lineCount());

    try editor.append("Server", "Apache");
    buf = editor.toOwnedSlice();
    defer testing.allocator.free(buf);
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n", buf);
    try testing.expectEqual(@as(usize, 2), editor.lineCount());
}

test "FieldsEditor delete" {
    var buf = try testing.allocator.alloc(u8, 32);
    var editor = try FieldsEditor.newFromOwnedSlice(testing.allocator, buf);
    defer editor.deinit();

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try editor.append("Server", "Apache");
    try editor.append("Vary", "Accept-Encoding");
    try testing.expectEqual(@as(usize, 3), editor.lineCount());

    try editor.delete(1);
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Vary: Accept-Encoding\r\n" ++
        "\r\n", editor.view());
    try testing.expectEqual(@as(usize, 2), editor.lineCount());

    try editor.delete(1);
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "\r\n", editor.view());
    try testing.expectEqual(@as(usize, 1), editor.lineCount());

    try editor.delete(0);
    try testing.expectEqualStrings("\r\n", editor.view());
    try testing.expectEqual(@as(usize, 0), editor.lineCount());
}
