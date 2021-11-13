const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Field = @import("field.zig").Field;
const FieldIterator = @import("field_iterator.zig").FieldIterator;

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
        editor.len = editor.insert_bytes(0, crlf);
        return editor;
    }

    /// FieldsEditor takes ownership of the passed in slice. The slice must have been
    /// allocated with `allocator`.
    /// Deinitialize with `deinit` or use `toOwnedSlice`.
    pub fn parseOwnedSlice(allocator: *Allocator, buf: []u8) !FieldsEditor {
        var line_count: usize = 0;
        var it = FieldIterator.init(buf);
        while (it.next()) |_| {
            line_count += 1;
        }
        const len = @ptrToInt(it.rest().ptr) - @ptrToInt(buf.ptr);

        return FieldsEditor{
            .buf = buf,
            .len = len,
            .line_count = line_count,
            .allocator = allocator,
        };
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
    pub fn slice(self: *const FieldsEditor) []const u8 {
        return self.buf[0..self.len];
    }

    /// The field line count without the last empty line.
    pub fn lineCount(self: *const FieldsEditor) usize {
        return self.line_count;
    }

    /// Append a field with `name` and `value`.
    pub fn append(self: *FieldsEditor, name: []const u8, value: []const u8) !void {
        try validateName(name);
        try validateValue(value);

        const new_capacity = self.len + name.len + ": ".len + value.len + crlf.len;
        try self.ensureTotalCapacity(new_capacity);
        var pos = self.insert_bytes(self.len - crlf.len, name);
        pos = self.insert_bytes(pos, ": ");
        pos = self.insert_bytes(pos, value);
        self.len = self.insert_bytes(pos, crlf_crlf);
        self.line_count += 1;
    }

    /// Insert a field with `name` and `value` at line index `i`.
    pub fn insert(self: *FieldsEditor, i: usize, name: []const u8, value: []const u8) !void {
        try self.validateLineIndex(i);
        try validateName(name);
        try validateValue(value);

        const line_len = name.len + ": ".len + value.len + crlf.len;
        const new_len = self.len + line_len;
        try self.ensureTotalCapacity(new_len);
        var pos = self.posForLineIndex(i);
        const dest_pos = pos + line_len;
        std.mem.copyBackwards(u8, self.buf[dest_pos..new_len], self.buf[pos..self.len]);
        pos = self.insert_bytes(pos, name);
        pos = self.insert_bytes(pos, ": ");
        pos = self.insert_bytes(pos, value);
        _ = self.insert_bytes(pos, crlf);
        self.len = new_len;
        self.line_count += 1;
    }

    /// Set the field with `name` and `value` at line index `i`.
    pub fn set(self: *FieldsEditor, i: usize, name: []const u8, value: []const u8) !void {
        try self.validateLineIndex(i);
        try validateName(name);
        try validateValue(value);

        var pos = self.posForLineIndex(i);
        const next_pos = self.nextLinePos(pos);
        const old_line_len = next_pos - pos;
        const line_len = name.len + ": ".len + value.len + crlf.len;
        const new_len = self.len - old_line_len + line_len;
        if (new_len > self.len) {
            try self.ensureTotalCapacity(new_len);
            const dest_pos = pos + line_len;
            std.mem.copyBackwards(u8, self.buf[dest_pos..new_len], self.buf[next_pos..self.len]);
        } else if (new_len < self.len) {
            const dest_pos = pos + line_len;
            std.mem.copy(u8, self.buf[dest_pos..new_len], self.buf[next_pos..self.len]);
        }
        pos = self.insert_bytes(pos, name);
        pos = self.insert_bytes(pos, ": ");
        pos = self.insert_bytes(pos, value);
        _ = self.insert_bytes(pos, crlf);
        self.len = new_len;
    }

    /// Delete the field at line index `i`.
    pub fn delete(self: *FieldsEditor, i: usize) !void {
        try self.validateLineIndex(i);

        const pos = self.posForLineIndex(i);
        const next_pos = self.nextLinePos(pos);
        const line_len = next_pos - pos;
        const new_len = self.len - line_len;
        std.mem.copy(u8, self.buf[pos..new_len], self.buf[next_pos..self.len]);
        self.len = new_len;
        self.line_count -= 1;
    }

    /// FieldsEditor owns the returned memory. The name and value of the
    /// returned Field is valid for use only until the next modification of
    /// this FieldsEditor.
    pub fn get(self: *const FieldsEditor, i: usize) !Field {
        try self.validateLineIndex(i);

        const pos = self.posForLineIndex(i);
        const colon_pos = std.mem.indexOfScalarPos(u8, self.buf, pos, ':').?;
        const end_pos = std.mem.indexOfPos(u8, self.buf, colon_pos + 1, crlf).?;
        return Field{
            .line = self.buf[pos..end_pos],
            .colon_pos = colon_pos - pos,
        };
    }

    pub fn indexOfName(self: *const FieldsEditor, name: []const u8) ?usize {
        if (self.line_count == 0) return null;
        return self.indexOfNamePos(name, 0) catch unreachable;
    }

    pub fn indexOfNamePos(self: *const FieldsEditor, name: []const u8, start_line_index: usize) !?usize {
        try self.validateLineIndex(start_line_index);

        var i = start_line_index;
        var pos = self.posForLineIndex(start_line_index);
        var end_pos: usize = 0;
        while (pos < self.len) : ({
            pos = end_pos + crlf.len;
            i += 1;
        }) {
            const colon_pos = std.mem.indexOfScalarPos(u8, self.buf, pos, ':') orelse return null;
            end_pos = std.mem.indexOfPos(u8, self.buf, colon_pos + 1, crlf).?;
            if (std.ascii.eqlIgnoreCase(self.buf[pos..colon_pos], name)) {
                return i;
            }
        }
        return null;
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

    fn nextLinePos(self: *const FieldsEditor, pos: usize) usize {
        return std.mem.indexOfPos(u8, self.buf, pos, crlf).? + crlf.len;
    }

    fn capacity(self: *const FieldsEditor) usize {
        return self.buf.len;
    }

    fn insert_bytes(self: *FieldsEditor, pos: usize, b: []const u8) usize {
        std.mem.copy(u8, self.buf[pos..], b);
        return pos + b.len;
    }

    fn validateLineIndex(self: *const FieldsEditor, i: usize) !void {
        if (i >= self.line_count) {
            return error.OutOfBounds;
        }
    }

    fn validateName(name: []const u8) !void {
        if (std.mem.indexOfScalar(u8, name, ':')) |_| {
            return error.InvalidInput;
        }
    }

    fn validateValue(value: []const u8) !void {
        if (std.mem.indexOf(u8, value, crlf)) |_| {
            return error.InvalidInput;
        }
    }
};

const testing = std.testing;

test "FieldsEditor append" {
    var buf = try testing.allocator.alloc(u8, 32);
    var editor = try FieldsEditor.newFromOwnedSlice(testing.allocator, buf);
    defer editor.deinit();
    try testing.expectEqualStrings("\r\n", editor.slice());
    try testing.expectEqual(@as(usize, 0), editor.lineCount());

    try testing.expectError(error.InvalidInput, editor.append("Date:", "Mon, 27 Jul 2009 12:28:53 GMT"));
    try testing.expectError(error.InvalidInput, editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT\r\n"));

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "\r\n", editor.slice());
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
        "\r\n", editor.slice());
    try testing.expectEqual(@as(usize, 2), editor.lineCount());

    try editor.delete(1);
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "\r\n", editor.slice());
    try testing.expectEqual(@as(usize, 1), editor.lineCount());

    try editor.delete(0);
    try testing.expectEqualStrings("\r\n", editor.slice());
    try testing.expectEqual(@as(usize, 0), editor.lineCount());
}

test "FieldsEditor insert" {
    var buf = try testing.allocator.alloc(u8, 32);
    var editor = try FieldsEditor.newFromOwnedSlice(testing.allocator, buf);
    defer editor.deinit();

    try testing.expectError(error.OutOfBounds, editor.insert(0, "Date", "Mon, 27 Jul 2009 12:28:53 GMT"));

    try editor.append("Vary", "Accept-Encoding");

    try testing.expectError(error.InvalidInput, editor.insert(0, "Date:", "Mon, 27 Jul 2009 12:28:53 GMT"));
    try testing.expectError(error.InvalidInput, editor.insert(0, "Date", "Mon, 27 Jul 2009 12:28:53 GMT\r\n"));

    try editor.insert(0, "Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Vary: Accept-Encoding\r\n" ++
        "\r\n", editor.slice());
    try testing.expectEqual(@as(usize, 2), editor.lineCount());

    try editor.insert(1, "Server", "Apache");
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "Vary: Accept-Encoding\r\n" ++
        "\r\n", editor.slice());
    try testing.expectEqual(@as(usize, 3), editor.lineCount());
}

test "FieldsEditor indexOfName" {
    var buf = try testing.allocator.alloc(u8, 32);
    var editor = try FieldsEditor.newFromOwnedSlice(testing.allocator, buf);
    defer editor.deinit();

    try testing.expect(editor.indexOfName("Date") == null);

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try editor.append("Cache-Control", "public, s-maxage=60");

    try testing.expectEqual(@as(?usize, 1), editor.indexOfName("cache-control"));
    try testing.expect(editor.indexOfName("Server") == null);
}

test "FieldsEditor indexOfNamePos" {
    var buf = try testing.allocator.alloc(u8, 32);
    var editor = try FieldsEditor.newFromOwnedSlice(testing.allocator, buf);
    defer editor.deinit();

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try editor.append("Cache-Control", "public, s-maxage=60");
    try editor.append("Server", "Apache");
    try editor.append("cache-control", "max-age=120");

    try testing.expectError(error.OutOfBounds, editor.indexOfNamePos("cache-control", 4));

    const wants = [_]usize{ 1, 3 };
    var j: usize = 0;
    var start: usize = 0;
    while (start < editor.lineCount()) {
        const result = try editor.indexOfNamePos("cache-control", start);
        if (result) |i| {
            try testing.expectEqual(wants[j], i);
            j += 1;
            start = i + 1;
        } else {
            break;
        }
    }
    try testing.expectEqual(wants.len, j);
}

test "FieldsEditor get" {
    var buf = try testing.allocator.alloc(u8, 32);
    var editor = try FieldsEditor.newFromOwnedSlice(testing.allocator, buf);
    defer editor.deinit();

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try editor.append("Cache-Control", "public, s-maxage=60");
    try editor.append("Server", "Apache");
    try editor.append("cache-control", "max-age=120");

    try testing.expectError(error.OutOfBounds, editor.get(4));

    const wants = [_][]const u8{
        "public, s-maxage=60",
        "max-age=120",
    };
    var j: usize = 0;
    var start: usize = 0;
    while (start < editor.lineCount()) {
        const result = try editor.indexOfNamePos("cache-control", start);
        if (result) |i| {
            const f = try editor.get(i);
            try testing.expectEqualStrings(wants[j], f.lineValue());
            j += 1;
            start = i + 1;
        } else {
            break;
        }
    }
    try testing.expectEqual(wants.len, j);
}

test "FieldsEditor get" {
    var buf = try testing.allocator.alloc(u8, 32);
    var editor = try FieldsEditor.newFromOwnedSlice(testing.allocator, buf);
    defer editor.deinit();

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try editor.append("Cache-Control", "public, s-maxage=60");
    try editor.append("Server", "Apache");

    try editor.set(0, "Date", "Tue, 28 Jul 2009 12:28:53 GMT");
    try testing.expectEqualStrings("Date: Tue, 28 Jul 2009 12:28:53 GMT\r\n" ++
        "Cache-Control: public, s-maxage=60\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n", editor.slice());

    try editor.set(1, "cache-control", "max-age=120");
    try testing.expectEqualStrings("Date: Tue, 28 Jul 2009 12:28:53 GMT\r\n" ++
        "cache-control: max-age=120\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n", editor.slice());

    try editor.set(1, "vary", "Accept-Encoding, Origin");
    try testing.expectEqualStrings("Date: Tue, 28 Jul 2009 12:28:53 GMT\r\n" ++
        "vary: Accept-Encoding, Origin\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n", editor.slice());
}

test "FieldsEditor parseOwnedSlice" {
    const input_fields =
        "Date:  \tMon, 27 Jul 2009 12:28:53 GMT \r\n" ++
        "Cache-Control: public, s-maxage=60\r\n" ++
        "Vary: Accept-Encoding\r\n" ++
        "cache-control: maxage=120\r\n" ++
        "\r\n";
    const input = input_fields ++
        "body";

    var buf = try testing.allocator.dupe(u8, input);
    var editor = try FieldsEditor.parseOwnedSlice(testing.allocator, buf);
    defer editor.deinit();

    try testing.expectEqualStrings(input_fields, editor.slice());
    try testing.expectEqual(@as(usize, 4), editor.lineCount());
}
