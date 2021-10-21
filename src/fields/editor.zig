const std = @import("std");
const Field = @import("../fields.zig").Field;

const crlf_crlf = "\r\n\r\n";
const crlf = "\r\n";

pub const FieldsEditor = struct {
    buf: []u8,
    len: usize,

    pub fn new(buf: []u8) !FieldsEditor {
        if (buf.len < crlf.len) {
            return error.BufferTooSmall;
        }
        std.mem.copy(u8, buf, crlf);
        return FieldsEditor{
            .buf = buf,
            .len = crlf.len,
        };
    }

    pub fn append(self: *FieldsEditor, name: []const u8, value: []const u8) !void {
        const line_len = name.len + ": ".len + value.len + crlf.len;
        if (self.buf.len < self.len + line_len) {
            return error.BufferTooSmall;
        }
        self.len -= crlf.len;
        self.append_bytes(name);
        self.append_bytes(": ");
        self.append_bytes(value);
        self.append_bytes(crlf_crlf);
    }

    inline fn append_bytes(self: *FieldsEditor, b: []const u8) void {
        std.mem.copy(u8, self.buf[self.len..], b);
        self.len += b.len;
    }
};

const testing = std.testing;

test "FieldsEditor append" {
    var buf = [_]u8{' '} ** 1024;
    var editor = try FieldsEditor.new(&buf);
    try testing.expectEqualStrings("\r\n", buf[0..editor.len]);

    try editor.append("Date", "Mon, 27 Jul 2009 12:28:53 GMT");
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "\r\n", buf[0..editor.len]);

    try editor.append("Server", "Apache");
    try testing.expectEqualStrings("Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n", buf[0..editor.len]);
}
