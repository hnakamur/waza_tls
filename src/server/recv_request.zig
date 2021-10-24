const std = @import("std");

/// A receiving request.
pub const RecvRequest = struct {};

const RequestLineEndFinder = struct {};

const FieldSectionEndFinder = struct {
    const State = enum {
        initial,
        seen_cr,
        seen_cr_lf,
        seen_cr_lf_cr,
        seen_cr_lf_cr_lf,
    };

    state: State = .initial,
    total_bytes_read: usize = 0,

    pub fn reachesToEnd(self: *FieldSectionEndFinder, buf: []const u8) !bool {
        var pos: usize = 0;
        while (pos < buf.len) {
            switch (self.state) {
                .initial => {
                    if (std.mem.indexOfScalarPos(u8, buf, pos, '\r')) |cr_pos| {
                        self.state = .seen_cr;
                        pos = cr_pos + "\r".len;
                    } else {
                        self.total_bytes_read += buf.len;
                        return false;
                    }
                },
                .seen_cr => {
                    if (buf[pos] == '\n') {
                        self.state = .seen_cr_lf;
                        pos += 1;
                    } else {
                        self.total_bytes_read += pos + 1;
                        return error.InvalidInput;
                    }
                },
                .seen_cr_lf => {
                    self.state = if (buf[pos] == '\r') .seen_cr_lf_cr else .initial;
                    pos += 1;
                },
                .seen_cr_lf_cr => {
                    if (buf[pos] == '\n') {
                        self.state = .seen_cr_lf_cr_lf;
                        self.total_bytes_read += pos + 1;
                        return true;
                    } else {
                        self.total_bytes_read += pos + 1;
                        return error.InvalidInput;
                    }
                },
                .seen_cr_lf_cr_lf => return error.InvalidState,
            }
        }
        self.total_bytes_read += buf.len;
        return false;
    }

    pub fn totalBytesRead(self: *const FieldSectionEndFinder) usize {
        return self.total_bytes_read;
    }
};

const testing = std.testing;

test "FieldSectionEndFinder - whole in one buf" {
    const input = "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "\r\n";
    var finder = FieldSectionEndFinder{};
    try testing.expect(try finder.reachesToEnd(input));
    try testing.expectEqual(input.len, finder.totalBytesRead());
}

test "FieldSectionEndFinder - splitted case" {
    const input = "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    var pos: usize = 0;
    while (pos < input.len) : (pos += 1) {
        var finder = FieldSectionEndFinder{};
        try testing.expect(!try finder.reachesToEnd(input[0..pos]));
        try testing.expectEqual(pos, finder.totalBytesRead());
        try testing.expect(try finder.reachesToEnd(input[pos..]));
        try testing.expectEqual(input.len, finder.totalBytesRead());
    }
}
