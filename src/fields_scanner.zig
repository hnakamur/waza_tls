const std = @import("std");

pub const FieldsScanner = struct {
    const State = enum {
        initial,
        seen_cr,
        seen_cr_lf,
        seen_cr_lf_cr,
        seen_cr_lf_cr_lf,
    };

    state: State = .initial,
    total_bytes_read: usize = 0,

    pub fn scan(self: *FieldsScanner, buf: []const u8) !bool {
        var pos: usize = 0;
        while (pos < buf.len) {
            switch (self.state) {
                .initial => {
                    if (std.mem.indexOfScalarPos(u8, buf, pos, '\r')) |cr_pos| {
                        self.state = .seen_cr;
                        self.total_bytes_read += cr_pos + "\r".len - pos;
                        pos = cr_pos + "\r".len;
                    } else {
                        self.total_bytes_read += buf.len - pos;
                        return false;
                    }
                },
                .seen_cr => {
                    self.total_bytes_read += 1;
                    if (buf[pos] == '\n') {
                        self.state = .seen_cr_lf;
                        pos += 1;
                    } else {
                        return error.InvalidInput;
                    }
                },
                .seen_cr_lf => {
                    self.total_bytes_read += 1;
                    self.state = if (buf[pos] == '\r') .seen_cr_lf_cr else .initial;
                    pos += 1;
                },
                .seen_cr_lf_cr => {
                    self.total_bytes_read += 1;
                    if (buf[pos] == '\n') {
                        self.state = .seen_cr_lf_cr_lf;
                        return true;
                    } else {
                        return error.InvalidInput;
                    }
                },
                .seen_cr_lf_cr_lf => return error.InvalidState,
            }
        }
        return false;
    }

    pub fn totalBytesRead(self: *const FieldsScanner) usize {
        return self.total_bytes_read;
    }
};
