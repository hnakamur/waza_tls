const std = @import("std");
const mem = std.mem;
const Field = @import("../fields.zig").Field;

pub fn fieldReader(reader: anytype, buffer: []u8) FieldReader(@TypeOf(reader)) {
    return FieldReader(@TypeOf(reader)).init(reader, buffer);
}

pub fn FieldReader(comptime Reader: type) type {
    return struct {
        const Self = @This();

        reader: Reader,
        buffer: []u8,
        bytes_read: usize = 0,

        pub fn init(reader: Reader, buffer: []u8) Self {
            return .{
                .reader = reader,
                .buffer = buffer,
            };
        }

        /// Returns a Field when a valid field is read, null when the valid fields end found.
        /// Otherwise returns a error.
        /// The returned Fiels is valid for use only until the next call of `read`.
        pub fn read(self: *Self) !?Field {
            var buf = self.buffer;
            // This may get `error.EndOfStream` or error.`error.StreamTooLong`.
            // Those are invalid inputs, too.
            var line = try readUntilDelimiter(self.reader, buf, '\n');
            self.bytes_read += line.len + "\n".len;
            if (line.len > 0 and line[line.len - 1] == '\r') {
                line.len -= "\r".len;
            } else return error.InvalidInput;

            if (line.len == 0) return null;

            const colon_pos = mem.indexOfScalar(u8, buf, ':') orelse return error.InvalidInput;
            return Field{
                .line = line,
                .colon_pos = colon_pos,
            };
        }

        /// Returns the byte count read succesfully.
        /// Note the byte count read in `read` before an error is not included.
        pub fn byteCountRead(self: *const Self) usize {
            return self.bytes_read;
        }

        /// Reads from the stream until specified byte is found. If the buffer is not
        /// large enough to hold the entire contents, `error.StreamTooLong` is returned.
        /// Returns a slice of the stream data, with ptr equal to `buf.ptr`. The
        /// delimiter byte is not included in the returned slice.
        /// (This code is copied from zig master).
        fn readUntilDelimiter(reader: Reader, buf: []u8, delimiter: u8) ![]u8 {
            var index: usize = 0;
            while (true) {
                const byte = try reader.readByte();

                if (byte == delimiter) return buf[0..index];
                if (index >= buf.len) return error.StreamTooLong;

                buf[index] = byte;
                index += 1;
            }
        }
    };
}

const io = std.io;
const testing = std.testing;

test "FieldReader read loop for fields" {
    const input_fields =
        "Date: Mon, 27 Jul 2009 12:28:53 GMT\r\n" ++
        "Server: Apache\r\n" ++
        "\r\n";
    const input = input_fields ++
        "Hello body";

    const MyField = struct {
        name: []const u8,
        value: []const u8,
    };
    const wants = [_]MyField{
        .{ .name = "Date", .value = "Mon, 27 Jul 2009 12:28:53 GMT" },
        .{ .name = "Server", .value = "Apache" },
    };

    const fbs_reader = io.fixedBufferStream(input).reader();
    var buf: [64]u8 = undefined;
    var reader = fieldReader(fbs_reader, &buf);
    var i: usize = 0;
    while (try reader.read()) |field| {
        try testing.expectEqualStrings(wants[i].name, field.name());
        try testing.expectEqualStrings(wants[i].value, field.value());
        i += 1;
    }
    try testing.expectEqual(wants.len, i);
    try testing.expectEqual(input_fields.len, reader.byteCountRead());
}
