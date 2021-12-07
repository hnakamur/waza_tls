const std = @import("std");
const fifo = std.fifo;

pub fn ByteBuffer(
    comptime buffer_type: fifo.LinearFifoBufferType,
) type {
    return fifo.LinearFifo(u8, buffer_type);
}

pub fn ChunkedDecoder(
    comptime output_buffer_type: fifo.LinearFifoBufferType,
) type {
    return struct {
        const Self = @This();

        pub const Error = error{InvalidChunk};

        const State = enum {
            chunk_size,
            chunk_size_cr,
            chunk_data,
            chunk_data_cr,
            last_chunk_cr,
            finished,
        };

        state: State = .chunk_size,
        chunk_size: ?usize = null,

        pub fn decode(
            self: *Self,
            input: []const u8,
            output: *ByteBuffer(output_buffer_type),
        ) Error!usize {
            var i: usize = 0;
            while (i < input.len) : (i += 1) {
                const c = input[i];
                switch (self.state) {
                    .chunk_size => {
                        if (std.fmt.charToDigit(c, 16)) |d| {
                            if (self.chunk_size) |size| {
                                self.chunk_size = size * 16 + d;
                            } else {
                                self.chunk_size = d;
                            }
                        } else |_| {
                            if (c == '\r') {
                                if (self.chunk_size) |size| {
                                    if (size == 0) {
                                        self.state = .last_chunk_cr;
                                    } else {
                                        self.state = .chunk_size_cr;
                                    }
                                } else return error.InvalidChunk;
                            } else return error.InvalidChunk;
                        }
                    },
                    .chunk_size_cr => {
                        if (c == '\n') {
                            self.state = .chunk_data;
                        } else return error.InvalidChunk;
                    },
                    .chunk_data => {
                        if (self.chunk_size.? == 0) {
                            if (c == '\r') {
                                self.state = .chunk_data_cr;
                            } else return error.InvalidChunk;
                        } else {
                            // std.log.debug("writing c=0x{x}", .{c});
                            output.writeItem(c) catch |_| return i;
                            self.chunk_size.? -= 1;
                        }
                    },
                    .chunk_data_cr => {
                        if (c == '\n') {
                            self.state = .chunk_size;
                        } else return error.InvalidChunk;
                    },
                    .last_chunk_cr => {
                        if (c == '\n') {
                            self.state = .finished;
                            break;
                        } else return error.InvalidChunk;
                    },
                    .finished => break,
                }
            }
            return i + 1;
        }

        pub fn finished(self: *const Self) bool {
            return self.state == .finished;
        }
    };
}

const testing = std.testing;

test "ChunkDecoder / dynamic output buffer" {
    const allocator = testing.allocator;

    var input = "7\r\nhello, \r\n7\r\nchunked\r\n0\r\n";
    var output = ByteBuffer(.Dynamic).init(allocator);
    defer output.deinit();

    var decoder = ChunkedDecoder(.Dynamic){};
    testing.log_level = .debug;
    try testing.expectEqual(input.len, try decoder.decode(input, &output));
    try testing.expectEqualStrings("hello, chunked", output.readableSlice(0));
    try testing.expect(decoder.finished());
}

test "ChunkDecoder / slice output buffer" {
    const allocator = testing.allocator;

    var input: []const u8 = "7\r\nhello, \r\n7\r\nchunked\r\n0\r\n";
    var buf = [_]u8{0} ** 5;
    var output = ByteBuffer(.Slice).init(&buf);
    defer output.deinit();

    var decoder = ChunkedDecoder(.Slice){};
    testing.log_level = .debug;

    var read = try decoder.decode(input, &output);
    try testing.expectEqual(@as(usize, 8), read);
    try testing.expectEqualStrings("hello", output.readableSlice(0));
    try testing.expect(!decoder.finished());

    output.discard(buf.len);
    input = input[read..];
    read = try decoder.decode(input, &output);
    try testing.expectEqual(@as(usize, 10), read);
    try testing.expectEqualStrings(", chu", output.readableSlice(0));
    try testing.expect(!decoder.finished());

    output.discard(buf.len);
    input = input[read..];
    read = try decoder.decode(input, &output);
    try testing.expectEqual(@as(usize, 9), read);
    try testing.expectEqualStrings("nked", output.readableSlice(0));
    try testing.expect(decoder.finished());
}
