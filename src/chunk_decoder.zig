const std = @import("std");
const fifo = std.fifo;
const BytesBuf = @import("bytes.zig").BytesBuf;
const BytesView = @import("bytes.zig").BytesView;

pub fn ChunkedDecoder(
    comptime output_buffer_type: fifo.LinearFifoBufferType,
) type {
    return struct {
        const Self = @This();

        pub const Error = error{
            InvalidChunk,
            InvalidState,
        };

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
            input: *BytesView,
            output: *BytesBuf(output_buffer_type),
        ) Error!bool {
            while (input.readByte()) |c| {
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
                            output.writeItem(c) catch |_| {
                                input.unreadByte();
                                return false;
                            };
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
                            return true;
                        } else return error.InvalidChunk;
                    },
                    else => return error.InvalidState,
                }
            }
            return false;
        }
    };
}

const testing = std.testing;

test "ChunkDecoder / dynamic output buffer" {
    const allocator = testing.allocator;

    var input = BytesView.init("7\r\nhello, \r\n7\r\nchunked\r\n0\r\n");
    var output = BytesBuf(.Dynamic).init(allocator);
    defer output.deinit();

    var decoder = ChunkedDecoder(.Dynamic){};
    testing.log_level = .debug;
    try testing.expect(try decoder.decode(&input, &output));
    try testing.expectEqualStrings("hello, chunked", output.readableSlice(0));
}

test "ChunkDecoder / slice output buffer" {
    const allocator = testing.allocator;

    var input = BytesView.init("7\r\nhello, \r\n7\r\nchunked\r\n0\r\n");
    var buf = [_]u8{0} ** 5;
    var output = BytesBuf(.Slice).init(&buf);
    defer output.deinit();

    var decoder = ChunkedDecoder(.Slice){};
    testing.log_level = .debug;

    try testing.expect(!try decoder.decode(&input, &output));
    try testing.expectEqualStrings("hello", output.readableSlice(0));

    output.discard(buf.len);
    try testing.expect(!try decoder.decode(&input, &output));
    try testing.expectEqualStrings(", chu", output.readableSlice(0));

    output.discard(buf.len);
    try testing.expect(try decoder.decode(&input, &output));
    try testing.expectEqualStrings("nked", output.readableSlice(0));
}
