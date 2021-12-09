const std = @import("std");
const fifo = std.fifo;
const BytesBuf = @import("parser.zig").bytes.BytesBuf;
const BytesView = @import("parser.zig").bytes.BytesView;

pub fn ChunkedDecoder(comptime WriterOrVoidType: type) type {
    return struct {
        const Self = @This();

        pub const Error = error{
            InvalidChunk,
            InvalidState,
        } || (if (WriterOrVoidType == void) error{} else WriterOrVoidType.Error);

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
            output: WriterOrVoidType,
        ) Error!bool {
            while (input.peekByte()) |c| {
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
                            if (WriterOrVoidType != void) {
                                _ = try output.writeByte(c);
                            }
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
                            input.advance();
                            return true;
                        } else return error.InvalidChunk;
                    },
                    else => return error.InvalidState,
                }
                input.advance();
            }
            return input.eof;
        }
    };
}

const testing = std.testing;

test "ChunkDecoder / void output" {
    var input = BytesView.init("7\r\nhello, \r\n7\r\nchunked\r\n0\r\n", true);
    var decoder = ChunkedDecoder(void){};
    try testing.expect(try decoder.decode(&input, {}));
}

test "ChunkDecoder / dynamic output buffer" {
    const allocator = testing.allocator;

    var input = BytesView.init("7\r\nhello, \r\n7\r\nchunked\r\n0\r\n", true);
    const DynamicBuf = BytesBuf(.Dynamic);

    var output = DynamicBuf.init(allocator);
    defer output.deinit();

    var decoder = ChunkedDecoder(DynamicBuf.Writer){};
    try testing.expect(try decoder.decode(&input, output.writer()));
    try testing.expectEqualStrings("hello, chunked", output.readableSlice(0));
}

test "ChunkDecoder / slice output buffer" {
    var data = "7\r\nhello, \r\n7\r\nchunked\r\n0\r\n";
    var input = BytesView.init(data[0..7], false);

    const SliceBuf = BytesBuf(.Slice);

    var buf = [_]u8{0} ** 5;
    var output = SliceBuf.init(&buf);
    defer output.deinit();

    var decoder = ChunkedDecoder(SliceBuf.Writer){};

    try testing.expect(!try decoder.decode(&input, output.writer()));
    try testing.expectEqualStrings("hell", output.readableSlice(0));

    input = BytesView.init(data[7..], true);
    try testing.expectError(error.OutOfMemory, decoder.decode(&input, output.writer()));
    try testing.expectEqualStrings("hello", output.readableSlice(0));

    output.discard(output.count);
    try testing.expectError(error.OutOfMemory, decoder.decode(&input, output.writer()));
    try testing.expectEqualStrings(", chu", output.readableSlice(0));

    output.discard(output.count);
    try testing.expect(try decoder.decode(&input, output.writer()));
    try testing.expectEqualStrings("nked", output.readableSlice(0));
}

test "ChunkDecoder / invalid chunk" {
    var buf = [_]u8{0} ** 16;
    const SliceBuf = BytesBuf(.Slice);
    var output = SliceBuf.init(&buf);
    defer output.deinit();

    const data_list = [_][]const u8{
        "7\n",
        "\r",
        "7\r\r",
        "1\r\na\n",
        "1\r\na\r\r",
        "0\r\r",
    };
    for (data_list) |data| {
        var input = BytesView.init(data, true);
        var decoder = ChunkedDecoder(SliceBuf.Writer){};
        output.discard(output.count);
        try testing.expectError(error.InvalidChunk, decoder.decode(&input, output.writer()));
    }
}

test "ChunkDecoder / invalid state" {
    const allocator = testing.allocator;

    var data = "7\r\nhello, \r\n7\r\nchunked\r\n0\r\n";
    var input = BytesView.init(data, true);

    const DynamicBuf = BytesBuf(.Dynamic);
    var output = DynamicBuf.init(allocator);
    defer output.deinit();

    var decoder = ChunkedDecoder(DynamicBuf.Writer){};
    try testing.expect(try decoder.decode(&input, output.writer()));

    input = BytesView.init(data, true);
    try testing.expectError(error.InvalidState, decoder.decode(&input, output.writer()));
}
