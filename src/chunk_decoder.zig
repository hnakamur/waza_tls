const std = @import("std");
const fifo = std.fifo;
const BytesBuf = @import("parser.zig").bytes.BytesBuf;
const BytesView = @import("parser.zig").bytes.BytesView;
const isTokenChar = @import("parser.zig").lex.isTokenChar;
const TokenParser = @import("parser.zig").TokenParser;
const QuotedStringParser = @import("parser.zig").QuotedStringParser;

pub fn ChunkedDecoder(comptime WriterOrVoidType: type) type {
    return struct {
        const Self = @This();

        pub const Error = error{
            InvalidChunk,
            InvalidState,
        } || ChunkExtSkipper.Error || (if (WriterOrVoidType == void) error{} else WriterOrVoidType.Error);

        const State = enum {
            chunk_size,
            chunk_data_ext,
            post_chunk_data_ext,
            chunk_size_cr,
            chunk_data,
            chunk_data_cr,
            last_chunk_ext,
            post_last_chunk_ext,
            last_chunk_cr,
            finished,
        };

        state: State,
        chunk_size: ?usize = null,
        chunk_ext_skipper: ChunkExtSkipper = undefined,

        pub fn init() Self {
            return .{ .state = .chunk_size };
        }

        pub fn decode(
            self: *Self,
            input: *BytesView,
            output: WriterOrVoidType,
        ) Error!bool {
            while (input.peekByte()) |c| {
                std.log.debug("ChunkedDecoder.decode c={c} (0x{x}) state={}, chunk_size={}", .{ c, c, self.state, self.chunk_size });
                switch (self.state) {
                    .chunk_size => {
                        var digit: ?u8 = null;
                        switch (c) {
                            '0'...'9' => digit = c - '0',
                            'A'...'F' => digit = c - 'A' + 10,
                            'a'...'f' => digit = c - 'a' + 10,
                            '\r' => if (self.chunk_size) |size| {
                                input.advance();
                                if (size == 0) {
                                    self.state = .last_chunk_cr;
                                } else {
                                    self.state = .chunk_size_cr;
                                }
                            } else return error.InvalidChunk,
                            '\t', ' ', ';' => if (self.chunk_size) |size| {
                                self.chunk_ext_skipper = ChunkExtSkipper.init();
                                if (!try self.chunk_ext_skipper.parse(input)) {
                                    if (size == 0) {
                                        self.state = .last_chunk_ext;
                                    } else {
                                        self.state = .chunk_data_ext;
                                    }
                                    return false;
                                }
                                if (size == 0) {
                                    self.state = .post_last_chunk_ext;
                                } else {
                                    self.state = .post_chunk_data_ext;
                                }
                            } else return error.InvalidChunk,
                            else => return error.InvalidChunk,
                        }
                        if (digit) |d| {
                            input.advance();
                            if (self.chunk_size) |size| {
                                self.chunk_size = 16 * size + d;
                            } else {
                                self.chunk_size = d;
                            }
                        }
                    },
                    .chunk_data_ext => {
                        if (!try self.chunk_ext_skipper.parse(input)) {
                            return false;
                        }
                        self.state = .post_chunk_data_ext;
                    },
                    .post_chunk_data_ext => {
                        if (c == '\r') {
                            input.advance();
                            self.state = .chunk_size_cr;
                        } else return error.InvalidChunk;
                    },
                    .chunk_size_cr => {
                        if (c == '\n') {
                            input.advance();
                            self.state = .chunk_data;
                        } else return error.InvalidChunk;
                    },
                    .chunk_data => {
                        if (self.chunk_size.? == 0) {
                            if (c == '\r') {
                                input.advance();
                                self.chunk_size = null;
                                self.state = .chunk_data_cr;
                            } else return error.InvalidChunk;
                        } else {
                            if (WriterOrVoidType != void) {
                                _ = try output.writeByte(c);
                            }
                            input.advance();
                            self.chunk_size.? -= 1;
                        }
                    },
                    .chunk_data_cr => {
                        if (c == '\n') {
                            input.advance();
                            self.state = .chunk_size;
                        } else return error.InvalidChunk;
                    },
                    .last_chunk_ext => {
                        if (!try self.chunk_ext_skipper.parse(input)) {
                            return false;
                        }
                        self.state = .post_last_chunk_ext;
                    },
                    .post_last_chunk_ext => {
                        if (c == '\r') {
                            input.advance();
                            self.state = .last_chunk_cr;
                        } else return error.InvalidChunk;
                    },
                    .last_chunk_cr => {
                        if (c == '\n') {
                            input.advance();
                            self.state = .finished;
                            return true;
                        } else return error.InvalidChunk;
                    },
                    else => return error.InvalidState,
                }
            }
            return if (input.eof) error.UnexpectedEof else false;
        }
    };
}

const ChunkExtSkipper = struct {
    pub const Error = error{
        InvalidCharacter,
        InvalidState,
        UnexpectedEof,
    } || TokenParser(void).Error;

    const State = enum {
        initial,
        semi,
        chunk_ext_name,
        post_chunk_ext_name,
        eq,
        chunk_ext_val_token,
        chunk_ext_val_quoted_string,
        post_chunk_ext_val,
        finished,
    };

    state: State,
    token_parser: TokenParser(void) = undefined,
    qstr_parser: QuotedStringParser(void) = undefined,

    pub fn init() ChunkExtSkipper {
        return .{ .state = .initial };
    }

    pub fn parse(
        self: *ChunkExtSkipper,
        input: *BytesView,
    ) Error!bool {
        while (input.peekByte()) |c| {
            std.log.debug("ChunkExtSkipper.parse c={c} (0x{x}) state={}", .{ c, c, self.state });
            switch (self.state) {
                .initial => switch (c) {
                    '\t', ' ' => if (!skipOptionalWhiteSpaces(input)) {
                        return false;
                    },
                    ';' => {
                        input.advance();
                        self.state = .semi;
                    },
                    else => return error.InvalidCharacter,
                },
                .semi => switch (c) {
                    '\t', ' ' => if (!skipOptionalWhiteSpaces(input)) {
                        return false;
                    },
                    else => if (isTokenChar(c)) {
                        self.token_parser = TokenParser(void).init();
                        if (!try self.token_parser.parse(input, {})) {
                            self.state = .chunk_ext_name;
                            return false;
                        }
                        self.state = .post_chunk_ext_name;
                    } else return error.InvalidCharacter,
                },
                .chunk_ext_name => {
                    if (!try self.token_parser.parse(input, {})) {
                        return false;
                    }
                    self.state = .post_chunk_ext_name;
                },
                .post_chunk_ext_name => switch (c) {
                    '\t', ' ' => if (!skipOptionalWhiteSpaces(input)) {
                        return false;
                    },
                    '=' => {
                        input.advance();
                        self.state = .eq;
                    },
                    ';' => {
                        input.advance();
                        self.state = .semi;
                    },
                    else => {
                        self.state = .finished;
                        return true;
                    },
                },
                .eq => switch (c) {
                    '\t', ' ' => if (!skipOptionalWhiteSpaces(input)) {
                        return false;
                    },
                    '"' => {
                        self.qstr_parser = QuotedStringParser(void).init();
                        if (!try self.qstr_parser.parse(input, {})) {
                            self.state = .chunk_ext_val_quoted_string;
                            return false;
                        }
                        self.state = .post_chunk_ext_val;
                    },
                    else => if (isTokenChar(c)) {
                        self.token_parser = TokenParser(void).init();
                        if (!try self.token_parser.parse(input, {})) {
                            self.state = .chunk_ext_val_token;
                            return false;
                        }
                        self.state = .post_chunk_ext_val;
                    } else return error.InvalidCharacter,
                },
                .chunk_ext_val_quoted_string => {
                    if (!try self.qstr_parser.parse(input, {})) {
                        return false;
                    }
                    self.state = .post_chunk_ext_val;
                },
                .chunk_ext_val_token => {
                    if (!try self.token_parser.parse(input, {})) {
                        return false;
                    }
                    self.state = .post_chunk_ext_val;
                },
                .post_chunk_ext_val => switch (c) {
                    '\t', ' ', ';' => self.state = .initial,
                    else => {
                        self.state = .finished;
                        return true;
                    },
                },
                else => return error.InvalidState,
            }
        }
        std.log.debug("ChunkExtSkipper.parse return after loop input.eof={}", .{input.eof});
        return if (input.eof) error.UnexpectedEof else false;
    }
};

fn skipOptionalWhiteSpaces(input: *BytesView) bool {
    while (input.peekByte()) |c| {
        switch (c) {
            '\t', ' ' => input.advance(),
            else => return true,
        }
    }
    return input.eof;
}

const testing = std.testing;

test "ChunkDecoder / void output" {
    var input = BytesView.init("7\r\nhello, \r\n7\r\nchunked\r\n0\r\n", true);
    var decoder = ChunkedDecoder(void).init();
    try testing.expect(try decoder.decode(&input, {}));
}

test "ChunkDecoder / incomplete input void output" {
    var input = BytesView.init("7\r\nhello, \r\n7\r\nchunked\r\n", true);
    var decoder = ChunkedDecoder(void).init();
    try testing.expectError(error.UnexpectedEof, decoder.decode(&input, {}));
}

test "ChunkDecoder / dynamic output buffer" {
    const allocator = testing.allocator;

    var input = BytesView.init("17\r\nhello, chunked encoding\r\n0\r\n", true);
    const DynamicBuf = BytesBuf(.Dynamic);

    var output = DynamicBuf.init(allocator);
    defer output.deinit();

    var decoder = ChunkedDecoder(DynamicBuf.Writer).init();
    try testing.expect(try decoder.decode(&input, output.writer()));
    try testing.expectEqualStrings("hello, chunked encoding", output.readableSlice(0));
}

test "ChunkDecoder / slice output buffer" {
    var data = "7\r\nhello, \r\n7\r\nchunked\r\n0\r\n";
    var input = BytesView.init(data[0..7], false);

    const SliceBuf = BytesBuf(.Slice);

    var buf = [_]u8{0} ** 5;
    var output = SliceBuf.init(&buf);
    defer output.deinit();

    var decoder = ChunkedDecoder(SliceBuf.Writer).init();

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
        var decoder = ChunkedDecoder(SliceBuf.Writer).init();
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

    var decoder = ChunkedDecoder(DynamicBuf.Writer).init();
    try testing.expect(try decoder.decode(&input, output.writer()));

    input = BytesView.init(data, true);
    try testing.expectError(error.InvalidState, decoder.decode(&input, output.writer()));
}

test "ChunkDecoder / chunk ext" {
    const data = "1;aa=bb\r\na\r\n0;bb=cc\r";
    var decoder = ChunkedDecoder(void).init();
    for (data) |c, i| {
        var input = BytesView.init(&[_]u8{c}, false);
        try testing.expect(!try decoder.decode(&input, {}));
    }

    decoder = ChunkedDecoder(void).init();
    var input = BytesView.init(data, false);
    try testing.expect(!try decoder.decode(&input, {}));

    const invalid_data_list = [_][]const u8{
        "\t",
        "1;a\x7f",
        "0;a\x7f",
    };
    for (invalid_data_list) |invalid_data| {
        decoder = ChunkedDecoder(void).init();
        input = BytesView.init(invalid_data, false);
        try testing.expectError(error.InvalidChunk, decoder.decode(&input, {}));
    }
}

test "ChunkDecoder / incomplete chunk ext" {
    // testing.log_level = .debug;
    const data = "1;aa=bb\r\na\r\n0;bb=cc\r";
    var input = BytesView.init(data, true);
    var decoder = ChunkedDecoder(void).init();
    try testing.expectError(error.UnexpectedEof, decoder.decode(&input, {}));
}

test "skipOptionalWhiteSpaces" {
    var input = BytesView.init("\t a", false);
    try testing.expect(skipOptionalWhiteSpaces(&input));
    try testing.expectEqualStrings("a", input.rest());

    input = BytesView.init("", false);
    try testing.expect(!skipOptionalWhiteSpaces(&input));
}

test "ChunkExtSkipper case 1" {
    var input = BytesView.init("\t ; a ; bb = cc ; c = \"a\"\r", false);
    var parser = ChunkExtSkipper.init();
    try testing.expect(try parser.parse(&input));
    try testing.expectEqualStrings("\r", input.rest());

    try testing.expectError(error.InvalidState, parser.parse(&input));
}

test "ChunkExtSkipper case 2" {
    var input = BytesView.init("\t ; a ; bb = cc ; c = \"a\"", false);
    var parser = ChunkExtSkipper.init();
    try testing.expect(!try parser.parse(&input));
    try testing.expectEqualStrings("", input.rest());
}

test "ChunkExtSkipper case 3" {
    var input = BytesView.init("\t ; a\r", false);
    var parser = ChunkExtSkipper.init();
    try testing.expect(try parser.parse(&input));
    try testing.expectEqualStrings("\r", input.rest());
}

test "ChunkExtSkipper case 4" {
    const data = "\t ;  aa  ;  bb  =  cc  ;  cc  =  \"aa\"\r";
    var parser = ChunkExtSkipper.init();
    for (data) |c| {
        var input = BytesView.init(&[_]u8{c}, false);
        try testing.expectEqual(c == '\r', try parser.parse(&input));
    }
}

test "ChunkExtSkipper invalid cases" {
    const data_list = [_][]const u8{
        "x",
        ";\x7f",
        ";x=\x7f",
    };
    for (data_list) |data| {
        var input = BytesView.init(data, false);
        var parser = ChunkExtSkipper.init();
        try testing.expectError(error.InvalidCharacter, parser.parse(&input));
    }
}
