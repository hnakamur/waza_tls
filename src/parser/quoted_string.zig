const std = @import("std");
const lex = @import("lex.zig");
const BytesView = @import("bytes.zig").BytesView;

pub fn QuotedStringParser(
    comptime WriterOrVoidType: type,
) type {
    return struct {
        const Self = @This();

        pub const Error = error{
            InvalidCharacter,
            InvalidState,
        } || (if (WriterOrVoidType == void) error{} else WriterOrVoidType.Error);

        const State = enum {
            initial,
            qdtext_or_backslash,
            post_backslash,
            finished,
        };

        state: State,

        pub fn init() Self {
            return .{ .state = .initial };
        }

        pub fn parse(
            self: *Self,
            input: *BytesView,
            output: WriterOrVoidType,
        ) Error!bool {
            while (input.peekByte()) |c| {
                switch (self.state) {
                    .initial => {
                        if (c == '"') {
                            self.state = .qdtext_or_backslash;
                        } else return error.InvalidCharacter;
                    },
                    .qdtext_or_backslash => {
                        if (c == '\\') {
                            self.state = .post_backslash;
                        } else if (lex.isQdTextChar(c)) {
                            if (WriterOrVoidType != void) {
                                _ = try output.writeByte(c);
                            }
                        } else if (c == '"') {
                            input.advance(1);
                            self.state = .finished;
                            return true;
                        } else return error.InvalidCharacter;
                    },
                    .post_backslash => {
                        if (lex.isQuotedPairChar(c)) {
                            self.state = .qdtext_or_backslash;
                            if (WriterOrVoidType != void) {
                                _ = try output.writeByte(c);
                            }
                        } else return error.InvalidCharacter;
                    },
                    else => return error.InvalidState,
                }
                input.advance(1);
            }
            return input.eof;
        }
    };
}

const fifo = std.fifo;
const testing = std.testing;

test "QuotedStringParser void output" {
    var vw = BytesView.init(
        \\"hello"
    , true);
    var parser = QuotedStringParser(void).init();
    try testing.expect(try parser.parse(&vw, {}));
    try testing.expectEqualStrings("", vw.rest());
}

test "QuotedStringParser SliceBuf output" {
    var data =
        \\"hello"
    ;
    const SliceBuf = fifo.LinearFifo(u8, .Slice);
    var buf = [_]u8{0} ** 4;
    var output = SliceBuf.init(&buf);
    var parser = QuotedStringParser(SliceBuf.Writer).init();

    var vw = BytesView.init(data[0..3], false);
    try testing.expect(!try parser.parse(&vw, output.writer()));
    try testing.expectEqualStrings("he", output.readableSlice(0));

    vw = BytesView.init(data[3..], true);
    try testing.expectError(error.OutOfMemory, parser.parse(&vw, output.writer()));
    try testing.expectEqualStrings("hell", &buf);

    output.discard(output.count);
    try testing.expectEqual(buf.len, output.writableLength());
    try testing.expectEqualStrings(
        \\o"
    ,
        vw.rest(),
    );
    try testing.expect(try parser.parse(&vw, output.writer()));
    try testing.expectEqualStrings("o", output.readableSlice(0));
}

test "QuotedStringParser escape" {
    const allocator = testing.allocator;

    const DynamicBuf = fifo.LinearFifo(u8, .Dynamic);
    var output = DynamicBuf.init(allocator);
    defer output.deinit();

    var data = "\"a\\\\b\\\tc\"";
    var vw = BytesView.init(data, true);

    var parser = QuotedStringParser(DynamicBuf.Writer).init();
    try testing.expect(try parser.parse(&vw, output.writer()));
    try testing.expectEqualStrings("a\\b\tc", output.readableSlice(0));
}

test "QuotedStringParser invalid character" {
    const data_list = [_][]const u8{
        "a",
        "\"\x7f",
        "\"\\\x7f",
    };
    for (data_list) |data| {
        var parser = QuotedStringParser(void).init();
        var vw = BytesView.init(data, true);
        try testing.expectError(error.InvalidCharacter, parser.parse(&vw, {}));
    }
}

test "QuotedStringParser invalid state" {
    const data =
        \\"hello"
    ;
    var parser = QuotedStringParser(void).init();

    var vw = BytesView.init(data, true);
    try testing.expect(try parser.parse(&vw, {}));

    vw = BytesView.init(data, true);
    try testing.expectError(error.InvalidState, parser.parse(&vw, {}));
}
