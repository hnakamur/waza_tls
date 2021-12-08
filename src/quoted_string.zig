const std = @import("std");
const fifo = std.fifo;
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
                // std.log.debug("c=0x{02x}", .{c});
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
                                std.log.debug("write#1 c={c}", .{c});
                                _ = try output.writeByte(c);
                            }
                        } else if (c == '"') {
                            input.advance();
                            self.state = .finished;
                            return true;
                        } else return error.InvalidCharacter;
                    },
                    .post_backslash => {
                        if (lex.isQuotedPairChar(c)) {
                            self.state = .qdtext_or_backslash;
                            if (WriterOrVoidType != void) {
                                std.log.debug("write#2 c={c}", .{c});
                                _ = try output.writeByte(c);
                            }
                        } else return error.InvalidCharacter;
                    },
                    else => return error.InvalidState,
                }
                input.advance();
            }
            return false;
        }
    };
}

const testing = std.testing;

test "QuotedStringParser void output" {
    testing.log_level = .debug;
    var vw = BytesView.init(
        \\"hello"
    );
    var parser = QuotedStringParser(void).init();
    try testing.expect(try parser.parse(&vw, {}));
    try testing.expectEqualStrings("", vw.rest());
}

test "QuotedStringParser SliceBuf output" {
    testing.log_level = .debug;
    var vw = BytesView.init(
        \\"hello"
    );
    const SliceBuf = fifo.LinearFifo(u8, .Slice);
    var buf = [_]u8{0} ** 4;
    var output = SliceBuf.init(&buf);
    var parser = QuotedStringParser(SliceBuf.Writer).init();

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
