const std = @import("std");
const lex = @import("lex.zig");
const isTokenChar = lex.isTokenChar;
const BytesView = @import("bytes.zig").BytesView;

pub fn TokenParser(
    comptime WriterOrVoidType: type,
) type {
    return struct {
        const Self = @This();

        pub const Error = error{
            EmptyToken,
            InvalidState,
        } || WriteError;
        const WriteError = if (WriterOrVoidType == void) error{} else WriterOrVoidType.Error;

        const State = enum {
            initial,
            token,
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
                    .initial => if (isTokenChar(c)) {
                        try writeByte(output, c);
                        input.advance(1);
                        self.state = .token;
                    } else return error.EmptyToken,
                    .token => if (isTokenChar(c)) {
                        try writeByte(output, c);
                        input.advance(1);
                    } else {
                        self.state = .finished;
                        return true;
                    },
                    else => return error.InvalidState,
                }
            }
            return input.eof;
        }

        fn writeByte(
            output: WriterOrVoidType,
            b: u8,
        ) WriteError!void {
            if (WriterOrVoidType != void) {
                _ = try output.writeByte(b);
            }
        }
    };
}

const testing = std.testing;
const fifo = std.fifo;

test "TokenParser success with eof" {
    const allocator = testing.allocator;

    const DynamicBuf = fifo.LinearFifo(u8, .Dynamic);
    var output = DynamicBuf.init(allocator);
    defer output.deinit();

    var parser = TokenParser(DynamicBuf.Writer).init();
    var vw = BytesView.init("ab", false);
    try testing.expect(!try parser.parse(&vw, output.writer()));
    try testing.expectEqualStrings("ab", output.readableSlice(0));

    vw = BytesView.init("c", true);
    try testing.expect(try parser.parse(&vw, output.writer()));
    try testing.expectEqualStrings("abc", output.readableSlice(0));
}

test "TokenParser success with delimiter" {
    const allocator = testing.allocator;

    const DynamicBuf = fifo.LinearFifo(u8, .Dynamic);
    var output = DynamicBuf.init(allocator);
    defer output.deinit();

    var parser = TokenParser(DynamicBuf.Writer).init();
    var vw = BytesView.init("ab;", false);
    try testing.expect(try parser.parse(&vw, output.writer()));
    try testing.expectEqualStrings("ab", output.readableSlice(0));

    vw = BytesView.init("c", true);
    try testing.expectError(error.InvalidState, parser.parse(&vw, output.writer()));
}

test "TokenParser empty" {
    var parser = TokenParser(void).init();
    var vw = BytesView.init("\x7f", false);
    try testing.expectError(error.EmptyToken, parser.parse(&vw, {}));
}
