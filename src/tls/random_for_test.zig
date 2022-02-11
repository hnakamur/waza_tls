const std = @import("std");
const mem = std.mem;
const Gimli = std.crypto.core.Gimli;
const Random = std.rand.Random;

pub const RandomForTest = struct {
    gimli: Gimli,

    pub const Error = error{};
    pub const Reader = std.io.Reader(*Self, Error, read);

    const Self = @This();

    pub fn init(initial_state: [Gimli.BLOCKBYTES]u8) RandomForTest {
        return .{ .gimli = Gimli.init(initial_state) };
    }

    pub fn bytes(self: *Self, buffer: []u8) void {
        if (buffer.len != 0) {
            self.gimli.squeeze(buffer);
        } else {
            self.gimli.permute();
        }
        mem.set(u8, self.gimli.toSlice()[0..Gimli.RATE], 0);
    }

    pub fn random(self: *Self) Random {
        return Random.init(self, bytes);
    }

    pub fn read(self: *Self, buffer: []u8) Error!usize {
        self.bytes(buffer);
        return buffer.len;
    }

    pub fn reader(self: *Self) Reader {
        return .{ .context = self };
    }
};

const testing = std.testing;
const fmtx = @import("../fmtx.zig");

test "gimli" {
    const initial = [_]u8{0} ** 48;
    var g = std.crypto.core.Gimli.init(initial);
    g.permute();
    std.debug.print("g={any}\n", .{g});

    const expected1 = [_]u32{
        1684527300, 131921979,  990621908,  455161420,  137638364,  251379342,
        5564548,    1686886741, 1247654958, 3389407691, 2255737538, 774952969,
    };
    try testing.expectEqualSlices(u32, &expected1, &g.data);

    g.permute();
    std.debug.print("g={any}\n", .{g});

    const expected2 = [_]u32{
        4187858519, 4251613304, 2291460841, 4250533253, 2671889682, 644487313,
        3480934449, 4179015401, 3114509800, 1031663185, 4111261949, 4043440222,
    };
    try testing.expectEqualSlices(u32, &expected2, &g.data);
}

test "RandomForTest" {
    const initial = [_]u8{0} ** 48;
    var rand = RandomForTest.init(initial);
    // var rand2 = rand.random();

    const expected = &[_][]const u8{
        "",
        "\x4a",
        "\xd9\xaa",
        "\x47\x5f\x17",
        "\x8c\x46\x12\xaa",
        "\xd7\x54\xeb\xec\x53",
        "\xaa\x6a\x28\xef\xe4\x94",
        "\x3b\x7d\x1d\x4c\x92\x7f\xcc",
        "\x63\xff\xb2\x36\xe2\x30\xf0\x0a",
        "\x26\xaf\xe3\x47\xe1\xb9\xaf\x1e\x36",
        "\xa3\xa0\x63\xcf\xd9\xd8\xf5\x8f\xa9\xcc",
        "\xf3\x73\x00\x14\xc3\xb4\x5e\xcd\x79\x6c\x86",
        "\xc6\xfb\x2c\x1a\x1e\x56\x12\xbe\xd7\x57\xc8\x4b",
        "\xfd\xf9\x03\x3d\x29\x9e\xbb\x56\x52\x67\x61\x95\x47",
        "\x87\x28\x2c\x91\x46\x84\x78\x6c\x74\x61\x11\xbe\x33\xfe",
        "\x19\xab\xed\x9c\xc8\x61\xa1\x0d\xfb\xb2\xf6\x88\x80\x36\x3b",
        "\x7b\x14\xe5\x40\x2f\xa7\x72\xc4\xe0\x92\xa4\xa9\xbb\x20\xd2\x86",
        "\xf2\xec\xf4\xd7\x94\xa0\x3d\x94\x5d\x68\x15\xed\xf7\x64\x74\x4d\x76",
        "\x9c\xf3\xd2\xc7\x6a\x4b\x68\xba\xd9\xf1\xf2\xbe\x0c\x17\x58\x1a\x0a\x1f",
        "\x58\x6f\x9d\x99\x9d\x7a\x75\x19\x4c\xdd\xcc\xaf\xb3\x31\x45\x18\xa4\x63\xe4",
    };

    var buf: [20]u8 = undefined;
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        rand.bytes(buf[0..i]);
        // std.debug.print("{}\n", .{fmtx.fmtSliceHexColonLower(buf[0..i])});
        try testing.expectEqualSlices(u8, expected[i], buf[0..i]);
    }
}
