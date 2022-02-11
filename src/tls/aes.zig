const std = @import("std");
const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

pub const AesBlock = struct {
    key: []const u8,

    const block_length = std.crypto.core.aes.Block.block_length;
    const byte_bits = @bitSizeOf(u8);
    const aes128_key_bytes = Aes128.key_bits / @bitSizeOf(u8);
    const aes256_key_bytes = Aes256.key_bits / @bitSizeOf(u8);

    // Caller must owns the memory for the key until later call of encrypt
    // is finished.
    pub fn init(key: []const u8) !AesBlock {
        switch (key.len) {
            aes128_key_bytes, aes256_key_bytes => {},
            192 / @bitSizeOf(u8) => return error.UnsupportedKeySize,
            else => return error.InvalidKeySize,
        }
        return AesBlock{ .key = key };
    }

    pub fn block_size(self: AesBlock) usize {
        _ = self;
        return block_length;
    }

    pub fn encrypt(self: AesBlock, out: *[block_length]u8, src: *const [block_length]u8) void {
        switch (self.key.len) {
            aes128_key_bytes => {
                const ctx = Aes128.initEnc(self.key[0..aes128_key_bytes].*);
                ctx.encrypt(out, src);
            },
            aes256_key_bytes => {
                const ctx = Aes256.initEnc(self.key[0..aes256_key_bytes].*);
                ctx.encrypt(out, src);
            },
            else => unreachable,
        }
    }
};

const testing = std.testing;

test "AesBlock.encrypt" {
    // Appendix B
    {
        const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
        const in = [_]u8{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
        const exp_out = [_]u8{ 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };

        var out: [exp_out.len]u8 = undefined;
        var block = try AesBlock.init(&key);
        block.encrypt(out[0..], in[0..]);
        try testing.expectEqual(@as(usize, 16), block.block_size());
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }

    // Appendix C.3
    {
        const key = [_]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };
        const in = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
        const exp_out = [_]u8{ 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

        var out: [exp_out.len]u8 = undefined;
        var block = try AesBlock.init(&key);
        block.encrypt(out[0..], in[0..]);
        try testing.expectEqual(@as(usize, 16), block.block_size());
        try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
    }
}
