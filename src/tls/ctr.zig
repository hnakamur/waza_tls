const std = @import("std");

// pub fn Ctr()

const mem = std.mem;
const debug = std.debug;

/// Counter mode.
///
/// This mode creates a key stream by encrypting an incrementing counter using a block cipher, and adding it to the source material.
///
/// Important: the counter mode doesn't provide authenticated encryption: the ciphertext can be trivially modified without this being detected.
/// As a result, applications should generally never use it directly, but only in a construction that includes a MAC.
pub fn ctr(comptime BlockCipher: anytype, block_cipher: BlockCipher, dst: []u8, src: []const u8, iv: [BlockCipher.block_length]u8, endian: std.builtin.Endian) void {
    debug.assert(dst.len >= src.len);
    const block_length = BlockCipher.block_length;
    var counter: [BlockCipher.block_length]u8 = undefined;
    var counterInt = mem.readInt(u128, &iv, endian);
    var i: usize = 0;

    const parallel_count = BlockCipher.block.parallel.optimal_parallel_blocks;
    const wide_block_length = parallel_count * 16;
    if (src.len >= wide_block_length) {
        var counters: [parallel_count * 16]u8 = undefined;
        while (i + wide_block_length <= src.len) : (i += wide_block_length) {
            comptime var j = 0;
            inline while (j < parallel_count) : (j += 1) {
                mem.writeInt(u128, counters[j * 16 .. j * 16 + 16], counterInt, endian);
                counterInt +%= 1;
            }
            block_cipher.xorWide(parallel_count, dst[i .. i + wide_block_length][0..wide_block_length], src[i .. i + wide_block_length][0..wide_block_length], counters);
        }
    }
    while (i + block_length <= src.len) : (i += block_length) {
        mem.writeInt(u128, &counter, counterInt, endian);
        counterInt +%= 1;
        block_cipher.xor(dst[i .. i + block_length][0..block_length], src[i .. i + block_length][0..block_length], counter);
    }
    if (i < src.len) {
        mem.writeInt(u128, &counter, counterInt, endian);
        var pad = [_]u8{0} ** block_length;
        mem.copy(u8, &pad, src[i..]);
        block_cipher.xor(&pad, &pad, counter);
        mem.copy(u8, dst[i..], pad[0 .. src.len - i]);
    }
}

const testing = std.testing;

test "copied crypto.core.modes.ctr" {
    const Aes128 = std.crypto.core.aes.Aes128;
    const AesEncryptCtx = std.crypto.core.aes.AesEncryptCtx;

    // NIST SP 800-38A pp 55-58
    const key = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const iv = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    const in = [_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const exp_out = [_]u8{
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
        0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
        0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
        0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
    };

    var out: [exp_out.len]u8 = undefined;
    var ctx = Aes128.initEnc(key);
    ctr(AesEncryptCtx(Aes128), ctx, out[0..], in[0..], iv, std.builtin.Endian.Big);
    try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
}
