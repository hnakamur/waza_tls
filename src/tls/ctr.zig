const std = @import("std");
const mem = std.mem;
const AesBlock = @import("aes.zig").AesBlock;

pub const Ctr = struct {
    const stream_buffer_size = 512;

    block: AesBlock,
    ctr: []u8,
    out: []u8,
    out_len: usize,
    out_used: usize,

    pub fn init(allocator: mem.Allocator, block: AesBlock, iv: []const u8) !Ctr {
        const block_size = block.block_size();
        if (iv.len != block_size) {
            @panic("Ctr.init: IV length must equal block size");
        }
        const buf_size = std.math.max(block_size, stream_buffer_size);
        var out = try allocator.alloc(u8, buf_size);
        errdefer allocator.free(out);
        mem.set(u8, out, 0);
        return Ctr{
            .block = block,
            .ctr = try allocator.dupe(u8, iv),
            .out = out,
            .out_len = 0,
            .out_used = 0,
        };
    }

    pub fn deinit(self: *Ctr, allocator: mem.Allocator) void {
        allocator.free(self.ctr);
        allocator.free(self.out);
    }

    pub fn xorKeyStream(self: *Ctr, dst: []u8, src: []const u8) void {
        if (dst.len < src.len) {
            @panic("Ctr.xorKeyStream: output smaller than input");
        }

        // TODO: implement and call inexactOverlap

        var src2 = src;
        var dst2 = dst;
        const block_size = self.block.block_size();
        while (src2.len > 0) {
            if (self.out_len < block_size or self.out_used >= self.out_len - block_size) {
                self.refill();
            }
            const n = xorBytes(dst2, src2, self.out[self.out_used..]);
            dst2 = dst2[n..];
            src2 = src2[n..];
            self.out_used += n;
        }
    }

    fn refill(self: *Ctr) void {
        var remain = self.out_len - self.out_used;
        mem.copy(u8, self.out, self.out[self.out_used..]);
        self.out_len = self.out.len;
        const block_size = self.block.block_size();
        while (remain <= self.out_len - block_size) {
            self.block.encrypt(
                self.out[remain..][0..AesBlock.block_length],
                self.ctr[0..AesBlock.block_length],
            );
            remain += block_size;

            // Increment counter
            var i: usize = self.ctr.len - 1;
            while (true) : (i -= 1) {
                self.ctr[i] +%= 1;
                if (self.ctr[i] != 0 or i == 0) {
                    break;
                }
            }
        }
        self.out_len = remain;
        self.out_used = 0;
    }
};

fn xorBytes(dst: []u8, a: []const u8, b: []const u8) usize {
    const n = std.math.min(a.len, b.len);
    var i: usize = 0;
    // TODO: optimize
    while (i < n) : (i += 1) {
        dst[i] = a[i] ^ b[i];
    }
    return n;
}

const testing = std.testing;

test "Ctr.xorKeyStream" {
    testing.log_level = .debug;

    const common_counter = &[_]u8{
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };

    const common_input = &[_]u8{
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };

    const TestCase = struct {
        name: []const u8,
        key: []const u8,
        iv: []const u8,
        in: []const u8,
        out: []const u8,
    };

    const tests = &[_]TestCase{
        .{
            .name = "CTR-AES128",
            .key = &[_]u8{
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
            },
            .iv = common_counter,
            .in = common_input,
            .out = &[_]u8{
                0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
                0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
                0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
                0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
            },
        },
    };

    const allocator = testing.allocator;
    for (tests) |t| {
        var block = try AesBlock.init(t.key);

        var j: usize = 0;
        while (j <= 5) : (j += 1) {
            const in = t.in[0 .. t.in.len - j];
            var c = try Ctr.init(allocator, block, t.iv);
            defer c.deinit(allocator);
            var encrypted = try allocator.alloc(u8, in.len);
            defer allocator.free(encrypted);
            c.xorKeyStream(encrypted, in);
            const want = t.out[0..in.len];
            try testing.expectEqualSlices(u8, want, encrypted);
        }

        j = 0;
        while (j <= 7) : (j += 1) {
            const in = t.out[0 .. t.out.len - j];
            var c = try Ctr.init(allocator, block, t.iv);
            defer c.deinit(allocator);
            var plain = try allocator.alloc(u8, in.len);
            defer allocator.free(plain);
            c.xorKeyStream(plain, in);
            const want = t.in[0..in.len];
            try testing.expectEqualSlices(u8, want, plain);
        }
    }
}

const debug = std.debug;

/// Counter mode.
///
/// This mode creates a key stream by encrypting an incrementing counter using a block cipher, and adding it to the source material.
///
/// Important: the counter mode doesn't provide authenticated encryption: the ciphertext can be trivially modified without this being detected.
/// As a result, applications should generally never use it directly, but only in a construction that includes a MAC.
pub fn ctr(block_cipher: anytype, dst: []u8, src: []const u8, iv: []const u8, endian: std.builtin.Endian) void {
    const BlockCipher = @TypeOf(block_cipher);
    debug.assert(dst.len >= src.len);
    const block_length = BlockCipher.block_length;
    var counter: [BlockCipher.block_length]u8 = undefined;
    var counterInt = mem.readInt(u128, iv[0..@sizeOf(u128)], endian);
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

test "copied crypto.core.modes.ctr" {
    const Aes128 = std.crypto.core.aes.Aes128;

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
    ctr(ctx, out[0..], in[0..], iv[0..], std.builtin.Endian.Big);
    try testing.expectEqualSlices(u8, exp_out[0..], out[0..]);
}
