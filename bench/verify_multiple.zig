const std = @import("std");
const zbench = @import("zbench");
const blst = @import("blst");

const Pairing = blst.Pairing;
const SecretKey = blst.SecretKey;
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const DST = blst.DST;

const MAX_COUNT = 256;

var pks: [MAX_COUNT]PublicKey = undefined;
var pk_ptrs: [MAX_COUNT]*PublicKey = undefined;
var sigs: [MAX_COUNT]Signature = undefined;
var sig_ptrs: [MAX_COUNT]*Signature = undefined;
var msgs: [MAX_COUNT][32]u8 = undefined;
var rands: [MAX_COUNT][32]u8 = undefined;

fn generateTestSets() void {
    for (0..MAX_COUNT) |i| {
        // Deterministic IKM per index
        var ikm: [32]u8 = [_]u8{0} ** 32;
        std.mem.writeInt(u64, ikm[0..8], @intCast(i + 1), .little);

        const sk = SecretKey.keyGen(&ikm, null) catch unreachable;
        pks[i] = sk.toPublicKey();
        pk_ptrs[i] = &pks[i];

        // Deterministic message per index
        msgs[i] = [_]u8{0} ** 32;
        std.mem.writeInt(u64, msgs[i][0..8], @intCast(i), .little);

        sigs[i] = sk.sign(&msgs[i], DST, null);
        sig_ptrs[i] = &sigs[i];

        // Deterministic random scalar per index
        rands[i] = [_]u8{0} ** 32;
        rands[i][0] = @intCast((i % 255) + 1); // must be non-zero
    }
}

fn VerifyMultipleBench(comptime count: usize) type {
    return struct {
        pub fn run(_: @This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            var pairing_buf: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined;
            const result = blst.verifyMultipleAggregateSignatures(
                &pairing_buf,
                count,
                msgs[0..count],
                DST,
                pk_ptrs[0..count],
                false,
                sig_ptrs[0..count],
                false,
                rands[0..count],
            ) catch false;
            std.mem.doNotOptimizeAway(&result);
        }
    };
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const stdout = std.io.getStdOut().writer();

    generateTestSets();

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    try bench.addParam("1 sets", &VerifyMultipleBench(1){}, .{});
    try bench.addParam("8 sets", &VerifyMultipleBench(8){}, .{});
    try bench.addParam("32 sets", &VerifyMultipleBench(32){}, .{});
    try bench.addParam("128 sets", &VerifyMultipleBench(128){}, .{});
    try bench.addParam("256 sets", &VerifyMultipleBench(256){}, .{});

    try bench.run(stdout);
}
