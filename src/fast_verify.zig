/// Number of random bytes used for verification.
const RAND_BYTES = 8;

/// Number of random bits used for verification.
const RAND_BITS = 8 * RAND_BYTES;

/// Verify multiple aggregate signatures efficiently using random coefficients.
///
/// Uses multiple threads when available. Each thread gets its own `Pairing`
/// context, processes work items via atomic counter, commits, and results are
/// merged sequentially on the main thread before final verification.
///
/// Source: https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
///
/// Returns true if verification succeeds, false otherwise.
pub fn verifyMultipleAggregateSignatures(
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *const PublicKey,
    pks_validate: bool,
    sigs: []const *const Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
    alloc: Allocator,
) BlstError!bool {
    const n_elems = pks.len;
    if (n_elems == 0 or
        msgs.len != n_elems or
        sigs.len != n_elems or
        rands.len != n_elems)
    {
        return BlstError.VerifyFail;
    }

    const cpu_count = @max(1, std.Thread.getCpuCount() catch 1);
    const n_workers = @min(@min(cpu_count, n_elems), MAX_WORKERS);

    var wg = std.Thread.WaitGroup{};
    const valid = std.atomic.Value(bool).init(true);

    const mem_pool = tp.getMemoryPool();

    // Each worker gets its own pairing buffer and Pairing context.
    // After all workers finish, we merge sequentially on the main thread.
    var pairing_bufs: [MAX_WORKERS][]u8 = undefined;
    var pairings: [MAX_WORKERS]Pairing = undefined;
    var worker_count: usize = 0;

    defer {
        if (mem_pool) |pool| {
            for (0..worker_count) |i| pool.returnPairingBuffer(pairing_bufs[i]) catch {};
        } else {
            for (0..worker_count) |i| alloc.free(pairing_bufs[i]);
        }
    }

    for (0..n_workers) |i| {
        pairing_bufs[i] = if (mem_pool) |pool|
            pool.getPairingBuffer() catch return BlstError.VerifyFail
        else
            alloc.alloc(u8, Pairing.sizeOf()) catch return BlstError.VerifyFail;
        pairings[i] = Pairing.init(
            @ptrCast(@alignCast(pairing_bufs[i].ptr)),
            true,
            dst,
        );
        worker_count += 1;
    }

    const counter = std.atomic.Value(usize).init(0);

    for (0..n_workers) |i| {
        tp.spawnTaskWg(&wg, struct {
            fn run(
                pairing: *Pairing,
                _valid: *const std.atomic.Value(bool),
                _counter: *const std.atomic.Value(usize),
                _n_elems: usize,
                _pks: []const *const PublicKey,
                _pks_validate: bool,
                _sigs: []const *const Signature,
                _sigs_groupcheck: bool,
                _rands: []const [32]u8,
                _msgs: []const [32]u8,
            ) void {
                while (_valid.load(.monotonic)) {
                    const work = @as(*std.atomic.Value(usize), @constCast(_counter)).fetchAdd(1, .monotonic);
                    if (work >= _n_elems) break;

                    pairing.mulAndAggregate(
                        _pks[work],
                        _pks_validate,
                        _sigs[work],
                        _sigs_groupcheck,
                        &_rands[work],
                        RAND_BITS,
                        &_msgs[work],
                    ) catch {
                        @as(*std.atomic.Value(bool), @constCast(_valid)).store(false, .monotonic);
                        return;
                    };
                }

                if (_valid.load(.monotonic)) {
                    pairing.commit();
                }
            }
        }.run, .{
            &pairings[i],
            &valid,
            &counter,
            n_elems,
            pks,
            pks_validate,
            sigs,
            sigs_groupcheck,
            rands,
            msgs,
        });
    }

    tp.waitAndWork(&wg);

    for (1..n_workers) |i| {
        pairings[0].merge(&pairings[i]) catch return BlstError.VerifyFail;
    }

    return valid.load(.monotonic) and pairings[0].finalVerify(null);
}

const MAX_WORKERS = 8;

const Allocator = std.mem.Allocator;
const BlstError = @import("error.zig").BlstError;
const Pairing = @import("Pairing.zig");
const blst = @import("root.zig");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const std = @import("std");
const tp = @import("thread_pool.zig");
