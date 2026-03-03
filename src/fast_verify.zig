/// Number of random bytes used for verification.
const RAND_BYTES = 8;

/// Number of random bits used for verification.
const RAND_BITS = 8 * RAND_BYTES;

/// Minimum number of elements to use multi-threaded verification.
const MIN_ELEMS_TO_THREAD = 4;

/// Maximum number of worker threads to use.
const MAX_WORKERS = 8;

const WorkerContext = struct {
    pairing_buf: *[Pairing.sizeOf()]u8,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
    sigs: []const *Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
    start: usize,
    end: usize,
    err: bool = false,
};

fn workerFn(ctx: *WorkerContext) void {
    var pairing = Pairing.init(ctx.pairing_buf, true, ctx.dst);
    for (ctx.start..ctx.end) |i| {
        pairing.mulAndAggregate(
            ctx.pks[i],
            ctx.pks_validate,
            ctx.sigs[i],
            ctx.sigs_groupcheck,
            &ctx.rands[i],
            RAND_BITS,
            &ctx.msgs[i],
        ) catch {
            ctx.err = true;
            return;
        };
    }
    pairing.commit();
}

/// Verify multiple aggregate signatures efficiently using random coefficients.
///
/// Uses multiple threads when the number of elements exceeds `MIN_ELEMS_TO_THREAD`.
/// Each thread gets its own `Pairing` context, processes a chunk of elements, commits,
/// and results are merged via `blst_pairing_merge` before final verification.
///
/// Source: https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
///
/// Returns true if verification succeeds, false if verification fails, `BlstError` on error.
pub fn verifyMultipleAggregateSignatures(
    pairing_buf: *align(Pairing.buf_align) [Pairing.sizeOf()]u8,
    n_elems: usize,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
    sigs: []const *Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
) BlstError!bool {
    if (n_elems == 0) {
        return BlstError.VerifyFail;
    }

    const cpu_count = std.Thread.getCpuCount() catch 1;
    const n_workers: usize = if (n_elems < MIN_ELEMS_TO_THREAD) 1 else @min(@min(cpu_count, n_elems), MAX_WORKERS);

    if (n_workers <= 1) {
        var pairing = Pairing.init(pairing_buf, true, dst);
        for (0..n_elems) |i| {
            try pairing.mulAndAggregate(
                pks[i],
                pks_validate,
                sigs[i],
                sigs_groupcheck,
                &rands[i],
                RAND_BITS,
                &msgs[i],
            );
        }
        pairing.commit();
        return pairing.finalVerify(null);
    }

    const allocator = std.heap.c_allocator;

    // Allocate pairing buffers for worker threads (worker 0 uses the caller's pairing_buf)
    const extra_bufs = allocator.alloc([Pairing.sizeOf()]u8, n_workers - 1) catch return BlstError.VerifyFail;
    defer allocator.free(extra_bufs);

    const contexts = allocator.alloc(WorkerContext, n_workers) catch return BlstError.VerifyFail;
    defer allocator.free(contexts);

    // Divide work evenly across workers
    const elems_per_worker = n_elems / n_workers;
    const remainder = n_elems % n_workers;

    var offset: usize = 0;
    for (0..n_workers) |w| {
        const count = elems_per_worker + if (w < remainder) @as(usize, 1) else @as(usize, 0);
        contexts[w] = .{
            .pairing_buf = if (w == 0) pairing_buf else &extra_bufs[w - 1],
            .msgs = msgs,
            .dst = dst,
            .pks = pks,
            .pks_validate = pks_validate,
            .sigs = sigs,
            .sigs_groupcheck = sigs_groupcheck,
            .rands = rands,
            .start = offset,
            .end = offset + count,
        };
        offset += count;
    }

    // Spawn n_workers - 1 threads (main thread handles worker 0)
    const threads = allocator.alloc(std.Thread, n_workers - 1) catch return BlstError.VerifyFail;
    defer allocator.free(threads);

    var spawned: usize = 0;
    errdefer for (threads[0..spawned]) |t| t.join();

    // Main thread does worker 0's work
    workerFn(&contexts[0]);
    for (0..n_workers - 1) |t| {
        threads[t] = std.Thread.spawn(.{}, workerFn, .{&contexts[t + 1]}) catch return BlstError.VerifyFail;
        spawned += 1;
    }

    for (threads[0..spawned]) |t| t.join();

    for (contexts[0..n_workers]) |ctx| {
        if (ctx.err) return BlstError.VerifyFail;
    }

    // Merge all worker pairings into the first one
    var main_pairing: Pairing = .{ .ctx = @ptrCast(pairing_buf) };
    for (1..n_workers) |w| {
        const worker_pairing: Pairing = .{ .ctx = @ptrCast(&extra_bufs[w - 1]) };
        try main_pairing.merge(&worker_pairing);
    }

    return main_pairing.finalVerify(null);
}

const BlstError = @import("error.zig").BlstError;
const Pairing = @import("Pairing.zig");
const blst = @import("root.zig");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const std = @import("std");
