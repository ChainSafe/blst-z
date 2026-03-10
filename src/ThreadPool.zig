//! Thread pool for parallel BLS operations.
//!
//! Provides multi-threaded versions of aggregation and verification functions
//! using a persistent pool of worker threads to avoid thread creation overhead.
const ThreadPool = @This();

const std = @import("std");
const c = @cImport({
    @cInclude("blst.h");
});
const Pairing = @import("Pairing.zig");
const blst = @import("root.zig");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const AggregatePublicKey = blst.AggregatePublicKey;
const AggregateSignature = blst.AggregateSignature;
const BlstError = @import("error.zig").BlstError;
const SecretKey = @import("SecretKey.zig");

pub const MAX_WORKERS: usize = 16;

/// Number of random bits used for verification.
const RAND_BITS = 64;

/// Minimum number of elements before using multi-threaded aggregation.
const AGGREGATION_MT_THRESHOLD = 64;

const PairingBuf = struct {
    data: [Pairing.sizeOf()]u8 align(Pairing.buf_align) = undefined,
};

const WorkItem = union(enum) {
    verify_multi: *VerifyMultiJob,
    aggregate_p1: *AggregateP1Job,
    aggregate_p2: *AggregateP2Job,
};

n_workers: usize,
threads: [MAX_WORKERS - 1]std.Thread = undefined,
work_ready: [MAX_WORKERS]std.Thread.ResetEvent = [_]std.Thread.ResetEvent{.{}} ** MAX_WORKERS,
work_done: [MAX_WORKERS]std.Thread.ResetEvent = [_]std.Thread.ResetEvent{.{}} ** MAX_WORKERS,
work_items: [MAX_WORKERS]?WorkItem = [_]?WorkItem{null} ** MAX_WORKERS,
shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
pairing_bufs: [MAX_WORKERS]PairingBuf = [_]PairingBuf{.{}} ** MAX_WORKERS,
partial_p1: [MAX_WORKERS]c.blst_p1 = undefined,
partial_p2: [MAX_WORKERS]c.blst_p2 = undefined,
has_work: [MAX_WORKERS]bool = [_]bool{false} ** MAX_WORKERS,

var instance: ?*ThreadPool = null;

/// Pairing size is = ~3.1KB * `MAX_WORKERS` = ~50KB
/// We allocate 4 pages (4 * 16KB) for this at startup.
const allocator = std.heap.page_allocator;

/// Returns the global thread pool singleton, creating it if necessary.
pub fn get() *ThreadPool {
    if (instance) |pool| return pool;
    const pool = allocator.create(ThreadPool) catch
        @panic("ThreadPool: failed to allocate");
    pool.* = .{
        .n_workers = blk: {
            const cpu_count = std.Thread.getCpuCount() catch 1;
            // Use 3/4 of available cores: aggregation saturates early so doesn't
            // need all cores, while leaving headroom for the host application
            // (e.g. Node.js event loop, libuv I/O threads).
            break :blk @min(@max(cpu_count * 3 / 4, 2), MAX_WORKERS);
        },
    };
    for (1..pool.n_workers) |i| {
        pool.threads[i - 1] = std.Thread.spawn(.{}, workerLoop, .{ pool, i }) catch
            @panic("ThreadPool: failed to spawn worker");
    }
    instance = pool;
    return pool;
}

/// Shuts down the thread pool and frees resources.
/// The pool pointer is invalid after this call.
pub fn deinit(pool: *ThreadPool) void {
    pool.shutdown.store(true, .release);
    const n_workers = pool.n_workers;
    for (1..n_workers) |i| {
        pool.work_ready[i].set();
    }
    for (pool.threads[0 .. n_workers - 1]) |t| {
        t.join();
    }
    if (instance == pool) instance = null;
    allocator.destroy(pool);
}

fn workerLoop(pool: *ThreadPool, worker_index: usize) void {
    while (true) {
        pool.work_ready[worker_index].wait();
        pool.work_ready[worker_index].reset();

        if (pool.shutdown.load(.acquire)) return;

        const item = pool.work_items[worker_index] orelse {
            pool.work_done[worker_index].set();
            continue;
        };

        switch (item) {
            .verify_multi => |job| execVerifyMulti(pool, job, worker_index),
            .aggregate_p1 => |job| execAggregateP1(pool, job, worker_index),
            .aggregate_p2 => |job| execAggregateP2(pool, job, worker_index),
        }

        pool.work_items[worker_index] = null;
        pool.work_done[worker_index].set();
    }
}

fn dispatch(pool: *ThreadPool) void {
    // Signal background workers before main thread starts
    for (1..pool.n_workers) |i| {
        pool.work_ready[i].set();
    }

    // Main thread executes as worker 0
    if (pool.work_items[0]) |item| {
        switch (item) {
            .verify_multi => |job| execVerifyMulti(pool, job, 0),
            .aggregate_p1 => |job| execAggregateP1(pool, job, 0),
            .aggregate_p2 => |job| execAggregateP2(pool, job, 0),
        }
        pool.work_items[0] = null;
    }

    // Wait for all background workers
    for (1..pool.n_workers) |i| {
        pool.work_done[i].wait();
        pool.work_done[i].reset();
    }
}

/// A worker job to aggregate an array of `PublicKey`s (which are p1 points).
const AggregateP1Job = struct {
    pks: []const PublicKey,
    pks_validate: bool,
    counter: std.atomic.Value(usize),
    err_flag: std.atomic.Value(bool),
    chunk_size: usize,
};

/// Performs aggregation of P1 points.
fn execAggregateP1(pool: *ThreadPool, job: *AggregateP1Job, worker_index: usize) void {
    const n = job.pks.len;
    var first = true;
    var result: c.blst_p1 = undefined;

    while (true) {
        const chunk_idx = job.counter.fetchAdd(1, .monotonic);
        const start = chunk_idx * job.chunk_size;
        if (start >= n) break;
        if (job.err_flag.load(.acquire)) break;
        const end = @min(start + job.chunk_size, n);

        if (job.pks_validate) {
            for (start..end) |i| {
                job.pks[i].validate() catch {
                    job.err_flag.store(true, .release);
                    return;
                };
            }
        }

        for (start..end) |i| {
            if (first) {
                c.blst_p1_from_affine(&result, &job.pks[i].point);
                first = false;
            } else {
                c.blst_p1_add_or_double_affine(&result, &result, &job.pks[i].point);
            }
        }
    }

    pool.has_work[worker_index] = !first;
    if (!first) {
        pool.partial_p1[worker_index] = result;
    }
}

/// Aggregates multiple public keys using the thread pool.
pub fn aggregatePublicKeys(
    pool: *ThreadPool,
    pks: []const PublicKey,
    pks_validate: bool,
) BlstError!AggregatePublicKey {
    if (pks.len == 0) return BlstError.AggrTypeMismatch;

    if (pks.len <= AGGREGATION_MT_THRESHOLD or pool.n_workers <= 1) {
        return AggregatePublicKey.aggregate(pks, pks_validate);
    }

    const chunk_size = @max(pks.len / (pool.n_workers * 4), 16);

    var job = AggregateP1Job{
        .pks = pks,
        .pks_validate = pks_validate,
        .counter = std.atomic.Value(usize).init(0),
        .err_flag = std.atomic.Value(bool).init(false),
        .chunk_size = chunk_size,
    };

    for (0..pool.n_workers) |i| {
        pool.work_items[i] = .{ .aggregate_p1 = &job };
        pool.has_work[i] = false;
    }

    pool.dispatch();

    if (job.err_flag.load(.acquire)) return BlstError.AggrTypeMismatch;

    // Merge partial results from all workers
    var agg_pk = AggregatePublicKey{};
    var found_first = false;
    for (0..pool.n_workers) |i| {
        if (pool.has_work[i]) {
            if (!found_first) {
                agg_pk.point = pool.partial_p1[i];
                found_first = true;
            } else {
                c.blst_p1_add_or_double(&agg_pk.point, &agg_pk.point, &pool.partial_p1[i]);
            }
        }
    }

    return agg_pk;
}

/// A worker job to aggregate an array of `Signature`s (which are p1 points).
const AggregateP2Job = struct {
    sigs: []const Signature,
    sigs_groupcheck: bool,
    counter: std.atomic.Value(usize),
    err_flag: std.atomic.Value(bool),
    chunk_size: usize,
};

/// Performs aggregation of P2 points.
fn execAggregateP2(pool: *ThreadPool, job: *AggregateP2Job, worker_index: usize) void {
    const n = job.sigs.len;
    var first = true;
    var result: c.blst_p2 = undefined;

    while (true) {
        const chunk_idx = job.counter.fetchAdd(1, .monotonic);
        const start = chunk_idx * job.chunk_size;
        if (start >= n) break;
        if (job.err_flag.load(.acquire)) break;
        const end = @min(start + job.chunk_size, n);

        if (job.sigs_groupcheck) {
            for (start..end) |i| {
                job.sigs[i].validate(false) catch {
                    job.err_flag.store(true, .release);
                    return;
                };
            }
        }

        for (start..end) |i| {
            if (first) {
                c.blst_p2_from_affine(&result, &job.sigs[i].point);
                first = false;
            } else {
                c.blst_p2_add_or_double_affine(&result, &result, &job.sigs[i].point);
            }
        }
    }

    pool.has_work[worker_index] = !first;
    if (!first) {
        pool.partial_p2[worker_index] = result;
    }
}

/// Aggregates multiple signatures using the thread pool.
pub fn aggregateSignatures(
    pool: *ThreadPool,
    sigs: []const Signature,
    sigs_groupcheck: bool,
) BlstError!AggregateSignature {
    if (sigs.len == 0) return BlstError.AggrTypeMismatch;

    if (sigs.len <= AGGREGATION_MT_THRESHOLD or pool.n_workers <= 1) {
        return AggregateSignature.aggregate(sigs, sigs_groupcheck);
    }

    const chunk_size = @max(sigs.len / (pool.n_workers * 4), 16);

    var job = AggregateP2Job{
        .sigs = sigs,
        .sigs_groupcheck = sigs_groupcheck,
        .counter = std.atomic.Value(usize).init(0),
        .err_flag = std.atomic.Value(bool).init(false),
        .chunk_size = chunk_size,
    };

    for (0..pool.n_workers) |i| {
        pool.work_items[i] = .{ .aggregate_p2 = &job };
        pool.has_work[i] = false;
    }

    pool.dispatch();

    if (job.err_flag.load(.acquire)) return BlstError.AggrTypeMismatch;

    // Merge partial results from all workers
    var agg_sig = AggregateSignature{};
    var found_first = false;
    for (0..pool.n_workers) |i| {
        if (pool.has_work[i]) {
            if (!found_first) {
                agg_sig.point = pool.partial_p2[i];
                found_first = true;
            } else {
                c.blst_p2_add_or_double(&agg_sig.point, &agg_sig.point, &pool.partial_p2[i]);
            }
        }
    }

    return agg_sig;
}

const VerifyMultiJob = struct {
    pks: []const *PublicKey,
    sigs: []const *Signature,
    msgs: []const [32]u8,
    rands: []const [32]u8,
    dst: []const u8,
    pks_validate: bool,
    sigs_groupcheck: bool,
    counter: std.atomic.Value(usize),
    err_flag: std.atomic.Value(bool),
};

fn execVerifyMulti(pool: *ThreadPool, job: *VerifyMultiJob, worker_index: usize) void {
    var pairing = Pairing.init(
        &pool.pairing_bufs[worker_index].data,
        true,
        job.dst,
    );

    var did_work = false;
    const n_elems = job.pks.len;

    while (true) {
        const i = job.counter.fetchAdd(1, .monotonic);
        if (i >= n_elems) break;
        if (job.err_flag.load(.acquire)) break;

        did_work = true;

        pairing.mulAndAggregate(
            job.pks[i],
            job.pks_validate,
            job.sigs[i],
            job.sigs_groupcheck,
            &job.rands[i],
            RAND_BITS,
            &job.msgs[i],
        ) catch {
            job.err_flag.store(true, .release);
            break;
        };
    }

    if (did_work) pairing.commit();
    pool.has_work[worker_index] = did_work;
}

/// Verifies multiple aggregate signatures in parallel using the thread pool.
///
/// This is the multi-threaded version of the same function in `fast_verify.zig`.
pub fn verifyMultipleAggregateSignatures(
    pool: *ThreadPool,
    n_elems: usize,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
    sigs: []const *Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
) BlstError!bool {
    if (n_elems == 0) return BlstError.VerifyFail;

    // Single-threaded fallback for small inputs or single worker
    if (n_elems <= 2 or pool.n_workers <= 1) {
        const fast_verify = @import("fast_verify.zig");
        return fast_verify.verifyMultipleAggregateSignatures(
            &pool.pairing_bufs[0].data,
            n_elems,
            msgs,
            dst,
            pks,
            pks_validate,
            sigs,
            sigs_groupcheck,
            rands,
        );
    }

    var job = VerifyMultiJob{
        .pks = pks[0..n_elems],
        .sigs = sigs[0..n_elems],
        .msgs = msgs[0..n_elems],
        .rands = rands[0..n_elems],
        .dst = dst,
        .pks_validate = pks_validate,
        .sigs_groupcheck = sigs_groupcheck,
        .counter = std.atomic.Value(usize).init(0),
        .err_flag = std.atomic.Value(bool).init(false),
    };

    for (0..pool.n_workers) |i| {
        pool.work_items[i] = .{ .verify_multi = &job };
        pool.has_work[i] = false;
    }

    pool.dispatch();

    if (job.err_flag.load(.acquire)) return BlstError.VerifyFail;

    var acc_idx: ?usize = null;
    for (0..pool.n_workers) |i| {
        if (pool.has_work[i]) {
            acc_idx = i;
            break;
        }
    }

    const first = acc_idx orelse return BlstError.VerifyFail;
    var acc = Pairing{ .ctx = @ptrCast(&pool.pairing_bufs[first].data) };

    for (first + 1..pool.n_workers) |i| {
        if (pool.has_work[i]) {
            const other = Pairing{ .ctx = @ptrCast(&pool.pairing_bufs[i].data) };
            acc.merge(&other) catch return false;
        }
    }

    return acc.finalVerify(null);
}

const DST = blst.DST;
const MAX_AGGREGATE_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;

test "aggregatePublicKeys matches single-threaded" {
    const pool = ThreadPool.get();
    defer pool.deinit();

    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const num_pks = 256;
    var pks: [num_pks]PublicKey = undefined;
    for (&pks, 0..) |*pk, i| {
        var ikm_i = ikm;
        ikm_i[0] = @intCast(i & 0xff);
        ikm_i[1] = @intCast((i >> 8) & 0xff);
        const sk = try SecretKey.keyGen(&ikm_i, null);
        pk.* = sk.toPublicKey();
    }

    const st_result = try AggregatePublicKey.aggregate(&pks, false);
    const mt_result = try pool.aggregatePublicKeys(&pks, false);

    const st_pk = st_result.toPublicKey();
    const mt_pk = mt_result.toPublicKey();
    try std.testing.expect(st_pk.isEqual(&mt_pk));
}

test "aggregateSignatures matches single-threaded" {
    const pool = ThreadPool.get();
    defer pool.deinit();

    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const num_sigs = 256;
    var sigs: [num_sigs]Signature = undefined;
    for (&sigs, 0..) |*sig, i| {
        var ikm_i = ikm;
        ikm_i[0] = @intCast(i & 0xff);
        ikm_i[1] = @intCast((i >> 8) & 0xff);
        const sk = try SecretKey.keyGen(&ikm_i, null);
        var msg: [32]u8 = undefined;
        msg[0] = @intCast(i & 0xff);
        sig.* = sk.sign(&msg, DST, null);
    }

    const st_result = try AggregateSignature.aggregate(&sigs, false);
    const mt_result = try pool.aggregateSignatures(&sigs, false);

    const st_sig = st_result.toSignature();
    const mt_sig = mt_result.toSignature();
    try std.testing.expect(st_sig.isEqual(&mt_sig));
}

test "verifyMultipleAggregateSignatures multi-threaded" {
    const pool = ThreadPool.get();
    defer pool.deinit();

    const ikm: [32]u8 = .{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const num_sigs = 16;

    var msgs: [num_sigs][32]u8 = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]Signature = undefined;
    var pk_ptrs: [num_sigs]*PublicKey = undefined;
    var sig_ptrs: [num_sigs]*Signature = undefined;

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
        break :blk seed;
    });
    const rand = prng.random();

    for (0..num_sigs) |i| {
        std.Random.bytes(rand, &msgs[i]);
        var ikm_i = ikm;
        ikm_i[0] = @intCast(i & 0xff);
        const sk = try SecretKey.keyGen(&ikm_i, null);
        pks[i] = sk.toPublicKey();
        sigs[i] = sk.sign(&msgs[i], DST, null);
        pk_ptrs[i] = &pks[i];
        sig_ptrs[i] = &sigs[i];
    }

    var rands: [num_sigs][32]u8 = undefined;
    for (&rands) |*r| std.Random.bytes(rand, r);

    const result = try pool.verifyMultipleAggregateSignatures(
        num_sigs,
        &msgs,
        DST,
        &pk_ptrs,
        true,
        &sig_ptrs,
        true,
        &rands,
    );

    try std.testing.expect(result);
}
