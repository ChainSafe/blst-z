const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @cImport({
    @cInclude("blst.h");
});

pub const MemoryPoolMinPk = MemoryPool(
    @import("root.zig").MAX_AGGREGATE_PER_JOB,
    c.blst_p1s_mult_pippenger_scratch_sizeof,
    c.blst_p2s_mult_pippenger_scratch_sizeof,
    @import("Pairing.zig").sizeOf,
);

/// for some apis, for example, aggregateWithRandomness, we have to allocate pk_scratch and sig_scratch buffer
/// since these are not constant, we need to allocate them dynamically
/// due to Zig not having a gc, it's reasonable to have a memory pool so that we can reuse the memory if needed
/// this implementation assumes an application only go with either min_pk or min_sig
/// pk_scratch_sizeof_fn: it's c.blst_p1s_mult_pippenger_scratch_sizeof function for min_pk
/// sig_scratch_sizeof_fn: it's c.blst_p2s_mult_pippenger_scratch_sizeof function for min_sig
pub fn MemoryPool(
    comptime scratch_in_batch: usize,
    comptime pk_scratch_sizeof_fn: *const fn (npoints: usize) callconv(.C) usize,
    comptime sig_scratch_sizeof_fn: *const fn (npoints: usize) callconv(.C) usize,
    comptime pairing_sizeof_fn: *const fn () usize,
) type {
    return struct {
        const Self = @This();
        // aggregateWithRandomness api, application decides number of signatures/publickeys to aggregate in batch
        // for Bun, it's 128
        pk_scratch_size_u64: usize,
        sig_scratch_size_u64: usize,
        pairing_size_u8: usize,
        pk_scratch_arr: std.ArrayList([]u64),
        sig_scratch_arr: std.ArrayList([]u64),
        pairing_buffer_arr: std.ArrayList([]u8),
        pk_scratch_mutex: std.Thread.Mutex,
        sig_scratch_mutex: std.Thread.Mutex,
        pairing_mutex: std.Thread.Mutex,
        allocator: Allocator,

        // inspired by thread pool implementation, consumer need to do the allocator.create() before this calls
        pub fn init(allocator: Allocator) !Self {
            const pk_scratch_size_u64 = pk_scratch_sizeof_fn(scratch_in_batch) / 8;
            const sig_scratch_size_u64 = sig_scratch_sizeof_fn(scratch_in_batch) / 8;
            return .{
                .pk_scratch_size_u64 = pk_scratch_size_u64,
                .sig_scratch_size_u64 = sig_scratch_size_u64,
                .pairing_size_u8 = pairing_sizeof_fn(),
                .pk_scratch_arr = try std.ArrayList([]u64).initCapacity(allocator, 0),
                .sig_scratch_arr = try std.ArrayList([]u64).initCapacity(allocator, 0),
                .pairing_buffer_arr = try std.ArrayList([]u8).initCapacity(allocator, 0),
                .allocator = allocator,
                .pk_scratch_mutex = std.Thread.Mutex{},
                .sig_scratch_mutex = std.Thread.Mutex{},
                .pairing_mutex = std.Thread.Mutex{},
            };
        }

        // consumer need to do the allocator.destroy() after this call
        pub fn deinit(self: *Self) void {
            // free all the scratch buffers
            for (self.pk_scratch_arr.items) |pk_scratch| {
                self.allocator.free(pk_scratch);
            }
            self.pk_scratch_arr.deinit();

            for (self.sig_scratch_arr.items) |sig_scratch| {
                self.allocator.free(sig_scratch);
            }
            self.sig_scratch_arr.deinit();

            for (self.pairing_buffer_arr.items) |pairing_buffer| {
                self.allocator.free(pairing_buffer);
            }
            self.pairing_buffer_arr.deinit();
        }

        pub fn getPublicKeyScratch(self: *Self) ![]u64 {
            self.pk_scratch_mutex.lock();
            defer self.pk_scratch_mutex.unlock();

            if (self.pk_scratch_arr.items.len == 0) {
                // allocate new
                return try self.allocator.alloc(u64, self.pk_scratch_size_u64);
            }

            // reuse last
            const opt_last_scratch = self.pk_scratch_arr.pop();
            if (opt_last_scratch) |last_scratch| {
                if (last_scratch.len != self.pk_scratch_size_u64) {
                    // this should not happen
                    return error.InvalidScratchSize;
                }
                return last_scratch;
            } else {
                // this should not happen
                return error.NotFound;
            }
        }

        pub fn getSignatureScratch(self: *Self) ![]u64 {
            self.sig_scratch_mutex.lock();
            defer self.sig_scratch_mutex.unlock();

            if (self.sig_scratch_arr.items.len == 0) {
                // allocate new
                return try self.allocator.alloc(u64, self.sig_scratch_size_u64);
            }

            // reuse last
            const optional_last_scratch = self.sig_scratch_arr.pop();
            if (optional_last_scratch) |last_scratch| {
                if (last_scratch.len != self.sig_scratch_size_u64) {
                    // this should not happen
                    return error.InvalidScratchSize;
                }
                return last_scratch;
            } else {
                // this should not happen
                return error.NotFound;
            }
        }

        pub fn getPairingBuffer(self: *Self) ![]u8 {
            self.pairing_mutex.lock();
            defer self.pairing_mutex.unlock();

            if (self.pairing_buffer_arr.items.len == 0) {
                // allocate new
                return try self.allocator.alloc(u8, self.pairing_size_u8);
            }

            // reuse last
            const opt_pairing_buffer = self.pairing_buffer_arr.pop();
            if (opt_pairing_buffer) |pairing_buffer| {
                if (pairing_buffer.len != self.pairing_size_u8) {
                    // this should not happen
                    return error.InvalidPairingBufferSize;
                }
                return pairing_buffer;
            } else {
                // this should not happen
                return error.NotFound;
            }
        }

        pub fn returnPublicKeyScratch(self: *Self, scratch: []u64) !void {
            self.pk_scratch_mutex.lock();
            defer self.pk_scratch_mutex.unlock();

            if (scratch.len != self.pk_scratch_size_u64) {
                // this should not happen
                return error.InvalidScratchSize;
            }

            // return the scratch to the pool
            try self.pk_scratch_arr.append(scratch);
        }

        pub fn returnSignatureScratch(self: *Self, scratch: []u64) !void {
            self.sig_scratch_mutex.lock();
            defer self.sig_scratch_mutex.unlock();

            if (scratch.len != self.sig_scratch_size_u64) {
                // this should not happen
                return error.InvalidScratchSize;
            }

            // return the scratch to the pool
            try self.sig_scratch_arr.append(scratch);
        }

        pub fn returnPairingBuffer(self: *Self, buffer: []u8) !void {
            self.pairing_mutex.lock();
            defer self.pairing_mutex.unlock();

            if (buffer.len != self.pairing_size_u8) {
                // this should not happen
                return error.InvalidPairingBufferSize;
            }

            // return the pairing buffer to the pool
            try self.pairing_buffer_arr.append(buffer);
        }
    };
}

test "memory pool - public key scratch" {
    const scratch_in_batch = 128;
    const Pool = MemoryPool(scratch_in_batch, c.blst_p1s_mult_pippenger_scratch_sizeof, c.blst_p2s_mult_pippenger_scratch_sizeof, struct {
        pub fn pairingSizeOfFn() usize {
            return 32;
        }
    }.pairingSizeOfFn);
    const allocator = std.testing.allocator;
    var pool = try Pool.init(allocator);
    defer pool.deinit();
    try std.testing.expect(pool.pk_scratch_arr.items.len == 0);
    // allocate new
    var pk_scratch_0 = try pool.getPublicKeyScratch();
    try std.testing.expect(pool.pk_scratch_arr.items.len == 0);
    try pool.returnPublicKeyScratch(pk_scratch_0);
    try std.testing.expect(pool.pk_scratch_arr.items.len == 1);

    // reuse
    pk_scratch_0 = try pool.getPublicKeyScratch();
    // no need to allocate again
    try std.testing.expect(pool.pk_scratch_arr.items.len == 0);
    defer allocator.free(pk_scratch_0);
}

test "memory pool - signature scratch" {
    const scratch_in_batch = 128;
    const Pool = MemoryPool(scratch_in_batch, c.blst_p1s_mult_pippenger_scratch_sizeof, c.blst_p2s_mult_pippenger_scratch_sizeof, struct {
        pub fn pairingSizeOfFn() usize {
            return 32;
        }
    }.pairingSizeOfFn);
    const allocator = std.testing.allocator;
    var pool = try Pool.init(allocator);
    defer pool.deinit();

    try std.testing.expect(pool.sig_scratch_arr.items.len == 0);
    // allocate new
    var sig_scratch_0 = try pool.getSignatureScratch();
    try std.testing.expect(pool.sig_scratch_arr.items.len == 0);
    try pool.returnSignatureScratch(sig_scratch_0);
    try std.testing.expect(pool.sig_scratch_arr.items.len == 1);

    // reuse
    sig_scratch_0 = try pool.getSignatureScratch();
    // no need to allocate again
    try std.testing.expect(pool.sig_scratch_arr.items.len == 0);
    defer allocator.free(sig_scratch_0);
}

test "memory pool - pairing buffer" {
    const scratch_in_batch = 128;
    const Pool = MemoryPool(scratch_in_batch, c.blst_p1s_mult_pippenger_scratch_sizeof, c.blst_p2s_mult_pippenger_scratch_sizeof, struct {
        pub fn pairingSizeOfFn() usize {
            return 32;
        }
    }.pairingSizeOfFn);
    const allocator = std.testing.allocator;
    var pool = try Pool.init(allocator);
    defer pool.deinit();

    try std.testing.expect(pool.pairing_buffer_arr.items.len == 0);
    // allocate new
    var pairing_buffer_0 = try pool.getPairingBuffer();
    try std.testing.expect(pool.pairing_buffer_arr.items.len == 0);
    try pool.returnPairingBuffer(pairing_buffer_0);
    try std.testing.expect(pool.pairing_buffer_arr.items.len == 1);

    // reuse
    pairing_buffer_0 = try pool.getPairingBuffer();
    // no need to allocate again
    try std.testing.expect(pool.pairing_buffer_arr.items.len == 0);
    defer allocator.free(pairing_buffer_0);
}

test "memory pool - multi thread" {
    const scratch_in_batch = 128;
    const Pool = MemoryPool(scratch_in_batch, c.blst_p1s_mult_pippenger_scratch_sizeof, c.blst_p2s_mult_pippenger_scratch_sizeof, struct {
        pub fn pairingSizeOfFn() usize {
            return 32;
        }
    }.pairingSizeOfFn);
    const allocator = std.testing.allocator;
    var pool = try Pool.init(allocator);
    const task_count = 64;

    var thread_pool = try allocator.create(std.Thread.Pool);
    // only max 8 jobs in thread pool but task_count is 64
    try thread_pool.init(.{ .allocator = allocator, .n_jobs = 8 });
    defer {
        thread_pool.deinit();
        allocator.destroy(thread_pool);
        pool.deinit();
    }

    var wg = std.Thread.WaitGroup{};
    var done_count: usize = 0;
    var mutex = std.Thread.Mutex{};

    for (0..task_count) |_| {
        thread_pool.spawnWg(&wg, struct {
            pub fn run(pool_: *Pool, done: *usize, m: *std.Thread.Mutex) void {
                const pk_scratch = pool_.getPublicKeyScratch() catch return;
                const sig_scratch = pool_.getSignatureScratch() catch return;
                const pairing_buffer = pool_.getPairingBuffer() catch return;
                defer {
                    pool_.returnPublicKeyScratch(pk_scratch) catch {};
                    pool_.returnSignatureScratch(sig_scratch) catch {};
                    pool_.returnPairingBuffer(pairing_buffer) catch {};
                }
                std.time.sleep(1 * std.time.ns_per_ms);
                m.lock();
                defer m.unlock();
                done.* += 1;
            }
        }.run, .{ &pool, &done_count, &mutex });
    }

    thread_pool.waitAndWork(&wg);
    try std.testing.expect(done_count == task_count);
    // on MacOS it prints 9, give some leeway for Linux
    try std.testing.expect(pool.pk_scratch_arr.items.len < task_count / 2);
    try std.testing.expect(pool.sig_scratch_arr.items.len < task_count / 2);
    try std.testing.expect(pool.pairing_buffer_arr.items.len < task_count / 2);
}
