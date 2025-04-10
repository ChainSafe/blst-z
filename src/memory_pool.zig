const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @cImport({
    @cInclude("blst.h");
});

const ScratchSizeOfFn = *const fn (npoints: usize) callconv(.C) usize;

const U64SliceArray = std.ArrayList([]u64);

/// for some apis, for example, aggregateWithRandomness, we have to allocate pk_scratch and sig_scratch buffer
/// since these are not constant, we need to allocate them dynamically
/// due to Zig not having a gc, it's reasonable to have a memory pool so that we can reuse the memory if needed
/// this implementation assumes an application only go with either min_pk or min_sig
/// pk_scratch_sizeof_fn: it's c.blst_p1s_mult_pippenger_scratch_sizeof function for min_pk
/// sig_scratch_sizeof_fn: it's c.blst_p2s_mult_pippenger_scratch_sizeof function for min_sig
pub fn createMemoryPool(comptime scratch_in_batch: usize, comptime pk_scratch_sizeof_fn: ScratchSizeOfFn, comptime sig_scratch_sizeof_fn: ScratchSizeOfFn) type {
    const MemoryPool = struct {
        // aggregateWithRandomness api, application decides number of signatures/publickeys to aggregate in batch
        // for Bun, it's 128
        pk_scratch_size_u64: usize,
        sig_scratch_size_u64: usize,
        pk_scratch_arr: U64SliceArray,
        sig_scratch_arr: U64SliceArray,
        pk_scratch_mutex: std.Thread.Mutex,
        sig_scratch_mutex: std.Thread.Mutex,
        allocator: Allocator,

        // inspired by thread pool implementation, consumer need to do the allocator.create() before this calls
        pub fn init(self: *@This(), allocator: Allocator) !void {
            const pk_scratch_size_u64 = pk_scratch_sizeof_fn(scratch_in_batch) / 8;
            const sig_scratch_size_u64 = sig_scratch_sizeof_fn(scratch_in_batch) / 8;
            self.* = .{
                .pk_scratch_size_u64 = pk_scratch_size_u64,
                .sig_scratch_size_u64 = sig_scratch_size_u64,
                .pk_scratch_arr = try U64SliceArray.initCapacity(allocator, 0),
                .sig_scratch_arr = try U64SliceArray.initCapacity(allocator, 0),
                .allocator = allocator,
                .pk_scratch_mutex = std.Thread.Mutex{},
                .sig_scratch_mutex = std.Thread.Mutex{},
            };
        }

        // consumer need to do the allocator.destroy() after this call
        pub fn deinit(self: *@This()) void {
            // free all the scratch buffers
            for (self.pk_scratch_arr.items) |pk_scratch| {
                self.allocator.free(pk_scratch);
            }
            self.pk_scratch_arr.deinit();

            for (self.sig_scratch_arr.items) |sig_scratch| {
                self.allocator.free(sig_scratch);
            }
            self.sig_scratch_arr.deinit();
        }

        pub fn getPublicKeyScratch(self: *@This()) ![]u64 {
            if (self.pk_scratch_arr.items.len == 0) {
                // allocate new
                return try self.allocator.alloc(u64, self.pk_scratch_size_u64);
            }

            self.pk_scratch_mutex.lock();
            defer self.pk_scratch_mutex.unlock();

            // reuse last
            const last_scratch = self.pk_scratch_arr.pop();
            if (last_scratch.len != self.pk_scratch_size_u64) {
                // this should not happen
                return error.InvalidScratchSize;
            }
            return last_scratch;
        }

        pub fn getSignatureScratch(self: *@This()) ![]u64 {
            if (self.sig_scratch_arr.items.len == 0) {
                // allocate new
                return try self.allocator.alloc(u64, self.sig_scratch_size_u64);
            }

            self.sig_scratch_mutex.lock();
            defer self.sig_scratch_mutex.unlock();

            // reuse last
            const last_scratch = self.sig_scratch_arr.pop();
            if (last_scratch.len != self.sig_scratch_size_u64) {
                // this should not happen
                return error.InvalidScratchSize;
            }
            return last_scratch;
        }

        pub fn returnPublicKeyScratch(self: *@This(), scratch: []u64) !void {
            if (scratch.len != self.pk_scratch_size_u64) {
                // this should not happen
                return error.InvalidScratchSize;
            }

            self.pk_scratch_mutex.lock();
            defer self.pk_scratch_mutex.unlock();
            // return the scratch to the pool
            try self.pk_scratch_arr.append(scratch);
        }

        pub fn returnSignatureScratch(self: *@This(), scratch: []u64) !void {
            if (scratch.len != self.sig_scratch_size_u64) {
                // this should not happen
                return error.InvalidScratchSize;
            }

            self.sig_scratch_mutex.lock();
            defer self.sig_scratch_mutex.unlock();
            // return the scratch to the pool
            try self.sig_scratch_arr.append(scratch);
        }
    };

    return MemoryPool;
}

test "memory pool - public key scratch" {
    const scratch_in_batch = 128;
    const MemoryPool = createMemoryPool(scratch_in_batch, c.blst_p1s_mult_pippenger_scratch_sizeof, c.blst_p2s_mult_pippenger_scratch_sizeof);
    const allocator = std.testing.allocator;
    var pool = try allocator.create(MemoryPool);
    try pool.init(allocator);
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }
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
    const MemoryPool = createMemoryPool(scratch_in_batch, c.blst_p1s_mult_pippenger_scratch_sizeof, c.blst_p2s_mult_pippenger_scratch_sizeof);
    const allocator = std.testing.allocator;
    var pool = try allocator.create(MemoryPool);
    try pool.init(allocator);
    defer {
        pool.deinit();
        allocator.destroy(pool);
    }

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

test "memory pool - multi thread" {
    const scratch_in_batch = 128;
    const MemoryPool = createMemoryPool(scratch_in_batch, c.blst_p1s_mult_pippenger_scratch_sizeof, c.blst_p2s_mult_pippenger_scratch_sizeof);
    const allocator = std.testing.allocator;
    var memory_pool = try allocator.create(MemoryPool);
    try memory_pool.init(allocator);
    const task_count = 64;

    var thread_pool = try allocator.create(std.Thread.Pool);
    // only max 8 jobs in thread pool but task_count is 64
    try thread_pool.init(.{ .allocator = allocator, .n_jobs = 8 });
    defer {
        thread_pool.deinit();
        allocator.destroy(thread_pool);
        memory_pool.deinit();
        allocator.destroy(memory_pool);
    }

    var wg = std.Thread.WaitGroup{};
    var done_count: usize = 0;
    var mutex = std.Thread.Mutex{};

    for (0..task_count) |_| {
        thread_pool.spawnWg(&wg, struct {
            pub fn run(pool: *MemoryPool, done: *usize, m: *std.Thread.Mutex) void {
                const pk_scratch = pool.getPublicKeyScratch() catch return;
                const sig_scratch = pool.getSignatureScratch() catch return;
                defer {
                    pool.returnPublicKeyScratch(pk_scratch) catch {};
                    pool.returnSignatureScratch(sig_scratch) catch {};
                }
                std.time.sleep(1 * std.time.ns_per_ms);
                m.lock();
                defer m.unlock();
                done.* += 1;
            }
        }.run, .{ memory_pool, &done_count, &mutex });
    }

    thread_pool.waitAndWork(&wg);
    try std.testing.expect(done_count == task_count);
    // on MacOS it prints 9, give some leeway for Linux
    try std.testing.expect(memory_pool.pk_scratch_arr.items.len < task_count / 2);
    try std.testing.expect(memory_pool.sig_scratch_arr.items.len < task_count / 2);
}
