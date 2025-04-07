const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @cImport({
    @cInclude("blst.h");
});

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

// for min_pk, it's  c.blst_p1s_mult_pippenger_scratch_sizeof function
const PkScratchSizeOfFn = *const fn (npoints: usize) callconv(.C) usize;
// for min_pk, it's c.blst_p2s_mult_pippenger_scratch_sizeof function
const SigScratchSizeOfFn = *const fn (npoints: usize) callconv(.C) usize;

const U8ArrayArray = std.ArrayList([]u8);

/// for some apis, for example, aggregateWithRandomness, we have to allocate pk_scratch and sig_scratch buffer
/// since these are not constant, we need to allocate them dynamically
/// due to Zig not having a gc, it's reasonable to have a memory pool so that we can reuse the memory if needed
/// this implementation assumes an application only go with either min_pk or min_sig
pub fn createMemoryPool(comptime scratch_in_batch: usize, comptime pk_scratch_sizeof_fn: PkScratchSizeOfFn, comptime sig_scratch_sizeof_fn: SigScratchSizeOfFn) type {
    const MemoryPool = struct {
        // aggregateWithRandomness api, application decides number of signatures/publickeys to aggregate in batch
        // for Bun, it's 128
        pk_scratch_arr: U8ArrayArray,
        sig_scratch_arr: U8ArrayArray,
        allocator: Allocator,

        pub fn init(in_allocator: ?Allocator) !@This() {
            const allocator = in_allocator orelse gpa.allocator();
            return @This(){
                .pk_scratch_arr = try U8ArrayArray.initCapacity(allocator, 0),
                .sig_scratch_arr = try U8ArrayArray.initCapacity(allocator, 0),
                .allocator = allocator,
            };
        }

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

        pub fn getPublicKeyScratch(self: *@This()) ![]u8 {
            const pk_scratch_size = pk_scratch_sizeof_fn(scratch_in_batch);
            if (self.pk_scratch_arr.items.len == 0) {
                // allocate new
                return try self.allocator.alloc(u8, pk_scratch_size);
            }

            // reuse last
            const last_scratch = self.pk_scratch_arr.pop();
            if (last_scratch.len != pk_scratch_size) {
                // this should not happen
                return error.InvalidScratchSize;
            }
            return last_scratch;
        }

        pub fn getSignatureScratch(self: *@This()) ![]u8 {
            const sig_scratch_size = sig_scratch_sizeof_fn(scratch_in_batch);
            if (self.sig_scratch_arr.items.len == 0) {
                // allocate new
                return try self.allocator.alloc(u8, sig_scratch_size);
            }

            // reuse last
            const last_scratch = self.sig_scratch_arr.pop();
            if (last_scratch.len != sig_scratch_size) {
                // this should not happen
                return error.InvalidScratchSize;
            }
            return last_scratch;
        }

        pub fn returnPublicKeyScratch(self: *@This(), scratch: []u8) !void {
            const pk_scratch_size = pk_scratch_sizeof_fn(scratch_in_batch);
            if (scratch.len != pk_scratch_size) {
                // this should not happen
                return error.InvalidScratchSize;
            }

            // return the scratch to the pool
            try self.pk_scratch_arr.append(scratch);
        }

        pub fn returnSignatureScratch(self: *@This(), scratch: []u8) !void {
            const sig_scratch_size = sig_scratch_sizeof_fn(scratch_in_batch);
            if (scratch.len != sig_scratch_size) {
                // this should not happen
                return error.InvalidScratchSize;
            }

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
    var pool = try MemoryPool.init(allocator);
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
    const MemoryPool = createMemoryPool(scratch_in_batch, c.blst_p1s_mult_pippenger_scratch_sizeof, c.blst_p2s_mult_pippenger_scratch_sizeof);
    const allocator = std.testing.allocator;
    var pool = try MemoryPool.init(allocator);
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
