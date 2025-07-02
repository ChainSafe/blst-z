const std = @import("std");
const Pool = @import("pool.zig");
const util = @import("util.zig");
const BlstError = util.BlstError;
const check = util.check;
const Variant = @import("variant.zig").Variant;

const Signature = @import("signature.zig").Signature;
const PublicKey = @import("public_key.zig").PublicKey;

pub fn MT(comptime variant: Variant) type {
    const V = variant.Types();

    return struct {
        allocator: std.mem.Allocator,
        pool: Pool,
        pairing_buf: []u8,
        pairing_allocator: std.mem.Allocator,
        pippenger_buf: []u8,
        pippenger_allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            max_threads: usize,
            pairing_scratch_size: usize,
            pippenger_scratch_size: usize,
        ) !@This() {
            const pairing_buf = try allocator.alloc(u8, pairing_scratch_size);
            const pairing_allocator = std.heap.FixedBufferAllocator.init(pairing_buf);
            const pippenger_buf = try allocator.alloc(u8, pippenger_scratch_size);
            const pippenger_allocator = std.heap.FixedBufferAllocator.init(pippenger_buf);
            return .{
                .allocator = allocator,
                .pool = Pool.init(max_threads),
                .pairing_buf = pairing_buf,
                .pairing_allocator = pairing_allocator.threadSafeAllocator(),
                .pippenger_buf = pippenger_buf,
                .pippenger_allocator = pippenger_allocator.threadSafeAllocator(),
            };
        }

        pub fn deinit(self: *Self) void {
            self.pool.deinit();
            self.allocator.free(self.pairing_allocator.buffer);
            self.allocator.free(self.pippenger_allocator.buffer);
        }

        pub const AV = struct {
            task: Pool.Task = .{ .callback = @This().callback },
            sig: *const Signature(variant),
            sig_groupcheck: bool,
            msgs: []const [32]u8,
            dst: []const u8,
            pks: []const *PublicKey(variant),
            pks_validate: bool,
            app_cb: *const fn () BlstError!void,

            pub fn callback(task: *Pool.Task) void {
                const self: *@This() = @alignCast(@fieldParentPtr("task", task));
            }
        };

        pub fn aggregateVerify(
            self: *Self,
            sig: *const Signature(variant),
            sig_groupcheck: bool,
            msgs: []const [32]u8,
            dst: []const u8,
            pks: []const *PublicKey(variant),
            pks_validate: bool,
            cb: *fn (*Pool.Task) void,
        ) BlstError!void {
            // const pairing_scratch = self.pairing_allocator.alloc(u8, )

            self.pool.schedule(callback);
        }
    };
}
