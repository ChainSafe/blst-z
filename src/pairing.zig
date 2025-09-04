const std = @import("std");
const Allocator = std.mem.Allocator;
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const Variant = @import("variant.zig").Variant;
const c = @import("c.zig");

pub const pairing_size = Pairing(.min_pk).sizeOf();

pub fn Pairing(comptime variant: Variant) type {
    const V = variant.Types();

    return extern struct {
        ctx: *c.blst_pairing,

        pub const Error = error{ BufferTooSmall, DstTooSmall, OutOfMemory, InvalidPairingBufferSize, NotFound };
        const Self = @This();

        /// Rust always use a heap allocation here, but adding an allocator as param for Zig is too complex
        /// instead of that we provide a buffer that's big enough for the struct to operate on so that:
        /// - it does not have allocator in its api
        /// - can use stack allocation at consumer side
        /// - can reuse memory if it makes sense at consumer side
        pub fn init(buffer: *[Self.sizeOf()]u8, hash_or_encode: bool, dst: []const u8) Error!Self {
            std.debug.assert(buffer.len == Self.sizeOf());

            if (dst.len == 0) {
                return Error.DstTooSmall;
            }

            const obj = Self{
                .ctx = @ptrCast(buffer),
            };
            c.blst_pairing_init(obj.ctx, hash_or_encode, @ptrCast(dst.ptr), dst.len);

            return obj;
        }

        /// Calculate the size of the internal (opaque) C type here in order to compute the pairing size at comptime
        ///
        /// This is safe because blst is statically linked to this binding
        pub fn sizeOf() usize {
            const vec384_size = 384 / @sizeOf(usize);
            const vec384fp12_size = vec384_size * 12;

            const point_e1_affine_size = vec384_size * 2;
            const point_e2_size = vec384_size * 2 * 3;
            const point_e2_affine_size = vec384_size * 2 * 2;

            const N_MAX = 8;

            const p: usize =
                @sizeOf(c_int) * 2 + // ctrl and nelems
                @sizeOf(usize) * 2 + // DST and DST_len
                vec384fp12_size + // GT
                point_e2_size + // AggrSign
                point_e2_affine_size * N_MAX + // Q
                point_e1_affine_size * N_MAX; // P

            // Same 8-byte rounding as the library
            return (p + 7) & ~@as(usize, 7);
        }

        pub fn aggregate(
            self: *Self,
            pk: *const V.Pk,
            pk_validate: bool,
            sig: ?*const V.Sig,
            sig_groupcheck: bool,
            msg: []const u8,
            aug: ?[]const u8,
        ) BlstError!void {
            try check(
                V.pairing_aggregate(
                    self.ctx(),
                    pk,
                    pk_validate,
                    sig,
                    sig_groupcheck,
                    msg,
                    msg.len,
                    aug,
                    if (aug) |a| a.len else 0,
                ),
            );
        }

        // TODO: msgs and scalar should have len > 0
        // check for other apis as well
        pub fn mulAndAggregate(
            self: *Self,
            pk: *const V.Pk,
            pk_validate: bool,
            sig: *const V.Sig,
            sig_groupcheck: bool,
            scalar: []const u8,
            nbits: usize,
            msg: []const u8,
            aug: ?[]const u8,
        ) BlstError!void {
            try check(
                V.pairing_mul_and_aggregate(
                    self.ctx,
                    pk,
                    pk_validate,
                    sig,
                    sig_groupcheck,
                    scalar,
                    nbits,
                    msg,
                    msg.len,
                    aug,
                    if (aug) |a| a.len else 0,
                ),
            );
        }

        pub fn aggregated(gtsig: *c.blst_fp12, sig: *const V.Sig) void {
            V.aggregated(gtsig, sig);
        }

        pub fn commit(self: *Self) void {
            c.blst_pairing_commit(self.ctx);
        }

        pub fn merge(self: *Self, ctx1: *const Self) BlstError!void {
            try check(
                c.blst_pairing_merge(self.ctx, ctx1.ctx),
            );
        }

        pub fn finalVerify(self: *const Self, gtsig: ?*const c.blst_fp12) bool {
            return c.blst_pairing_finalverify(self.ctx, gtsig);
        }

        pub fn rawAggregate(self: *Self, q: *c.blst_p2_affine, p: *c.blst_p1_affine) void {
            c.blst_pairing_raw_aggregate(self.ctx, q, p);
        }

        pub fn asFp12(self: *Self) *c.blst_fp12 {
            return c.blst_pairing_as_fp12(self.ctx);
        }
    };
}

test "init Pairing" {
    const allocator = std.testing.allocator;
    const P = Pairing(.min_pk);
    const buffer = try allocator.alloc(u8, P.sizeOf());
    defer allocator.free(buffer);

    const dst = "destination";
    _ = try P.init(@ptrCast(buffer), true, dst);
}

test "sizeOf Pairing" {
    try std.testing.expectEqual(
        c.blst_pairing_sizeof(),
        Pairing(.min_pk).sizeOf(),
    );
    // for (0..100) |i| {
    //     std.debug.print("sz {} {}\n", .{ i, c.blst_p1s_mult_pippenger_scratch_sizeof(i) });
    // }
}
