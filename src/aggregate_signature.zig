const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const Variant = @import("variant.zig").Variant;
const Signature = @import("signature.zig").Signature;

pub fn AggregateSignature(comptime variant: Variant) type {
    const V = variant.Types();

    return struct {
        point: V.AggSig = V.AggSig{},

        const Self = @This();

        pub fn validate(self: *const Self) BlstError!void {
            if (!V.agg_sig_in_group(&self.point)) {
                return BlstError.POINT_NOT_IN_GROUP;
            }
        }

        pub fn fromSignature(sig: *const Signature(variant)) Self {
            var agg_sig = Self{};
            V.sig_to_agg_sig(&agg_sig.point, &sig.point);
            return agg_sig;
        }

        pub fn toSignature(self: *const Self) Signature(variant) {
            var sig = Signature(variant){};
            V.agg_sig_to_sig(&sig.point, &self.point);
            return sig;
        }

        pub fn aggregate(sigs: []const Signature(variant), sigs_groupcheck: bool) BlstError!Self {
            if (sigs.len == 0) {
                return BlstError.AGGR_TYPE_MISMATCH;
            }
            if (sigs_groupcheck) {
                for (sigs) |sig| {
                    try sig.validate(false);
                }
            }
            var agg_sig = Self{};
            // warn: ptrCast here is a little sketchy
            V.sigs_add(&agg_sig.point, @ptrCast(sigs.ptr), sigs.len);
            return agg_sig;
        }

        pub fn aggregateWithRandomness(
            sigs: []const Signature(variant),
            randomness: []const u64,
            sigs_groupcheck: bool,
            scratch: []const u8,
        ) BlstError!Self {
            if (sigs.len == 0) {
                return BlstError.AGGR_TYPE_MISMATCH;
            }
            if (randomness.len != sigs.len) {
                return BlstError.AGGR_TYPE_MISMATCH;
            }
            if (scratch.len < V.sigs_pippenger_scratch_sizeof(sigs.len)) {
                return BlstError.AGGR_TYPE_MISMATCH;
            }

            if (sigs_groupcheck) {
                for (sigs) |sig| {
                    try sig.validate(false);
                }
            }
            var agg_sig = Self{};
            V.sigs_mult(
                &agg_sig.point,
                @ptrCast(sigs.ptr),
                sigs.len,
                @ptrCast(randomness.ptr),
                64,
                @ptrCast(scratch),
            );
            return agg_sig;
        }

        pub fn addAggregate(self: *const Self, agg_sig: *const Self) BlstError!void {
            V.sig_add_or_double(&self.point, &self.point, &agg_sig.point);
        }

        pub fn addSignature(self: *const Self, sig: *const Signature(variant)) BlstError!void {
            V.sig_add_or_double_affine(&self.point, &sig.point);
        }

        pub fn subgroupCheck(self: *const Self) bool {
            return V.agg_sig_in_group(&self.point);
        }
    };
}
