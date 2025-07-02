const std = @import("std");
const util = @import("util.zig");
const BlstError = util.BlstError;
const check = util.check;
const Variant = @import("variant.zig").Variant;
const PublicKey = @import("public_key.zig").PublicKey;
const Pairing = @import("pairing.zig").Pairing;
const pairing_size = @import("pairing.zig").pairing_size;

pub fn AggregatePublicKey(comptime variant: Variant) type {
    const V = variant.Types();

    return struct {
        point: V.AggPk = V.AggPk{},

        const Self = @This();

        pub fn fromPublicKey(pk: *const PublicKey(variant)) Self {
            var agg_pk = Self{};
            V.pk_to_agg_pk(&agg_pk.point, &pk.point);
            return agg_pk;
        }

        pub fn toPublicKey(self: *const Self) PublicKey(variant) {
            var pk = PublicKey(variant){};
            V.agg_pk_to_pk(&pk.point, &self.point);
            return pk;
        }

        pub fn aggregate(pks: []const PublicKey(variant), pks_validate: bool) Self {
            if (pks.len == 0) {
                return BlstError.AGGR_TYPE_MISMATCH;
            }
            if (pks_validate) {
                for (pks) |pk| {
                    try pk.validate();
                }
            }
            var agg_pk = Self{};
            // warn: ptrCast here is a little sketchy
            V.pks_add(&agg_pk.point, @ptrCast(pks), pks.len);
            return agg_pk;
        }

        pub fn addAggregate(self: *Self, other: *const Self) void {
            V.pk_add_or_double(&self.point, &self.point, &other.point);
        }

        pub fn addPublicKey(self: *Self, pk: *const PublicKey(variant), pk_validate: bool) BlstError!void {
            if (pk_validate) {
                try pk.validate();
            }

            V.pk_add_or_double_affine(&self.point, &self.point, &pk.point);
        }
    };
}
