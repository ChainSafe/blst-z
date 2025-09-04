const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const Variant = @import("variant.zig").Variant;
const c = @import("c.zig");

pub fn PublicKey(comptime variant: Variant) type {
    const Types = variant.Types();
    return extern struct {
        point: Types.Pk = Types.Pk{},

        const Self = @This();

        pub const serialize_size = Types.pk_serialize_size;
        pub const compress_size = Types.pk_compress_size;

        // Core operations

        // key_validate
        pub fn validate(self: *const Self) BlstError!void {
            if (Types.pk_is_inf(&self.point)) {
                return BlstError.PK_IS_INFINITY;
            }

            if (!Types.pk_in_group(&self.point)) {
                return BlstError.POINT_NOT_IN_GROUP;
            }
        }

        pub fn keyValidate(key: []const u8) BlstError!Self {
            const pk = try Self.deserialize(key);
            try pk.validate();
            return pk;
        }

        pub fn fromAggregate(agg_pk: *const Types.AggPk) Self {
            var pk_aff = Types.Pk{};
            Types.agg_pk_to_pk(&pk_aff.point, &agg_pk.point);
            return pk_aff;
        }

        pub fn toAggregate(self: *const Self) Types.AggPk {
            var agg_pk = Types.AggPk{};
            Types.pk_to_agg_pk(&agg_pk.point, &self.point);
            return agg_pk;
        }

        // Serdes

        pub fn compress(self: *const Self) [Types.pk_compress_size]u8 {
            var pk_comp = [_]u8{0} ** Types.pk_compress_size;
            Types.pk_compress(&pk_comp, &self.point);
            return pk_comp;
        }

        pub fn serialize(self: *const Self) [Types.pk_serialize_size]u8 {
            var pk_out = [_]u8{0} ** Types.pk_serialize_size;
            Types.pk_serialize(&pk_out, &self.point);
            return pk_out;
        }

        pub fn uncompress(pk_comp: []const u8) BlstError!Self {
            if (pk_comp.len == Types.pk_compress_size or (pk_comp[0] & 0x80) != 0) {
                var pk = Self{};
                try check(
                    Types.pk_uncompress(&pk.point, pk_comp.ptr),
                );
                return pk;
            }
            return BlstError.BAD_ENCODING;
        }

        pub fn deserialize(pk_in: []const u8) BlstError!Self {
            if ((pk_in.len == Types.pk_serialize_size and (pk_in[0] & 0x80) == 0) or
                (pk_in.len == Types.pk_compress_size and (pk_in[0] & 0x80) != 0))
            {
                var pk = Self{};
                return Types.pk_deserialize(&pk.point, &pk_in);
            }

            return BlstError.BAD_ENCODING;
        }

        pub fn isEqual(self: *const Self, other: *const Self) bool {
            return Types.pk_is_equal(&self.point, &other.point);
        }
    };
}
