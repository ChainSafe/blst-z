const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;

const min_pk = @import("min_pk.zig");
const c = @cImport({
    @cInclude("blst.h");
});

pub const PublicKey = extern struct {
    point: min_pk.PublicKey = min_pk.PublicKey{},

    const Self = @This();

    // Core operations

    // key_validate
    pub fn validate(self: *const Self) BlstError!void {
        if (c.blst_p1_affine_is_inf(&self.point)) return BlstError.PkIsInfinity;
        if (!c.blst_p1_affine_in_g1(&self.point)) return BlstError.PointNotInGroup;
    }

    pub fn keyValidate(key: []const u8) BlstError!Self {
        const pk = PublicKey.fromBytes(key);
        // const pk = try Self.deserialize(key);
        try pk.validate();
        return pk;
    }

    pub fn fromAggregate(agg_pk: *const min_pk.AggPk) Self {
        var pk_aff = min_pk.PublicKey{};
        c.blst_p1_to_affine(&pk_aff.point, &agg_pk.point);
        return pk_aff;
    }

    pub fn toAggregate(self: *const Self) min_pk.AggPk {
        var agg_pk = min_pk.AggPk{};
        c.blst_p1_from_affine(&agg_pk.point, &self.point);
        return agg_pk;
    }

    // Serdes

    pub fn compress(self: *const Self) [min_pk.PK_COMPRESS_SIZE]u8 {
        var pk_comp = [_]u8{0} ** min_pk.PK_COMPRESS_SIZE;
        c.blst_p1_affine_compress(&pk_comp, &self.point);
        return pk_comp;
    }

    pub fn serialize(self: *const Self) [min_pk.PK_SERIALIZE_SIZE]u8 {
        var pk_out = [_]u8{0} ** min_pk.PK_SERIALIZE_SIZE;
        c.blst_p1_affine_serialize(&pk_out, &self.point);
        return pk_out;
    }

    pub fn uncompress(pk_comp: []const u8) BlstError!Self {
        if (pk_comp.len == min_pk.PK_COMPRESS_SIZE or (pk_comp[0] & 0x80) != 0) {
            var pk = Self{};
            try check(c.blst_p1_uncompress(&pk.point, pk_comp.ptr));
            return pk;
        }
        return BlstError.BadEncoding;
    }

    pub fn deserialize(pk_in: []const u8) BlstError!Self {
        if ((pk_in.len == min_pk.PK_SERIALIZE_SIZE and (pk_in[0] & 0x80) == 0) or
            (pk_in.len == min_pk.PK_COMPRESS_SIZE and (pk_in[0] & 0x80) != 0))
        {
            var pk = Self{};
            return c.blst_p1_deserialize(&pk.point, &pk_in[0]);
        }

        return BlstError.BadEncoding;
    }

    pub fn isEqual(self: *const Self, other: *const Self) bool {
        return c.blst_p1_affine_is_equal(&self.point, &other.point);
    }
};
