const std = @import("std");
const testing = std.testing;

const c = @cImport({
    @cInclude("blst.h");
});

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

/// TODO: the size of SecretKey is only 32 bytes so go with stack allocation
/// consider adding heap allocation with allocator in the future
const SecretKey = struct {
    value: c.blst_scalar,

    pub fn default() SecretKey {
        return .{
            .value = util.default_blst_scalar(),
        };
    }

    pub fn keyGen(ikm: []const u8, key_info: []const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        c.blst_keygen(&sk.value, &ikm[0], ikm.len, &key_info[0], key_info.len);
        return sk;
    }

    pub fn keyGenV3(ikm: []const u8, key_info: []const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        c.blst_keygen_v3(&sk.value, &ikm[0], ikm.len, &key_info[0], key_info.len);
        return sk;
    }

    pub fn keyGenV45(ikm: []const u8, salt: []const u8, info: []const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        c.blst_keygen_v4_5(&sk.value, &ikm[0], ikm.len, &salt[0], salt.len, &info[0], info.len);
        return sk;
    }

    pub fn keyGenV5(ikm: []const u8, salt: []const u8, info: []const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        c.blst_keygen_v5(&sk.value, &ikm[0], ikm.len, &salt[0], salt.len, &info[0], info.len);
        return sk;
    }

    pub fn deriveMasterEip2333(ikm: []const u8) BLST_ERROR!SecretKey {
        if (ikm.len < 32) {
            return BLST_ERROR.BAD_ENCODING;
        }

        var sk = SecretKey.default();
        c.blst_derive_master_eip2333(&sk.value, &ikm[0], ikm.len);
        return sk;
    }

    pub fn deriveChildEip2333(self: *const SecretKey, child_index: u32) BLST_ERROR!SecretKey {
        var sk = SecretKey.default();
        c.blst_derive_child_eip2333(&sk.value, &self.value, child_index);
        return sk;
    }
};

// TODO: implement Clone, Copy, Equal
const PublicKey = struct {
    point: c.blst_p1_affine,

    pub fn default() PublicKey {
        return .{
            .point = util.default_blst_p1_affline(),
        };
    }

    // Core operations

    // key_validate
    pub fn validate(self: *const PublicKey) BLST_ERROR!void {
        if (c.blst_p1_affine_is_inf(&self.point) == false) {
            return BLST_ERROR.PK_IS_INFINITY;
        }

        if (c.blst_p1_affine_in_g1(&self.point) == false) {
            return BLST_ERROR.POINT_NOT_IN_GROUP;
        }
    }

    pub fn key_validate(key: []const u8) BLST_ERROR!void {
        const pk = PublicKey.fromBytes(key);
        return pk.validate();
    }

    // TODO: from_aggregate

    // Serdes

    pub fn compress(self: *const PublicKey) [48]u8 {
        var pk_comp = [_]u8{0} ** 48;
        c.blst_p1_affine_compress(&pk_comp[0], &self.point);
        return pk_comp;
    }

    pub fn serialize(self: *const PublicKey) [96]u8 {
        var pk_out = [_]u8{0} ** 96;
        c.blst_p1_affine_serialize(&pk_out[0], &self.point);
        return pk_out;
    }

    pub fn uncompress(pk_comp: []const u8) BLST_ERROR!PublicKey {
        if (pk_comp.len == 48 and (pk_comp[0] & 0x80) == 0) {
            var pk = PublicKey.default();
            const res = c.blst_p1_uncompress(&pk.point, &pk_comp[0]);
            const err = toBlstError(res);
            if (err != null) {
                return err;
            }
            return pk;
        }
    }

    pub fn deserialize(pk_in: []const u8) BLST_ERROR!PublicKey {
        if ((pk_in.len == 96 and (pk_in[0] & 0x80) == 0) or
            (pk_in.len == 48 and (pk_in[0] & 0x80) != 0))
        {
            var pk = PublicKey.default();
            const res = c.blst_p1_deserialize(&pk.point, &pk_in[0]);
            const err = toBlstError(res);
            if (err != null) {
                return err;
            }
            return pk;
        }

        return BLST_ERROR.BAD_ENCODING;
    }

    pub fn fromBytes(pk_in: []const u8) BLST_ERROR!PublicKey {
        return PublicKey.deserialize(pk_in);
    }

    pub fn toBytes(self: *const PublicKey) [48]u8 {
        return self.compress();
    }
};

const AggregatePublicKey = struct {
    point: c.blst_p1,

    pub fn default() AggregatePublicKey {
        return .{
            .point = util.default_blst_p1(),
        };
    }

    pub fn fromPublicKey(pk: *const PublicKey) AggregatePublicKey {
        var agg_pk = AggregatePublicKey.default();
        c.blst_p1_from_affine(&agg_pk.point, &pk.point);

        return agg_pk;
    }

    pub fn toPublicKey(self: *const AggregatePublicKey) PublicKey {
        var pk = PublicKey.default();
        c.blst_p1_to_affine(&pk.point, &self.point);
    }

    // Aggregate
    pub fn aggregate(pks: []*const PublicKey, pks_validate: bool) BLST_ERROR!AggregatePublicKey {
        if (pks.len == 0) {
            return BLST_ERROR.AGGR_TYPE_MISMATCH;
        }
        if (pks.validate) {
            pks[0].validate();
        }

        var agg_pk = AggregatePublicKey.fromPublicKey(pks[0]);
        for (pks[1..]) |pk| {
            if (pks_validate) {
                pk.validate();
            }

            c.blst_p1_add_or_double_affine(&agg_pk.point, &agg_pk.point, &pk.point);
        }

        return agg_pk;
    }

    pub fn aggregateSerialized(pks: [][]const u8, pks_validate: bool) BLST_ERROR!AggregatePublicKey {
        // TODO - threading
        if (pks.len == 0) {
            return BLST_ERROR.AGGR_TYPE_MISMATCH;
        }
        var pk = if (pks_validate) PublicKey.key_validate(pks[0]) else PublicKey.fromBytes(pks[0]);
        var agg_pk = AggregatePublicKey.fromPublicKey(&pk);
        for (pks[1..]) |s| {
            pk = if (pks_validate) PublicKey.key_validate(s) else PublicKey.fromBytes(s);
            c.blst_p1_add_or_double_affine(&agg_pk.point, &agg_pk.point, &pk.point);
        }

        return agg_pk;
    }

    pub fn addAggregate(self: *AggregatePublicKey, agg_pk: *const AggregatePublicKey) BLST_ERROR!void {
        c.blst_p1_add_or_double_affine(&self.point, &self.point, &agg_pk.point);
    }

    pub fn addPublicKey(self: *AggregatePublicKey, pk: *const PublicKey, pk_validate: bool) BLST_ERROR!void {
        if (pk_validate) {
            try pk.validate();
        }

        c.blst_p1_add_or_double_affine(&self.point, &self.point, &pk.point);
    }
};

test "SecretKey" {
    std.debug.print("size of SecretKey: {}, align is {}\n", .{ @sizeOf(SecretKey), @alignOf(SecretKey) });
    const zero_bytes = [_]u8{0} ** 32;
    const info = zero_bytes[0..32];
    _ = try SecretKey.keyGen(info, info);
    _ = try SecretKey.keyGenV3(info, info);
    _ = try SecretKey.keyGenV45(info, info, info);
    _ = try SecretKey.keyGenV5(info, info, info);
    const sk = try SecretKey.deriveMasterEip2333(info);
    _ = try sk.deriveChildEip2333(0);
}

test "test_sign_n_verify" {
    // TODO: add all tests from Rust bindings
}
