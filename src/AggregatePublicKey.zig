const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const PublicKey = @import("public_key.zig").PublicKey;
const Pairing = @import("pairing.zig").Pairing;
const pairing_size = @import("pairing.zig").pairing_size;

const SCRATCH_SIZE = @import("eth_c_abi.zig").SCRATCH_SIZE;
const blst = @import("blst.zig");
const c = @cImport({
    @cInclude("blst.h");
});

point: blst.AggPublicKey = blst.AggPublicKey{},

const Self = @This();

pub fn fromPublicKey(pk: *const PublicKey) Self {
    var agg_pk = Self{};
    c.blst_p1_from_affine(&agg_pk.point, &pk.point);
    return agg_pk;
}

pub fn toPublicKey(self: *const Self) PublicKey {
    var pk = PublicKey{};
    c.blst_p1_to_affine(&pk.point, &self.point);
    return pk;
}

pub fn aggregate(pks: []const PublicKey, pks_validate: bool) BlstError!Self {
    if (pks.len == 0) {
        return BlstError.AggrTypeMismatch;
    }
    if (pks_validate) {
        for (pks) |pk| {
            try pk.validate();
        }
    }
    var agg_pk = Self{};
    // warn: ptrCast here is a little sketchy
    c.blst_p1s_add(&agg_pk.point, @ptrCast(pks), pks.len);
    return agg_pk;
}

pub fn aggregateWithRandomness(
    pks: []const PublicKey,
    randomness: []const u64,
    pks_validate: bool,
    scratch: *[SCRATCH_SIZE]u8,
) BlstError!Self {
    if (pks.len == 0) {
        return BlstError.AggrTypeMismatch;
    }
    if (randomness.len != pks.len) {
        return BlstError.AggrTypeMismatch;
    }
    if (scratch.len < c.blst_p1s_mult_pippenger_scratch_sizeof(pks.len)) {
        return BlstError.AggrTypeMismatch;
    }
    if (pks_validate) {
        for (pks) |pk| {
            try pk.validate();
        }
    }
    var agg_pk = Self{};
    c.blst_p1s_mult_pippenger(
        &agg_pk.point,
        @ptrCast(pks.ptr),
        pks.len,
        @ptrCast(randomness.ptr),
        64,
        @ptrCast(@alignCast(scratch)),
    );
    return agg_pk;
}

pub fn addAggregate(self: *Self, other: *const Self) void {
    c.blst_p1_add_or_double(&self.point, &self.point, &other.point);
}

pub fn addPublicKey(self: *Self, pk: *const PublicKey, pk_validate: bool) BlstError!void {
    if (pk_validate) {
        try pk.validate();
    }

    c.blst_p1_add_or_double_affine(&self.point, &self.point, &pk.point);
}
