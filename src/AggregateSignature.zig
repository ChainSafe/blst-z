const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const Signature = @import("signature.zig").Signature;
const min_pk = @import("min_pk.zig");
const c = @cImport({
    @cInclude("blst.h");
});
const SCRATCH_SIZE = @import("eth_c_abi.zig").SCRATCH_SIZE;

point: min_pk.AggSignature = min_pk.AggSignature{},

const Self = @This();

pub fn validate(self: *const Self) BlstError!void {
    if (!c.blst_p2_in_g2(&self.point)) {
        return BlstError.PointNotInGroup;
    }
}

pub fn fromSignature(sig: *const Signature) Self {
    var agg_sig = Self{};
    c.blst_p2_from_affine(&agg_sig.point, &sig.point);
    return agg_sig;
}

pub fn toSignature(self: *const Self) Signature {
    var sig = Signature{};
    c.blst_p2_to_affine(&sig.point, &self.point);
    return sig;
}

pub fn aggregate(sigs: []const Signature, sigs_groupcheck: bool) BlstError!Self {
    if (sigs.len == 0) return BlstError.AggrTypeMismatch;
    if (sigs_groupcheck) {
        //        for (sigs) |sig| {
        //            try sig.validate(false);
        //        }
    }
    var agg_sig = Self{};
    c.blst_p2_from_affine(&agg_sig.point, &sigs[0].point);
    for (1..sigs.len) |i| {
        c.blst_p2_add_or_double_affine(&agg_sig.point, &agg_sig.point, &sigs[i].point);
    }

    return agg_sig;
}

pub fn aggregateWithRandomness(
    sigs: []const Signature,
    randomness: []const u64,
    sigs_groupcheck: bool,
    scratch: *[SCRATCH_SIZE]u8,
) BlstError!Self {
    if (sigs.len == 0) {
        return BlstError.AggrTypeMismatch;
    }
    if (randomness.len != sigs.len) {
        return BlstError.AggrTypeMismatch;
    }
    if (scratch.len <
        c.blst_p2s_mult_pippenger_scratch_sizeof(sigs.len))
    {
        return BlstError.AggrTypeMismatch;
    }

    if (sigs_groupcheck) {
        for (sigs) |sig| {
            try sig.validate(false);
        }
    }
    var agg_sig = Self{};
    c.blst_p2s_mult_pippenger(
        &agg_sig.point,
        @ptrCast(sigs.ptr),
        sigs.len,
        @ptrCast(randomness.ptr),
        64,
        @ptrCast(@alignCast(scratch)),
    );
    return agg_sig;
}

pub fn addAggregate(self: *Self, agg_sig: *const Self) BlstError!void {
    c.blst_p2_add_or_double(@ptrCast(&self.point), &self.point, &agg_sig.point);
}

pub fn addSignature(self: *const Self, sig: *const Signature, out: *Self) BlstError!void {
    c.blst_p2_add_or_double_affine(&out.point, &self.point, &sig.point);
}

pub fn subgroupCheck(self: *const Self) bool {
    return c.blst_p2_in_g2(&self.point);
}
