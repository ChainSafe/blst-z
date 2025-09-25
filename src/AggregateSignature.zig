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
    if (sigs_groupcheck) for (sigs) |sig| try sig.validate(false);

    var agg_sig = Self{};
    c.blst_p2_from_affine(&agg_sig.point, &sigs[0].point);
    for (1..sigs.len) |i| {
        c.blst_p2_add_or_double_affine(&agg_sig.point, &agg_sig.point, &sigs[i].point);
    }

    return agg_sig;
}

pub fn aggregateWithRandomness(
    sigs: []*const Signature,
    randomness: []const u8,
    sigs_groupcheck: bool,
    scratch: []u64,
) BlstError!Self {
    if (sigs_groupcheck) for (sigs) |sig| try sig.validate(false);
    if (scratch.len < c.blst_p2s_mult_pippenger_scratch_sizeof(sigs.len)) {
        return BlstError.AggrTypeMismatch;
    }

    var scalars_refs: [128]*const u8 = undefined;
    for (0..sigs.len) |i| scalars_refs[i] = &randomness[i * 32];

    var agg_sig = Self{};

    c.blst_p2s_mult_pippenger(
        &agg_sig.point,
        @ptrCast(sigs.ptr),
        sigs.len,
        @ptrCast(scalars_refs[0..sigs.len]),
        64,
        scratch.ptr,
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

test aggregateWithRandomness {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    // aug is null

    const num_sigs = 128;

    var msgs: [num_sigs][32]u8 = undefined;
    var sks: [num_sigs]SecretKey = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]Signature = undefined;

    const m = c.blst_p2s_mult_pippenger_scratch_sizeof(num_sigs) * 64;
    const allocator = std.testing.allocator;
    var scratch = try std.testing.allocator.alloc(u64, m);
    defer allocator.free(scratch);

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
        break :blk seed;
    });
    const rand = prng.random();
    for (0..num_sigs) |i| {
        std.Random.bytes(rand, &msgs[i]);
        const sk = try SecretKey.keyGen(&ikm, null);
        const pk = sk.toPublicKey();
        const sig = sk.sign(&msgs[i], dst, null);

        sks[i] = sk;
        pks[i] = pk;
        sigs[i] = sig;
    }
    var rands: [32 * 128]u8 = [_]u8{0} ** (32 * 128);
    var sigs_refs: [128]*const Signature = undefined;
    std.Random.bytes(rand, &rands);

    for (0..num_sigs) |i| {
        sigs_refs[i] = &sigs[i];
    }

    const agg_sig = try aggregateWithRandomness(
        &sigs_refs,
        &rands,
        true,
        scratch[0..],
    );
    _ = agg_sig.toSignature();
}

const SecretKey = @import("secret_key.zig").SecretKey;
const PublicKey = @import("public_key.zig").PublicKey;
