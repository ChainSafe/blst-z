const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const PublicKey = @import("public_key.zig").PublicKey;
const Pairing = @import("pairing.zig").Pairing;
const pairing_size = @import("pairing.zig").pairing_size;

const SCRATCH_SIZE = @import("eth_c_abi.zig").SCRATCH_SIZE;
const min_pk = @import("min_pk.zig");
const c = @cImport({
    @cInclude("blst.h");
});

point: min_pk.AggPublicKey = min_pk.AggPublicKey{},

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
    c.blst_p1_from_affine(&agg_pk.point, &pks[0].point);
    for (1..pks.len) |i| {
        c.blst_p1_add_or_double_affine(&agg_pk.point, &agg_pk.point, &pks[i].point);
    }
    return agg_pk;
}

pub fn aggregateWithRandomness(
    pks: []*const PublicKey,
    randomness: []const u8,
    pks_validate: bool,
    scratch: *[]u64,
) BlstError!Self {
    if (pks.len == 0) return BlstError.AggrTypeMismatch;
    if (scratch.len < c.blst_p1s_mult_pippenger_scratch_sizeof(pks.len)) {
        return BlstError.AggrTypeMismatch;
    }
    if (pks_validate) {
        for (pks) |pk| {
            try pk.validate();
        }
    }

    var scalars_refs: [128]*const u8 = undefined;
    for (0..pks.len) |i| scalars_refs[i] = &randomness[i * 32];

    var agg_pk = Self{};
    c.blst_p1s_mult_pippenger(
        &agg_pk.point,
        @ptrCast(pks.ptr),
        pks.len,
        @ptrCast(scalars_refs[0..pks.len]),
        64,
        scratch.ptr,
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

    const m = c.blst_p1s_mult_pippenger_scratch_sizeof(num_sigs) * 8;
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
    var scalars_refs: [128]*const u8 = undefined;
    var pks_refs: [128]*const PublicKey = undefined;
    std.Random.bytes(rand, &rands);

    for (0..num_sigs) |i| {
        scalars_refs[i] = &rands[i * 32];
        pks_refs[i] = &pks[i];
    }

    _ = try aggregateWithRandomness(
        &pks_refs,
        &rands,
        true,
        &scratch,
    );
}

const SecretKey = @import("secret_key.zig").SecretKey;
const Signature = @import("signature.zig").Signature;
