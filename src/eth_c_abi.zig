// fastAggregateVerify
// verify
// aggregateSerailiezdPublicKeys
// PublicKey
// aggregatePublicKeys
// aggregateSignatures
// Signature
// verifyMultipleAggregateSignatures
// asyncAggregateWithRandomness
const std = @import("std");
const blst = @import("root.zig");
const signature = @import("signature.zig");
const intFromError = @import("error.zig").intFromError;

/// See https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub const MAX_AGGREGATE_PER_JOB: usize = 128;

/// Size of the scratch buffer for pairing operations.
pub const SCRATCH_SIZE_PAIRING: usize = @import("pairing.zig").pairing_size;

/// Scratch buffer used for operations that require temporary storage.
threadlocal var scratch_pairing: [SCRATCH_SIZE_PAIRING]u8 = undefined;

pub const SCRATCH_SIZE_AGG: usize = 1024 * 16;

/// Scratch buffer used for operations that require temporary storage.
threadlocal var scratch_agg: [SCRATCH_SIZE_AGG]u64 = undefined;

////// SecretKey

export fn secretKeyFromBytes(out: *blst.SecretKey, bytes: [*c]const u8, len: c_uint) c_uint {
    out.* = blst.SecretKey.deserialize(@ptrCast(bytes[0..len])) catch |e| return intFromError(e);
    return 0;
}

export fn secretKeyToBytes(out: [*c]u8, sk: *const blst.SecretKey) void {
    out[0..blst.SecretKey.serialize_size].* = sk.serialize();
}

export fn secretKeyKeyGen(out: *blst.SecretKey, ikm: [*c]const u8, ikm_len: c_uint) c_uint {
    out.* = blst.SecretKey.keyGen(ikm[0..ikm_len], null) catch |e| return intFromError(e);
    return 0;
}

export fn secretKeyKeyGenV3(out: *blst.SecretKey, ikm: [*c]const u8, ikm_len: c_uint) c_uint {
    out.* = blst.SecretKey.keyGenV3(ikm[0..ikm_len], null) catch |e| return intFromError(e);
    return 0;
}

export fn secretKeyKeyGenV45(out: *blst.SecretKey, ikm: [*c]const u8, ikm_len: c_uint, salt: [*c]const u8, salt_len: c_uint) c_uint {
    out.* = blst.SecretKey.keyGenV45(ikm[0..ikm_len], salt[0..salt_len], null) catch |e| return intFromError(e);
    return 0;
}

export fn secretKeyDeriveMasterEip2333(out: *blst.SecretKey, ikm: [*c]const u8, ikm_len: c_uint) c_uint {
    out.* = blst.SecretKey.deriveMasterEip2333(ikm[0..ikm_len]) catch |e| return intFromError(e);
    return 0;
}

export fn secretKeyDeriveChildEip2333(out: *blst.SecretKey, sk: *const blst.SecretKey, index: c_uint) c_uint {
    out.* = sk.deriveChildEip2333(index) catch |e| return intFromError(e);
    return 0;
}

export fn secretKeyToPublicKey(out: *blst.PublicKey, sk: *const blst.SecretKey) void {
    out.* = sk.toPublicKey();
}

export fn secretKeySign(out: *blst.Signature, sk: *const blst.SecretKey, msg: [*c]const u8, msg_len: c_uint) c_uint {
    out.* = sk.sign(msg[0..msg_len], DST, null);
    return 0;
}

////// PublicKey

export fn publicKeyFromBytes(out: *blst.PublicKey, bytes: [*c]const u8, len: c_uint) c_uint {
    out.* = blst.PublicKey.uncompress(bytes[0..len]) catch |e| return intFromError(e);
    return 0;
}

export fn publicKeyToBytes(out: [*c]u8, pk: *const blst.PublicKey) void {
    out[0..blst.min_pk.PK_COMPRESS_SIZE].* = pk.compress();
}

export fn publicKeyValidate(a: *const blst.PublicKey) c_uint {
    a.validate() catch |e| return intFromError(e);
    return 0;
}

export fn publicKeyAggregateWithRandomness(
    out: *blst.PublicKey,
    pks: [*c]*const blst.PublicKey,
    len: c_uint,
    pks_validate: bool,
) c_uint {
    var rands: [32 * MAX_AGGREGATE_PER_JOB]u8 = [_]u8{0} ** (32 * MAX_AGGREGATE_PER_JOB);
    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
        break :blk seed;
    });
    const rand = prng.random();
    std.Random.bytes(rand, &rands);

    const agg_pk = blst.AggregatePublicKey.aggregateWithRandomness(
        pks[0..len],
        &rands,
        pks_validate,
        scratch_agg[0..],
    ) catch |e| return intFromError(e);

    out.* = agg_pk.toPublicKey();

    return 0;
}

export fn publicKeyAggregate(out: *blst.PublicKey, pks: [*c]const blst.PublicKey, len: c_uint, pks_validate: bool) c_uint {
    const agg_pk = blst.AggregatePublicKey.aggregate(pks[0..len], pks_validate) catch |e| return intFromError(e);
    out.* = agg_pk.toPublicKey();

    return 0;
}

////// Signature

export fn signatureFromBytes(out: *blst.Signature, bytes: [*c]const u8, bytes_len: c_uint) c_uint {
    out.* = blst.Signature.uncompress(bytes[0..bytes_len]) catch |e| return intFromError(e);
    return 0;
}

export fn signatureToBytes(out: [*c]u8, sig: *const blst.Signature) void {
    out[0..blst.min_pk.SIG_COMPRESS_SIZE].* = sig.compress();
}

export fn signatureValidate(sig: *const blst.Signature, sig_infcheck: bool) c_uint {
    sig.validate(sig_infcheck) catch |e| return intFromError(e);
    return 0;
}

export fn signatureVerify(
    sig: *const blst.Signature,
    sig_groupcheck: bool,
    msg: [*c]const u8,
    msg_len: c_uint,
    pk: *const blst.PublicKey,
    pk_validate: bool,
) c_uint {
    sig.verify(
        sig_groupcheck,
        msg[0..msg_len],
        DST,
        null,
        pk,
        pk_validate,
    ) catch |e| return intFromError(e);
    return 0;
}

export fn signatureAggregateVerify(
    sig: *const blst.Signature,
    sig_groupcheck: bool,
    msgs: [*c]const [32]u8,
    pks: [*c]const blst.PublicKey,
    len: c_uint,
    pks_validate: bool,
) c_uint {
    const res = sig.aggregateVerify(
        sig_groupcheck,
        &scratch_pairing,
        msgs[0..len],
        DST,
        pks[0..len],
        pks_validate,
    ) catch |e| return intFromError(e);
    return @intFromBool(!res);
}

export fn signatureFastAggregateVerify(
    sig: *const blst.Signature,
    sig_groupcheck: bool,
    msg: *[32]u8,
    pks: [*c]const blst.PublicKey,
    pks_len: c_uint,
) c_uint {
    const res = sig.fastAggregateVerify(
        sig_groupcheck,
        &scratch_pairing,
        msg.*,
        DST,
        pks[0..pks_len],
    ) catch |e| return intFromError(e);
    return @intFromBool(!res);
}

export fn signatureVerifyMultipleAggregateSignatures(
    n_elems: c_uint,
    msgs: [*c]const [32]u8,
    pks: [*c]const *blst.PublicKey,
    pks_validate: bool,
    sigs: [*c]const *blst.Signature,
    sig_groupcheck: bool,
) c_uint {
    var rands: [32 * MAX_AGGREGATE_PER_JOB][32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
        break :blk seed;
    });
    const rand = prng.random();

    for (0..32 * MAX_AGGREGATE_PER_JOB) |i| {
        std.Random.bytes(rand, &rands[i]);
    }
    const res = @import("signature.zig").verifyMultipleAggregateSignatures(
        &scratch_pairing,
        n_elems,
        msgs,
        DST,
        pks,
        pks_validate,
        sigs,
        sig_groupcheck,
        &rands,
    ) catch |e| return intFromError(e);

    return @intFromBool(!res);
}

export fn signatureAggregateWithRandomness(
    out: *blst.Signature,
    sigs: [*c]*const blst.Signature,
    len: c_uint,
    sigs_groupcheck: bool,
) c_uint {
    var rands: [32 * MAX_AGGREGATE_PER_JOB]u8 = [_]u8{0} ** (32 * MAX_AGGREGATE_PER_JOB);
    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
        break :blk seed;
    });
    const rand = prng.random();
    std.Random.bytes(rand, &rands);

    const agg_sig = blst.AggregateSignature.aggregateWithRandomness(
        sigs[0..len],
        &rands,
        sigs_groupcheck,
        scratch_agg[0..],
    ) catch |e| return intFromError(e);

    out.* = agg_sig.toSignature();

    return 0;
}

export fn signatureAggregate(
    out: *blst.Signature,
    sigs: [*c]const blst.Signature,
    len: c_uint,
    sigs_groupcheck: bool,
) c_uint {
    const agg_sig = blst.AggregateSignature.aggregate(
        sigs[0..len],
        sigs_groupcheck,
    ) catch |e| return intFromError(e);

    out.* = agg_sig.toSignature();

    return 0;
}
