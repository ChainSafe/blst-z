/// Maximum number of signatures that can be aggregated in a single job.
pub const MAX_AGGREGATE_PER_JOB: usize = 128;

/// Size of the scratch buffer for pairing operations.
pub const SCRATCH_SIZE_PAIRING: usize = @import("Pairing.zig").sizeOf();

/// Scratch buffer used for pairing operations that require temporary storage.
threadlocal var scratch_pairing: [SCRATCH_SIZE_PAIRING]u8 = undefined;

/// Size of the scratch buffer for aggregation operations.
pub const SCRATCH_SIZE_AGG: usize = 1024 * 16;

/// Scratch buffer used for aggregation operations that require temporary storage.
threadlocal var scratch_agg: [SCRATCH_SIZE_AGG]u64 = undefined;

////// SecretKey

/// Deserialize a `blst.SecretKey` from bytes.
///
/// Returns 0 on success, error code on failure.
export fn secretKeyFromBytes(out: *blst.SecretKey, bytes: [*c]const u8, len: c_uint) c_uint {
    out.* = blst.SecretKey.deserialize(@ptrCast(bytes[0..len])) catch |e| return intFromError(e);
    return 0;
}

/// Serialize a `blst.SecretKey` to bytes.
export fn secretKeyToBytes(out: [*c]u8, sk: *const blst.SecretKey) void {
    out[0..blst.SecretKey.serialize_size].* = sk.serialize();
}

/// Generate a `blst.SecretKey` from input key material using HKDF.
///
/// Returns 0 on success, error code on failure.
export fn secretKeyKeyGen(out: *blst.SecretKey, ikm: [*c]const u8, ikm_len: c_uint) c_uint {
    out.* = blst.SecretKey.keyGen(ikm[0..ikm_len], null) catch |e| return intFromError(e);
    return 0;
}

/// Generate a `blst.SecretKey` from input key material using HKDF (version 3).
///
/// Returns 0 on success, error code on failure.
export fn secretKeyKeyGenV3(out: *blst.SecretKey, ikm: [*c]const u8, ikm_len: c_uint) c_uint {
    out.* = blst.SecretKey.keyGenV3(ikm[0..ikm_len], null) catch |e| return intFromError(e);
    return 0;
}

/// Generate a `blst.SecretKey` from input key material using HKDF (version 4.5).
///
/// Returns 0 on success, error code on failure.
export fn secretKeyKeyGenV45(
    out: *blst.SecretKey,
    ikm: [*c]const u8,
    ikm_len: c_uint,
    salt: [*c]const u8,
    salt_len: c_uint,
) c_uint {
    out.* = blst.SecretKey.keyGenV45(ikm[0..ikm_len], salt[0..salt_len], null) catch |e| return intFromError(e);
    return 0;
}

/// Derive a master `blst.SecretKey` using EIP-2333 key derivation.
///
/// Returns 0 on success, error code on failure.
export fn secretKeyDeriveMasterEip2333(out: *blst.SecretKey, ikm: [*c]const u8, ikm_len: c_uint) c_uint {
    out.* = blst.SecretKey.deriveMasterEip2333(ikm[0..ikm_len]) catch |e| return intFromError(e);
    return 0;
}

/// Derive a child `blst.SecretKey` using EIP-2333 key derivation.
///
/// Returns 0 on success, error code on failure.
export fn secretKeyDeriveChildEip2333(out: *blst.SecretKey, sk: *const blst.SecretKey, index: c_uint) c_uint {
    out.* = sk.deriveChildEip2333(index) catch |e| return intFromError(e);
    return 0;
}

/// Derive a `blst.PublicKey` from a `blst.SecretKey`.
export fn secretKeyToPublicKey(out: *blst.PublicKey, sk: *const blst.SecretKey) void {
    out.* = sk.toPublicKey();
}

/// Sign a message with `blst.SecretKey`. and produces a `Signature` in `out`.
///
/// Returns 0 on success, error code on failure.
export fn secretKeySign(out: *Signature, sk: *const blst.SecretKey, msg: [*c]const u8, msg_len: c_uint) c_uint {
    out.* = sk.sign(msg[0..msg_len], DST, null);
    return 0;
}

////// PublicKey

/// Deserialize a `blst.PublicKey` in `out` from compressed bytes.
///
/// Returns 0 on success, error code on failure.
export fn publicKeyFromBytes(out: *blst.PublicKey, bytes: [*c]const u8, len: c_uint) c_uint {
    out.* = blst.PublicKey.uncompress(bytes[0..len]) catch |e| return intFromError(e);
    return 0;
}

/// Serialize a `blst.PublicKey` to compressed bytes in `out`.
export fn publicKeyToBytes(out: [*c]u8, pk: *const blst.PublicKey) void {
    out[0..blst.PublicKey.COMPRESS_SIZE].* = pk.compress();
}

/// Validate a `blst.PublicKey`.
///
/// Returns 0 on success, error code on failure.
export fn publicKeyValidate(a: *const blst.PublicKey) c_uint {
    PublicKey.validate(&a.point) catch |e| return intFromError(e);
    return 0;
}

/// Aggregate multiple `blst.PublicKey`s with randomness for security.
///
/// Returns 0 on success, error code on failure.
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

/// Aggregate multiple `blst.PublicKey`s.
///
/// Returns 0 on success, error code on failure.
export fn publicKeyAggregate(out: *PublicKey, pks: [*c]const PublicKey.Point, len: c_uint, pks_validate: bool) c_uint {
    const agg_pk = blst.AggregatePublicKey.aggregate(pks[0..len], pks_validate) catch |e| return intFromError(e);
    out.* = agg_pk.toPublicKey();

    return 0;
}

////// Signature

/// Deserialize a `Signature` in `out` from compressed bytes.
///
/// Returns 0 on success, error code on failure.
export fn signatureFromBytes(out: *Signature, bytes: [*c]const u8, bytes_len: c_uint) c_uint {
    out.* = (Signature.uncompress(bytes[0..bytes_len]) catch |e| return intFromError(e));
    return 0;
}

/// Serialize a `Signature` to compressed bytes in `out`.
export fn signatureToBytes(out: [*c]u8, sig: *const Signature) void {
    out[0..Signature.COMPRESS_SIZE].* = sig.compress();
}

/// Validate a `Signature`.
///
/// Returns 0 on success, error code on failure.
export fn signatureValidate(sig: *const Signature, sig_infcheck: bool) c_uint {
    sig.validate(sig_infcheck) catch |e| return intFromError(e);
    return 0;
}

/// Verify a `Signature` against a `blst.PublicKey` and message `msg`.
///
/// Returns 0 on success, error code on failure.
export fn signatureVerify(
    sig: *const Signature,
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

/// Verify an aggregate signature `Signature` against multiple messages and `blst.PublicKey`s.
///
/// Returns 0 if verification succeeds, 1 if verification fails, error code on error.
export fn signatureAggregateVerify(
    sig: *const Signature,
    sig_groupcheck: bool,
    msgs: [*c]const [32]u8,
    pks: [*c]const PublicKey.Point,
    len: c_uint,
    pks_validate: bool,
) c_uint {
    const res = sig.aggregateVerify(
        sig_groupcheck,
        &scratch_pairing,
        msgs[0..len],
        DST,
        @ptrCast(pks[0..len]),
        pks_validate,
    ) catch |e| return intFromError(e);
    return @intFromBool(!res);
}

/// Faster verify an aggregate signature `Signature` against multiple messages and `blst.PublicKey`s.
///
/// Returns 0 if verification succeeds, 1 if verification fails, error code on error.
export fn signatureFastAggregateVerify(
    sig: *const Signature,
    sig_groupcheck: bool,
    msg: *[32]u8,
    pks: [*c]const PublicKey.Point,
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

/// Verify multiple aggregate signatures efficiently.
///
/// Returns 0 if verification succeeds, 1 if verification fails, error code on error.
export fn signatureVerifyMultipleAggregateSignatures(
    n_elems: c_uint,
    msgs: [*c]const [32]u8,
    pks: [*c]const *blst.PublicKey,
    pks_validate: bool,
    sigs: [*c]const *Signature,
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

    const res = @import("fast_verify.zig").verifyMultipleAggregateSignatures(
        &scratch_pairing,
        n_elems,
        msgs[0..n_elems],
        DST,
        pks[0..n_elems],
        pks_validate,
        @ptrCast(sigs[0..n_elems]),
        sig_groupcheck,
        &rands,
    ) catch |e| return intFromError(e);

    return @intFromBool(!res);
}

/// Aggregates a slice of `Signature` with randomness into a single `Signature`.
///
/// Returns 0 on success, error code on failure.
export fn signatureAggregateWithRandomness(
    out: *Signature,
    sigs: [*c]*const Signature,
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

/// Aggregates a slice of `Signature` into a single `Signature`.
///
/// Returns 0 on success, error code on failure.
export fn signatureAggregate(
    out: *Signature,
    sigs: [*c]const Signature.Point,
    len: c_uint,
    sigs_groupcheck: bool,
) c_uint {
    const agg_sig = blst.AggregateSignature.aggregate(
        @ptrCast(sigs[0..len]),
        sigs_groupcheck,
    ) catch |e| return intFromError(e);

    out.* = agg_sig.toSignature();

    return 0;
}

const std = @import("std");
const blst = @import("root.zig");
const PublicKey = blst.PublicKey;
const Signature = blst.Signature;
const DST = blst.DST;
const intFromError = @import("error.zig").intFromError;

const c = @cImport({
    @cInclude("blst.h");
});
