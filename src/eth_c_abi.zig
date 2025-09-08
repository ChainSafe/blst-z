const std = @import("std");
const blst = @import("root.zig");
const intFromError = @import("error.zig").intFromError;

/// See https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub const SCRATCH_SIZE: usize = 3192;

/// This is a scratch buffer used for operations that require temporary storage
threadlocal var scratch: [SCRATCH_SIZE]u8 = undefined;

////// SecretKey

export fn secretKeySizeOf() c_uint {
    return @sizeOf(blst.SecretKey);
}

export fn secretKeySerializeSize() c_uint {
    return blst.SecretKey.serialize_size;
}

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

export fn publicKeySizeOf() c_uint {
    return @sizeOf(blst.PublicKey);
}

export fn publicKeyCompressSize() c_uint {
    return blst.MIN_PK_SERIALIZE_SIZE;
}

export fn publicKeyFromBytes(out: *blst.PublicKey, bytes: [*c]const u8, len: c_uint) c_uint {
    out.* = blst.PublicKey.uncompress(bytes[0..len]) catch |e| return intFromError(e);
    return 0;
}

export fn publicKeyToBytes(out: [*c]u8, pk: *const blst.PublicKey) void {
    out[0..blst.MIN_PK_COMPRESS_SIZE].* = pk.compress();
}

export fn publicKeyIsEqual(a: *const blst.PublicKey, b: *const blst.PublicKey) bool {
    return a.isEqual(b);
}

export fn publicKeyValidate(a: *const blst.PublicKey) c_uint {
    a.validate() catch |e| return intFromError(e);
    return 0;
}

export fn publicKeyFromAggregate(out: *blst.PublicKey, agg_pk: *const blst.AggregatePublicKey) void {
    out.* = agg_pk.toPublicKey();
}

export fn publicKeyToAggregate(out: *blst.AggregatePublicKey, pk: *const blst.PublicKey) void {
    out.* = blst.AggregatePublicKey.fromPublicKey(pk);
}

export fn publicKeyAggregateWithRandomness(
    out: *blst.PublicKey,
    pks: [*c]const blst.PublicKey,
    randomness: [*c]const u64,
    len: c_uint,
    pks_validate: bool,
) c_uint {
    const agg_pk = blst.AggregatePublicKey.aggregateWithRandomness(
        pks[0..len],
        randomness[0..len],
        pks_validate,
        &scratch,
    ) catch |e| return intFromError(e);

    out.* = agg_pk.toPublicKey();

    return 0;
}

export fn publicKeyAggregate(out: *blst.PublicKey, pks: [*c]const blst.PublicKey, len: c_uint, pks_validate: bool) c_uint {
    const agg_pk = blst.AggregatePublicKey.aggregate(pks[0..len], pks_validate) catch |e| return intFromError(e);

    out.* = agg_pk.toPublicKey();

    return 0;
}

////// AggregatePublicKey

export fn aggregatePublicKeySizeOf() c_uint {
    return @sizeOf(blst.AggregatePublicKey);
}

export fn aggregatePublicKeyAggregate(out: *blst.AggregatePublicKey, pks: [*c]const blst.PublicKey, pks_len: c_uint, pks_validate: bool) c_uint {
    out.* = blst.AggregatePublicKey.aggregate(pks[0..pks_len], pks_validate) catch |e| return intFromError(e);
    return 0;
}

export fn aggregatePublicKeyAggregateWithRandomness(
    out: *blst.AggregatePublicKey,
    pks: [*c]const blst.PublicKey,
    randomness: [*c]const u64,
    len: c_uint,
    pks_validate: bool,
) c_uint {
    out.* = blst.AggregatePublicKey.aggregateWithRandomness(
        pks[0..len],
        randomness[0..len],
        pks_validate,
        &scratch,
    ) catch |e| return intFromError(e);
    return 0;
}

export fn aggregatePublicKeyAddAggregate(out: *blst.AggregatePublicKey, other: *const blst.AggregatePublicKey) void {
    out.addAggregate(other);
}

export fn aggregatePublicKeyAddPublicKey(out: *blst.AggregatePublicKey, pk: *const blst.PublicKey, pk_validate: bool) c_uint {
    out.addPublicKey(pk, pk_validate) catch |e| return intFromError(e);
    return 0;
}

////// Signature

export fn signatureSizeOf() c_uint {
    return @sizeOf(blst.Signature);
}

export fn signatureCompressSize() c_uint {
    return blst.MIN_PK_COMPRESS_SIZE;
}

export fn signatureFromBytes(out: *blst.Signature, bytes: [*c]const u8, bytes_len: c_uint) c_uint {
    out.* = blst.Signature.uncompress(bytes[0..bytes_len]) catch |e| return intFromError(e);
    return 0;
}

export fn signatureToBytes(out: [*c]u8, sig: *const blst.Signature) void {
    out[0..blst.MIN_PK_COMPRESS_SIZE].* = sig.compress();
}

export fn signatureValidate(sig: *const blst.Signature, sig_infcheck: bool) c_uint {
    sig.validate(sig_infcheck) catch |e| return intFromError(e);
    return 0;
}

export fn signatureGroupCheck(sig: *const blst.Signature) bool {
    return sig.subgroupCheck();
}

export fn signatureToAggregate(out: *blst.AggregateSignature, sig: *const blst.Signature) void {
    out.* = blst.AggregateSignature.fromSignature(sig);
}

export fn signatureFromAggregate(out: *blst.Signature, agg_sig: *const blst.AggregateSignature) void {
    out.* = agg_sig.toSignature();
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
        &scratch,
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
        &scratch,
        msg.*,
        DST,
        pks[0..pks_len],
    ) catch |e| return intFromError(e);
    return @intFromBool(res);
}

export fn signatureAggregateWithRandomness(
    out: *blst.Signature,
    sigs: [*c]const blst.Signature,
    randomness: [*c]const u64,
    len: c_uint,
    sigs_groupcheck: bool,
) c_uint {
    const agg_sig = blst.AggregateSignature.aggregateWithRandomness(
        sigs[0..len],
        randomness[0..len],
        sigs_groupcheck,
        scratch[0..],
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
    const agg_sig = blst.AggregateSignature.aggregate(sigs[0..len], sigs_groupcheck) catch |e| return intFromError(e);

    out.* = agg_sig.toSignature();

    return 0;
}

////// AggregateSignature

export fn aggregateSignatureSizeOf() c_uint {
    return @sizeOf(blst.AggregateSignature);
}

export fn aggregateSignatureAggregate(out: *blst.AggregateSignature, sigs: [*c]const blst.Signature, sigs_len: c_uint, sigs_groupcheck: bool) c_uint {
    out.* = blst.AggregateSignature.aggregate(sigs[0..sigs_len], sigs_groupcheck) catch |e| return intFromError(e);
    return 0;
}

export fn aggregateSignatureAggregateWithRandomness(
    out: *blst.AggregateSignature,
    sigs: [*c]const blst.Signature,
    randomness: [*c]const u64,
    len: c_uint,
    sigs_groupcheck: bool,
) c_uint {
    out.* = blst.AggregateSignature.aggregateWithRandomness(
        sigs[0..len],
        randomness[0..len],
        sigs_groupcheck,
        &scratch,
    ) catch |e| return intFromError(e);

    return 0;
}

export fn aggregateSignatureAddAggregate(out: *blst.AggregateSignature, other: *const blst.AggregateSignature) c_uint {
    out.addAggregate(other) catch |e| return intFromError(e);
    return 0;
}

export fn aggregateSignatureAddSignature(out: *blst.AggregateSignature, sig: *const blst.Signature) c_uint {
    out.addSignature(sig, out) catch |e| return intFromError(e);
    return 0;
}
