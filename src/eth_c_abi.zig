const std = @import("std");
const blst = @import("min_pk.zig");
const intFromError = @import("util.zig").intFromError;

/// See https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

////// SecretKey

export fn secretKeySizeOf() c_uint {
    return @sizeOf(blst.SecretKey);
}

export fn secretKeySerializeSize() c_uint {
    return blst.SecretKey.serialize_size;
}

export fn secretKeyFromBytes(out: *blst.SecretKey, bytes: [*c]const u8, len: c_uint) c_uint {
    out.* = blst.SecretKey.deserialize(bytes[0..len]) catch |e| return intFromError(e);
    return 0;
}

export fn secretKeyToBytes(out: [*c]u8, sk: *const blst.SecretKey) void {
    out[0..blst.SecretKey.serialize_size].* = sk.serialize();
}

export fn sign(out: *blst.Signature, sk: *const blst.SecretKey, msg: [*c]const u8, msg_len: c_uint) c_uint {
    out.* = sk.sign(msg[0..msg_len], DST, null) catch |e| return intFromError(e);
    return 0;
}

////// PublicKey

export fn publicKeySizeOf() c_uint {
    return @sizeOf(blst.PublicKey);
}

export fn publicKeyCompressSize() c_uint {
    return blst.PublicKey.compress_size;
}

export fn publicKeyFromBytes(out: *blst.PublicKey, bytes: [*c]const u8, len: c_uint) c_uint {
    out.* = blst.PublicKey.uncompress(bytes[0..len]) catch |e| return intFromError(e);
    return 0;
}

export fn publicKeyToBytes(out: [*c]u8, pk: *const blst.PublicKey) void {
    out[0..blst.PublicKey.compress_size].* = pk.compress();
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

////// AggregatePublicKey

export fn aggregatePublicKeySizeOf() c_uint {
    return @sizeOf(blst.AggregatePublicKey);
}

export fn aggregatePublicKeyAggregate(out: *blst.AggregatePublicKey, pks: [*c]const blst.PublicKey, pks_len: c_uint, pks_validate: bool) c_uint {
    out.* = blst.AggregatePublicKey.aggregate(pks[0..pks_len], pks_validate) catch |e| return intFromError(e);
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
    return blst.Signature.compress_size;
}

export fn signatureFromBytes(out: *blst.Signature, bytes: [*c]const u8, bytes_len: c_uint) c_uint {
    out.* = blst.Signature.uncompress(bytes[0..bytes_len]) catch |e| return intFromError(e);
    return 0;
}

export fn signatureToBytes(out: [*c]u8, sig: *const blst.Signature) void {
    out[0..blst.Signature.compress_size].* = sig.compress();
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

threadlocal var pairing_buf: [blst.Pairing.sizeOf()]u8 = undefined;

export fn signatureAggregateVerify(
    sig: *const blst.Signature,
    sig_groupcheck: bool,
    msgs: [*c]const [32]u8,
    msgs_len: c_uint,
    pks: [*c]const blst.PublicKey,
    pks_len: c_uint,
    pks_validate: bool,
) c_uint {
    sig.aggregateVerify(
        sig_groupcheck,
        &pairing_buf,
        msgs[0..msgs_len],
        DST,
        pks[0..pks_len],
        pks_validate,
    ) catch |e| return intFromError(e);
    return 0;
}

export fn signatureFastAggregateVerify(
    sig: *const blst.Signature,
    sig_groupcheck: bool,
    msg: *const [32]u8,
    pks: [*c]const blst.PublicKey,
    pks_len: c_uint,
) c_uint {
    sig.fastAggregateVerify(
        sig_groupcheck,
        &pairing_buf,
        msg,
        DST,
        pks[0..pks_len],
    ) catch |e| return intFromError(e);
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

export fn aggregateSignatureAddAggregate(out: *blst.AggregateSignature, other: *const blst.AggregateSignature) void {
    out.addAggregate(other);
}

export fn aggregateSignatureAddSignature(out: *blst.AggregateSignature, sig: *const blst.Signature, sig_groupcheck: bool) c_uint {
    out.addSignature(sig, sig_groupcheck) catch |e| return intFromError(e);
    return 0;
}
