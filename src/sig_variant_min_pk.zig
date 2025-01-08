const std = @import("std");
const testing = std.testing;
const Xoshiro256 = std.rand.Xoshiro256;
const Pairing = @import("./pairing.zig").Pairing;
const c = @cImport({
    @cInclude("blst.h");
});
const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

const createSigVariant = @import("./sig_variant.zig").createSigVariant;

const SigVariant = createSigVariant(
    util.default_blst_p1_affline,
    util.default_blst_p1,
    util.default_blst_p2_affine,
    util.default_blst_p2,
    c.blst_p1,
    c.blst_p1_affine,
    c.blst_p2,
    c.blst_p2_affine,
    c.blst_sk_to_pk2_in_g1,
    true,
    c.blst_hash_to_g2,
    c.blst_sign_pk2_in_g1,
    c.blst_p1_affine_is_equal,
    c.blst_p2_affine_is_equal,
    // 2 new zig specific eq functions
    c.blst_p1_is_equal,
    c.blst_p2_is_equal,
    c.blst_core_verify_pk_in_g1,
    c.blst_p1_affine_in_g1,
    c.blst_p1_to_affine,
    c.blst_p1_from_affine,
    c.blst_p1_affine_serialize,
    c.blst_p1_affine_compress,
    c.blst_p1_deserialize,
    c.blst_p1_uncompress,
    48,
    96,
    c.blst_p2_affine_in_g2,
    c.blst_p2_to_affine,
    c.blst_p2_from_affine,
    c.blst_p2_affine_serialize,
    c.blst_p2_affine_compress,
    c.blst_p2_deserialize,
    c.blst_p2_uncompress,
    96,
    192,
    c.blst_p1_add_or_double,
    c.blst_p1_add_or_double_affine,
    c.blst_p2_add_or_double,
    c.blst_p2_add_or_double_affine,
    c.blst_p1_affine_is_inf,
    c.blst_p2_affine_is_inf,
    c.blst_p2_in_g2,
    // multi_point
    c.blst_p1s_add,
    c.blst_p1s_mult_pippenger,
    c.blst_p1s_mult_pippenger_scratch_sizeof,
    c.blst_p1_mult,
    c.blst_p1_generator,
    c.blst_p1s_to_affine,
    c.blst_p2s_add,
    c.blst_p2s_mult_pippenger,
    c.blst_p2s_mult_pippenger_scratch_sizeof,
    c.blst_p2_mult,
    c.blst_p2_generator,
    c.blst_p2s_to_affine,
);

pub const PublicKey = SigVariant.createPublicKey();
pub const AggregatePublicKey = SigVariant.createAggregatePublicKey();
pub const Signature = SigVariant.createSignature();
pub const AggregateSignature = SigVariant.createAggregateSignature();
pub const SecretKey = SigVariant.createSecretKey();
pub const aggregateWithRandomness = SigVariant.aggregateWithRandomness;

/// exported C-ABI functions need to be declared at top level, and they only work with extern struct
const PublicKeyType = SigVariant.getPublicKeyType();
const AggregatePublicKeyType = SigVariant.getAggregatePublicKeyType();
const SignatureType = SigVariant.getSignatureType();
const AggregateSignatureType = SigVariant.getAggregateSignatureType();

/// PublicKey functions
export fn defaultPublicKey(out: *PublicKeyType) void {
    return PublicKey.defaultPublicKey(out);
}

export fn validatePublicKey(pk: *const PublicKeyType) c_uint {
    return PublicKey.validatePublicKey(pk);
}

export fn publicKeyBytesValidate(key: [*c]const u8, len: usize) c_uint {
    return PublicKey.publicKeyBytesValidate(key, len);
}

export fn publicKeyFromAggregate(out: *PublicKeyType, agg_pk: *const AggregatePublicKeyType) void {
    return PublicKey.publicKeyFromAggregate(out, agg_pk);
}

export fn compressPublicKey(out: *u8, point: *const PublicKeyType) void {
    return PublicKey.compressPublicKey(out, point);
}

export fn serializePublicKey(out: *u8, point: *const PublicKeyType) void {
    return PublicKey.serializePublicKey(out, point);
}

export fn uncompressPublicKey(out: *PublicKeyType, pk_comp: [*c]const u8, len: usize) c_uint {
    return PublicKey.uncompressPublicKey(out, pk_comp, len);
}

export fn deserializePublicKey(out: *PublicKeyType, pk_in: [*c]const u8, len: usize) c_uint {
    return PublicKey.deserializePublicKey(out, pk_in, len);
}

export fn publicKeyFromBytes(point: *PublicKeyType, pk_in: [*c]const u8, len: usize) c_uint {
    return PublicKey.publicKeyFromBytes(point, pk_in, len);
}

export fn toPublicKeyBytes(out: *u8, point: *PublicKeyType) void {
    return PublicKey.toPublicKeyBytes(out, point);
}

export fn isPublicKeyEqual(point: *PublicKeyType, other: *PublicKeyType) bool {
    return PublicKey.isPublicKeyEqual(point, other);
}

/// AggregatePublicKeyType functions
export fn defaultAggregatePublicKey(out: *AggregatePublicKeyType) void {
    return AggregatePublicKey.defaultAggregatePublicKey(out);
}

export fn aggregateFromPublicKey(out: *AggregatePublicKeyType, pk: *const PublicKeyType) void {
    return AggregatePublicKey.aggregateFromPublicKey(out, pk);
}

export fn aggregateToPublicKey(out: *PublicKeyType, agg_pk: *const AggregatePublicKeyType) void {
    return AggregatePublicKey.aggregateToPublicKey(out, agg_pk);
}

export fn aggregatePublicKeys(out: *AggregatePublicKeyType, pks: [*c]*const PublicKeyType, len: usize, pks_validate: bool) c_uint {
    return AggregatePublicKey.aggregatePublicKeys(out, pks, len, pks_validate);
}

export fn aggregateCompressedPublicKeys(out: *AggregatePublicKeyType, pks: [*c][*c]const u8, len: usize, pks_validate: bool) c_uint {
    return AggregatePublicKey.aggregateCompressedPublicKeys(out, pks, len, pks_validate);
}

export fn aggregateSerializedPublicKeys(out: *AggregatePublicKeyType, pks: [*c][*c]const u8, len: usize, pks_validate: bool) c_uint {
    return AggregatePublicKey.aggregateSerializedPublicKeys(out, pks, len, pks_validate);
}

export fn addAggregatePublicKey(out: *AggregatePublicKeyType, agg_pk: *const AggregatePublicKeyType) void {
    return AggregatePublicKey.addAggregatePublicKey(out, agg_pk);
}

export fn addPublicKeyToAggregate(out: *AggregatePublicKeyType, pk: *const PublicKeyType, pk_validate: bool) c_uint {
    return AggregatePublicKey.addPublicKeyToAggregate(out, pk, pk_validate);
}

export fn isAggregatePublicKeyEqual(agg_pk: *const AggregatePublicKeyType, other: *const AggregatePublicKeyType) bool {
    return AggregatePublicKey.isAggregatePublicKeyEqual(agg_pk, other);
}

/// Signature functions
export fn defaultSignature(out: *SignatureType) void {
    return Signature.defaultSignature(out);
}

export fn validateSignature(sig: *const SignatureType, sig_infcheck: bool) c_uint {
    return Signature.validateSignature(sig, sig_infcheck);
}

export fn signatureBytesValidate(sig: [*c]const u8, sig_len: usize, sig_infcheck: bool) c_uint {
    return Signature.signatureBytesValidate(sig, sig_len, sig_infcheck);
}

export fn verifySignature(sig: *const SignatureType, sig_groupcheck: bool, msg: [*c]const u8, msg_len: usize, dst: [*c]const u8, dst_len: usize, aug_ptr: [*c]const u8, aug_len: usize, pk: *const PublicKeyType, pk_validate: bool) c_uint {
    return Signature.verifySignature(sig, sig_groupcheck, msg, msg_len, dst, dst_len, aug_ptr, aug_len, pk, pk_validate);
}

export fn aggregateVerify(sig: *const SignatureType, sig_groupcheck: bool, msgs: [*c][*c]const u8, msgs_len: usize, msg_len: usize, dst: [*c]const u8, dst_len: usize, pks: [*c]const *PublicKeyType, pks_len: usize, pks_validate: bool, pairing_buffer: [*c]u8, pairing_buffer_len: usize) c_uint {
    return Signature.aggregateVerifyC(sig, sig_groupcheck, msgs, msgs_len, msg_len, dst, dst_len, pks, pks_len, pks_validate, pairing_buffer, pairing_buffer_len);
}

// TODO: fastAggregateVerify: wait for AggregateSignatureType to be implemented

export fn fastAggregateVerifyPreAggregated(sig: *const SignatureType, sig_groupcheck: bool, msg: [*c]const u8, msg_len: usize, dst: [*c]const u8, dst_len: usize, pk: *PublicKeyType, pairing_buffer: [*c]u8, pairing_buffer_len: usize) c_uint {
    return Signature.fastAggregateVerifyPreAggregatedC(sig, sig_groupcheck, msg, msg_len, dst, dst_len, pk, pairing_buffer, pairing_buffer_len);
}

export fn verifyMultipleSignatures(msgs: [*c][*c]const u8, msgs_len: usize, msg_len: usize, dst: [*c]const u8, dst_len: usize, pks: [*c]*const PublicKeyType, pks_len: usize, pks_validate: bool, sigs: [*c]*const SignatureType, sigs_len: usize, sigs_groupcheck: bool, rands: [*c][*c]const u8, rands_len: usize, rand_bits: usize, pairing_buffer: [*c]u8, pairing_buffer_len: usize) c_uint {
    return Signature.verifyMultipleSignatures(msgs, msgs_len, msg_len, dst, dst_len, pks, pks_len, pks_validate, sigs, sigs_len, sigs_groupcheck, rands, rands_len, rand_bits, pairing_buffer, pairing_buffer_len);
}

export fn signatureFromAggregate(out: *SignatureType, agg_sig: *const AggregateSignatureType) void {
    Signature.signatureFromAggregate(out, agg_sig);
}

export fn compressSignature(out: *u8, point: *const SignatureType) void {
    Signature.compressSignature(out, point);
}

export fn serializeSignature(out: *u8, point: *const SignatureType) void {
    Signature.serializeSignature(out, point);
}

export fn uncompressSignature(out: *SignatureType, sig_comp: [*c]const u8, len: usize) c_uint {
    return Signature.uncompressSignature(out, sig_comp, len);
}

export fn deserializeSignature(out: *SignatureType, sig_in: [*c]const u8, len: usize) c_uint {
    return Signature.deserializeSignature(out, sig_in, len);
}

export fn signatureFromBytes(out: *SignatureType, sig_in: [*c]const u8, len: usize) c_uint {
    return Signature.signatureFromBytes(out, sig_in, len);
}

export fn signatureToBytes(out: *u8, point: *SignatureType) void {
    return Signature.signatureToBytes(out, point);
}

export fn signatureSubgroupCheck(point: *SignatureType) bool {
    return Signature.signatureSubgroupCheck(point);
}

export fn isSignatureEqual(point: *const SignatureType, other: *const SignatureType) bool {
    return Signature.isSignatureEqual(point, other);
}

/// AggregateSignatureType functions
export fn defaultAggregateSignature(out: *AggregateSignatureType) void {
    return AggregateSignature.defaultAggregateSignature(out);
}

export fn validateAggregateSignature(point: *const AggregateSignatureType) c_uint {
    return AggregateSignature.validateAggregateSignature(point);
}

export fn aggregateFromSignature(out: *AggregateSignatureType, sig: *const SignatureType) void {
    return AggregateSignature.aggregateFromSignature(out, sig);
}

export fn aggregateToSignature(out: *SignatureType, agg_sig: *const AggregateSignatureType) void {
    return AggregateSignature.aggregateToSignature(out, agg_sig);
}

export fn aggregateSignatures(out: *AggregateSignatureType, sigs: [*c]*const SignatureType, len: usize, sigs_groupcheck: bool) c_uint {
    return AggregateSignature.aggregateSignatures(out, sigs, len, sigs_groupcheck);
}

export fn aggregateSerialized(out: *AggregateSignatureType, sigs: [*c][*c]const u8, sigs_len: usize, sig_len: usize, sigs_groupcheck: bool) c_uint {
    return AggregateSignature.aggregateSerializedC(out, sigs, sigs_len, sig_len, sigs_groupcheck);
}

export fn addAggregateC(out: *AggregateSignatureType, agg_sig: *const AggregateSignatureType) void {
    return AggregateSignature.addAggregateC(out, agg_sig);
}

export fn addSignatureToAggregate(out: *AggregateSignatureType, sig: *const SignatureType, sig_groupcheck: bool) c_uint {
    return AggregateSignature.addSignatureToAggregate(out, sig, sig_groupcheck);
}

export fn subgroupCheckC(agg_sig: *const AggregateSignatureType) bool {
    return AggregateSignature.subgroupCheckC(agg_sig);
}

export fn isAggregateSignatureEqual(point: *const AggregateSignatureType, other: *const AggregateSignatureType) bool {
    return AggregateSignature.isAggregateSignatureEqual(point, other);
}

test "test_sign_n_verify" {
    try SigVariant.testSignNVerify();
}

test "test_aggregate" {
    try SigVariant.testAggregate();
}

test "test_multiple_agg_sigs" {
    try SigVariant.testMultipleAggSigs();
}

test "test_serialization" {
    try SigVariant.testSerialization();
}

test "test_serde" {
    try SigVariant.testSerde();
}

// prerequisite for test_multi_point
test "multi_point_test_type_alignment" {
    try SigVariant.testTypeAlignment();
}

test "multi_point_test_add_pubkey" {
    try SigVariant.testAddPubkey();
}

test "multi_point_test_mult_pubkey" {
    try SigVariant.testMultPubkey();
}

test "multi_point_test_add_signature" {
    try SigVariant.testAddSig();
}

test "multi_point_test_mult_signature" {
    try SigVariant.testMultSig();
}

test "test_multi_point" {
    try SigVariant.testMultiPoint();
}

test "test_aggregate_with_randomness" {
    try SigVariant.testAggregateWithRandomness();
}
