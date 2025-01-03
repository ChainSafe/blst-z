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

/// PublicKey functions
export fn defaultPublicKey() PublicKeyType {
    return PublicKey.defaultPublicKey();
}

export fn validatePublicKey(pk: *const PublicKeyType) c_uint {
    return PublicKey.validatePublicKey(pk);
}

export fn publicKeyBytesValidate(key: *const u8, len: usize) c_uint {
    return PublicKey.publicKeyBytesValidate(key, len);
}

export fn fromAggregatePublicKey(out: *PublicKeyType, agg_pk: *const AggregatePublicKeyType) void {
    return PublicKey.fromAggregatePublicKey(out, agg_pk);
}

export fn compressPublicKey(out: *u8, point: *const PublicKeyType) void {
    return PublicKey.compressPublicKey(out, point);
}

export fn serializePublicKey(out: *u8, point: *const PublicKeyType) void {
    return PublicKey.serializePublicKey(out, point);
}

export fn uncompressPublicKey(point: *PublicKeyType, pk_comp: *const u8, len: usize) c_uint {
    return PublicKey.uncompressPublicKey(point, pk_comp, len);
}

export fn deserializePublicKey(point: *PublicKeyType, pk_in: *const u8, len: usize) c_uint {
    return PublicKey.deserializePublicKey(point, pk_in, len);
}

export fn fromPublicKeyBytes(point: *PublicKeyType, pk_in: *const u8, len: usize) c_uint {
    return PublicKey.fromPublicKeyBytes(point, pk_in, len);
}

export fn toPublicKeyBytes(out: *u8, point: *PublicKeyType) void {
    return PublicKey.toPublicKeyBytes(out, point);
}

export fn isPublicKeyEqual(point: *PublicKeyType, other: *PublicKeyType) bool {
    return PublicKey.isPublicKeyEqual(point, other);
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
