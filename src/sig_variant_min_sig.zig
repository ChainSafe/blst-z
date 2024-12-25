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
    util.default_blst_p2_affline,
    util.default_blst_p2,
    util.default_blst_p1_affine,
    util.default_blst_p1,
    c.blst_p2,
    c.blst_p2_affine,
    c.blst_p1,
    c.blst_p1_affine,
    c.blst_sk_to_pk2_in_g2,
    true,
    c.blst_hash_to_g1,
    c.blst_sign_pk2_in_g2,
    c.blst_p2_affine_is_equal,
    c.blst_p1_affine_is_equal,
    // 2 new zig specific eq functions
    c.blst_p2_is_equal,
    c.blst_p1_is_equal,
    c.blst_core_verify_pk_in_g2,
    c.blst_p2_affine_in_g2,
    c.blst_p2_to_affine,
    c.blst_p2_from_affine,
    c.blst_p2_affine_serialize,
    c.blst_p2_affine_compress,
    c.blst_p2_deserialize,
    c.blst_p2_uncompress,
    96,
    192,
    c.blst_p1_affine_in_g1,
    c.blst_p1_to_affine,
    c.blst_p1_from_affine,
    c.blst_p1_affine_serialize,
    c.blst_p1_affine_compress,
    c.blst_p1_deserialize,
    c.blst_p1_uncompress,
    48,
    96,
    c.blst_p2_add_or_double,
    c.blst_p2_add_or_double_affine,
    c.blst_p1_add_or_double,
    c.blst_p1_add_or_double_affine,
    c.blst_p2_affine_is_inf,
    c.blst_p1_affine_is_inf,
    c.blst_p1_in_g1,
    // multi_point
    c.blst_p2s_add,
    c.blst_p2s_mult_pippenger,
    c.blst_p2s_mult_pippenger_scratch_sizeof,
    c.blst_p2_mult,
    c.blst_p2_generator,
    c.blst_p2s_to_affine,
);

pub const min_sig = struct {
    pub const PublicKey = SigVariant.createPublicKey();
    pub const AggregatePublicKey = SigVariant.createAggregatePublicKey();
    pub const Signature = SigVariant.createSignature();
    pub const AggregateSignature = SigVariant.createAggregateSignature();
    pub const SecretKey = SigVariant.createSecretKey();
};

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
test "test_type_alignment" {
    try SigVariant.testTypeAlignment();
}

test "multi_point_test_add_pubkey" {
    try SigVariant.testAddPubkey();
}

test "multi_point_test_mult_pubkey" {
    try SigVariant.testMultPubkey();
}

// TODO test_multi_point
