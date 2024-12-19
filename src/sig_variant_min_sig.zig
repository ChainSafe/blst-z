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
    // c.blst_p2_affine_is_equal,
    // c.blst_p1_affine_is_equal,
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

// TODO test_serialization, test_serde, test_multi_point
