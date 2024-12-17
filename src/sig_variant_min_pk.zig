const c = @cImport({
    @cInclude("blst.h");
});
const util = @import("util.zig");

const createSigVariant = @import("./sig_variant.zig").createSigVariant;
// const SigVariant = createSigVariant(c.blst_p1_affine, util.default_blst_p1_affline, c.blst_p1_affine_is_inf, c.blst_p1_affine_in_g1, c.blst_p1_to_affine, c.blst_p1_affine_compress, c.blst_p1_affine_serialize, c.blst_p1_uncompress, c.blst_p1_deserialize);
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
    // c.blst_p1_affine_is_equal,
    // c.blst_p2_affine_is_equal,
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
);
pub const PublicKey = SigVariant.createPublicKey();
pub const SecretKey = SigVariant.createSecretKey();

test "SecretKey" {
    _ = SecretKey.default();
}

test "PublicKey" {
    _ = PublicKey.default();
}
