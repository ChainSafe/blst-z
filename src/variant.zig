const c = @import("c.zig");

pub const Variant = enum {
    min_pk,
    min_sig,

    pub fn Types(variant: Variant) type {
        _ = variant;
        // if (variant == .min_pk) {
        return struct {
            pub const Pk = c.blst_p1_affine;
            pub const AggPk = c.blst_p1;
            pub const Sig = c.blst_p2_affine;
            pub const AggSig = c.blst_p2;

            pub const sk_to_pk = c.blst_sk_to_pk2_in_g1;
            pub const sk_to_agg_pk = c.blst_sk_to_pk_in_g1;
            pub const hash = c.blst_hash_to_g2;
            pub const encode = c.blst_encode_to_g2;
            pub const sign = c.blst_sign_pk2_in_g1;
            pub const sign_agg = c.blst_sign_pk_in_g1;

            pub const pairing_aggregate = c.blst_pairing_chk_n_aggr_pk_in_g1;
            pub const pairing_mul_and_aggregate = c.blst_pairing_chk_n_mul_n_aggr_pk_in_g1;
            pub const aggregated = c.blst_aggregated_in_g2;

            pub const pk_is_inf = c.blst_p1_affine_is_inf;
            pub const agg_pk_is_inf = c.blst_p1_is_inf;
            pub const pk_in_group = c.blst_p1_affine_in_g1;
            pub const agg_pk_in_group = c.blst_p1_in_g1;
            pub const agg_pk_to_pk = c.blst_p1_to_affine;
            pub const pk_to_agg_pk = c.blst_p1_from_affine;
            pub const agg_pks_to_pk = c.blst_p1s_to_affine;
            pub const pks_add = c.blst_p1s_add;
            pub const pks_mult = c.blst_p1s_mult_pippenger;
            pub const pks_pippenger_scratch_sizeof = c.blst_p1s_mult_pippenger_scratch_sizeof;
            pub const pk_add_or_double_affine = c.blst_p1_add_or_double_affine;
            pub const pk_add_or_double = c.blst_p1_add_or_double;
            pub const pk_serialize_size = 96;
            pub const pk_serialize = c.blst_p1_affine_serialize;
            pub const agg_pk_serialize = c.blst_p1_serialize;
            pub const pk_deserialize = c.blst_p1_deserialize;
            pub const pk_compress_size = 48;
            pub const pk_compress = c.blst_p1_affine_compress;
            pub const agg_pk_compress = c.blst_p1_compress;
            pub const pk_uncompress = c.blst_p1_uncompress;
            pub const pk_is_equal = c.blst_p1_affine_is_equal;
            pub const agg_pk_is_equal = c.blst_p1_is_equal;

            pub const sig_is_inf = c.blst_p2_affine_is_inf;
            pub const sig_in_group = c.blst_p2_affine_in_g2;
            pub const agg_sig_in_group = c.blst_p2_in_g2;
            pub const agg_sig_to_sig = c.blst_p2_to_affine;
            pub const sig_to_agg_sig = c.blst_p2_from_affine;
            pub const agg_sigs_to_sig = c.blst_p2s_to_affine;
            pub const sigs_add = c.blst_p2s_add;
            pub const sigs_mult = c.blst_p2s_mult_pippenger;
            pub const sigs_pippenger_scratch_sizeof = c.blst_p2s_mult_pippenger_scratch_sizeof;
            pub const sig_add_or_double = c.blst_p2_add_or_double;
            pub const sig_add_or_double_affine = c.blst_p2_add_or_double_affine;
            pub const sig_serialize_size = 192;
            pub const sig_serialize = c.blst_p2_affine_serialize;
            pub const agg_sig_serialize = c.blst_p2_serialize;
            pub const sig_deserialize = c.blst_p2_deserialize;
            pub const sig_compress_size = 96;
            pub const sig_compress = c.blst_p2_affine_compress;
            pub const agg_sig_compress = c.blst_p2_compress;
            pub const sig_uncompress = c.blst_p2_uncompress;
            pub const sig_is_equal = c.blst_p2_affine_is_equal;
            pub const agg_sig_is_equal = c.blst_p2_is_equal;

            pub const sig_verify = c.blst_core_verify_pk_in_g1;
        };
        // } else {
        //     return struct {
        //         //
        //     };
        // }
    }
};
