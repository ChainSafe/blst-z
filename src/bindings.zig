const c = @cImport({
    @cInclude("blst.h");
});

const byte = u8;
const limb_t = u64;

const blst_scalar = struct {
    b: [256 / 8]byte,
};

const blst_fr = struct {
    l: [256 / 8 / @sizeOf(limb_t)]limb_t,
};

const blst_fp = struct {
    l: [384 / 8 / @sizeOf(limb_t)]limb_t,
};

// /* 0 is "real" part, 1 is "imaginary" */

const blst_fp2 = struct {
    fp: [2]blst_fp,
};

const blst_fp6 = struct {
    fp2: [3]blst_fp2,
};

const blst_fp12 = struct {
    fp6: [2]blst_fp6,
};

pub const IncorrectLen = error{IncorrectLen};

pub fn blst_scalar_from_uint32(out: *blst_scalar, a: []const u32) IncorrectLen!void {
    if (a.len != 8) {
        return error.IncorrectLen;
    }
    c.blst_scalar_from_uint32(out, a);
}

pub fn blst_uint32_from_scalar(out: []u32, a: *const blst_scalar) IncorrectLen!void {
    if (out.len != 8) {}
    c.blst_uint32_from_scalar(out, a);
}

pub fn blst_scalar_from_uint64(out: *blst_scalar, a: []const u64) IncorrectLen!void {
    if (a.len != 4) {
        return error.IncorrectLen;
    }
    c.blst_scalar_from_uint64(out, a);
}

pub fn blst_uint64_from_scalar(out: []u64, a: *const blst_scalar) IncorrectLen!void {
    if (out.len != 4) {
        return error.IncorrectLen;
    }
    c.blst_uint64_from_scalar(out, a);
}

pub fn blst_bendian_from_scalar(out: []byte, a: *const blst_scalar) IncorrectLen!void {
    if (out.len != 32) {
        return error.IncorrectLen;
    }
    c.blst_bendian_from_scalar(out, a);
}

pub fn blst_scalar_from_lendian(out: *blst_scalar, a: []const byte) IncorrectLen!void {
    if (a.len != 32) {
        return error.IncorrectLen;
    }
    c.blst_scalar_from_lendian(out, a);
}

pub fn blst_lendian_from_scalar(out: []byte, a: *const blst_scalar) IncorrectLen!void {
    if (out.len != 32) {
        return error.IncorrectLen;
    }
    c.blst_lendian_from_scalar(out, a);
}

pub fn blst_scalar_fr_check(a: *const blst_scalar) bool {
    return c.blst_scalar_fr_check(a);
}

pub fn blst_sk_check(a: *const blst_scalar) bool {
    return c.blst_sk_check(a);
}

pub fn blst_sk_add_n_check(out: *blst_scalar, a: *const blst_scalar, b: *const blst_scalar) bool {
    return c.blst_sk_add_n_check(out, a, b);
}

pub fn blst_sk_sub_n_check(out: *blst_scalar, a: *const blst_scalar, b: *const blst_scalar) bool {
    return c.blst_sk_sub_n_check(out, a, b);
}

pub fn blst_sk_mul_n_check(out: *blst_scalar, a: *const blst_scalar, b: *const blst_scalar) bool {
    return c.blst_sk_mul_n_check(out, a, b);
}

pub fn blst_sk_inverse(out: *blst_scalar, a: *const blst_scalar) void {
    c.blst_sk_inverse(out, a);
}

pub fn blst_scalar_from_le_bytes(out: *blst_scalar, in: *const byte, len: usize) bool {
    return c.blst_scalar_from_le_bytes(out, in, len);
}

pub fn blst_scalar_from_be_bytes(out: *blst_scalar, in: *const byte, len: usize) bool {
    return c.blst_scalar_from_be_bytes(out, in, len);
}

/// BLS12-381-specific Fr operations.
pub fn blst_fr_add(ret: *blst_fr, a: *const blst_fr, b: *const blst_fr) void {
    c.blst_fr_add(ret, a, b);
}

pub fn blst_fr_sub(ret: *blst_fr, a: *const blst_fr, b: *const blst_fr) void {
    c.blst_fr_sub(ret, a, b);
}

pub fn blst_fr_mul_by_3(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_mul_by_3(ret, a);
}

pub fn blst_fr_lshift(ret: *blst_fr, a: *const blst_fr, count: usize) void {
    c.blst_fr_lshift(ret, a, count);
}

pub fn blst_fr_rshift(ret: *blst_fr, a: *const blst_fr, count: usize) void {
    c.blst_fr_rshift(ret, a, count);
}

pub fn blst_fr_mul(ret: *blst_fr, a: *const blst_fr, b: *const blst_fr) void {
    c.blst_fr_mul(ret, a, b);
}

pub fn blst_fr_sqr(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_sqr(ret, a);
}

pub fn blst_fr_cneg(ret: *blst_fr, a: *const blst_fr, flag: bool) void {
    c.blst_fr_cneg(ret, a, flag);
}

pub fn blst_fr_eucl_inverse(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_eucl_inverse(ret, a);
}

pub fn blst_fr_inverse(ret: *blst_fr, a: *const blst_fr) void {
    c.blst_fr_inverse(ret, a);
}

pub fn blst_fr_from_uint64(ret: *blst_fr, a: []const u64) IncorrectLen!void {
    if (a.len != 4) {
        return error.IncorrectLen;
    }

    c.blst_fr_from_uint64(ret, a);
}

pub fn blst_uint64_from_fr(ret: []u64, a: *const blst_fr) IncorrectLen!void {
    if (ret.len != 4) {
        return error.IncorrectLen;
    }

    c.blst_uint64_from_fr(ret, a);
}

pub fn blst_fr_from_scalar(ret: *blst_fr, a: *const blst_scalar) void {
    c.blst_fr_from_scalar(ret, a);
}

pub fn blst_scalar_from_fr(ret: *blst_scalar, a: *const blst_fr) void {
    c.blst_scalar_from_fr(ret, a);
}

/// BLS12-381-specific Fp operations.
pub fn blst_fp_add(ret: *blst_fp, a: *const blst_fp, b: *const blst_fp) void {
    c.blst_fp_add(ret, a, b);
}

pub fn blst_fp_sub(ret: *blst_fp, a: *const blst_fp, b: *const blst_fp) void {
    c.blst_fp_sub(ret, a, b);
}

pub fn blst_fp_mul_by_3(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_mul_by_3(ret, a);
}

pub fn blst_fp_mul_by_8(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_mul_by_8(ret, a);
}

pub fn blst_fp_lshift(ret: *blst_fp, a: *const blst_fp, count: usize) void {
    c.blst_fp_lshift(ret, a, count);
}

pub fn blst_fp_mul(ret: *blst_fp, a: *const blst_fp, b: *const blst_fp) void {
    c.blst_fp_mul(ret, a, b);
}

pub fn blst_fp_sqr(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_sqr(ret, a);
}

pub fn blst_fp_cneg(ret: *blst_fp, a: *const blst_fp, flag: bool) void {
    c.blst_fp_cneg(ret, a, flag);
}

pub fn blst_fp_eucl_inverse(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_eucl_inverse(ret, a);
}

pub fn blst_fp_inverse(ret: *blst_fp, a: *const blst_fp) void {
    c.blst_fp_inverse(ret, a);
}

pub fn blst_fp_sqrt(ret: *blst_fp, a: *const blst_fp) bool {
    return c.blst_fp_sqrt(ret, a);
}

pub fn blst_fp_from_uint32(ret: *blst_fp, a: []const u32) IncorrectLen!void {
    if (a.len != 12) {
        return error.IncorrectLen;
    }

    c.blst_fp_from_uint32(ret, a);
}

pub fn blst_uint32_from_fp(ret: []u32, a: *const blst_fp) IncorrectLen!void {
    if (ret.len != 12) {
        return error.IncorrectLen;
    }

    c.blst_uint32_from_fp(ret, a);
}

pub fn blst_fp_from_uint64(ret: *blst_fp, a: []const u64) IncorrectLen!void {
    if (a.len != 6) {
        return error.IncorrectLen;
    }

    c.blst_fp_from_uint64(ret, a);
}

pub fn blst_uint64_from_fp(ret: []u64, a: *const blst_fp) IncorrectLen!void {
    if (ret.len != 6) {
        return error.IncorrectLen;
    }

    c.blst_uint64_from_fp(ret, a);
}

pub fn blst_fp_from_bendian(ret: *blst_fp, a: []const byte) IncorrectLen!void {
    if (a.len != 48) {
        return error.IncorrectLen;
    }

    c.blst_fp_from_bendian(ret, a);
}

pub fn blst_bendian_from_fp(ret: []byte, a: *const blst_fp) IncorrectLen!void {
    if (ret.len != 48) {
        return error.IncorrectLen;
    }

    c.blst_bendian_from_fp(ret, a);
}

pub fn blst_fp_from_lendian(ret: *blst_fp, a: []const byte) IncorrectLen!void {
    if (a.len != 48) {
        return error.IncorrectLen;
    }

    c.blst_fp_from_lendian(ret, a);
}

pub fn blst_lendian_from_fp(ret: []byte, a: *const blst_fp) IncorrectLen!void {
    if (ret.len != 48) {
        return error.IncorrectLen;
    }

    c.blst_lendian_from_fp(ret, a);
}

/// BLS12-381-specific Fp2 operations.
pub fn blst_fp2_add(ret: *blst_fp2, a: *const blst_fp2, b: *const blst_fp2) void {
    c.blst_fp2_add(ret, a, b);
}

pub fn blst_fp2_sub(ret: *blst_fp2, a: *const blst_fp2, b: *const blst_fp2) void {
    c.blst_fp2_sub(ret, a, b);
}

pub fn blst_fp2_mul_by_3(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_mul_by_3(ret, a);
}

pub fn blst_fp2_mul_by_8(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_mul_by_8(ret, a);
}

pub fn blst_fp2_lshift(ret: *blst_fp2, a: *const blst_fp2, count: usize) void {
    c.blst_fp2_lshift(ret, a, count);
}

pub fn blst_fp2_mul(ret: *blst_fp2, a: *const blst_fp2, b: *const blst_fp2) void {
    c.blst_fp2_mul(ret, a, b);
}

pub fn blst_fp2_sqr(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_sqr(ret, a);
}

pub fn blst_fp2_cneg(ret: *blst_fp2, a: *const blst_fp2, flag: bool) void {
    c.blst_fp2_cneg(ret, a, flag);
}

pub fn blst_fp2_eucl_inverse(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_eucl_inverse(ret, a);
}

pub fn blst_fp2_inverse(ret: *blst_fp2, a: *const blst_fp2) void {
    c.blst_fp2_inverse(ret, a);
}

pub fn blst_fp2_sqrt(ret: *blst_fp2, a: *const blst_fp2) bool {
    return c.blst_fp2_sqrt(ret, a);
}

/// BLS12-381-specific Fp12 operations.
pub fn blst_fp12_sqr(ret: *blst_fp12, a: *const blst_fp12) void {
    c.blst_fp12_sqr(ret, a);
}

pub fn blst_fp12_cyclotomic_sqr(ret: *blst_fp12, a: *const blst_fp12) void {
    c.blst_fp12_cyclotomic_sqr(ret, a);
}

pub fn blst_fp12_mul(ret: *blst_fp12, a: *const blst_fp12, b: *const blst_fp12) void {
    c.blst_fp12_mul(ret, a, b);
}

pub fn blst_fp12_mul_by_xy00z0(ret: *blst_fp12, a: *const blst_fp12, xy00z0: *blst_fp6) void {
    c.blst_fp12_mul_by_xy00z0(ret, a, xy00z0);
}

pub fn blst_fp12_conjugate(a: *const blst_fp12) void {
    c.blst_fp12_conjugate(a);
}

pub fn blst_fp12_inverse(ret: *blst_fp12, a: *const blst_fp12) void {
    c.blst_fp12_inverse(ret, a);
}

// caveat lector! |n| has to be non-zero and not more than 3!
pub fn blst_fp12_frobenius_map(ret: *blst_fp12, a: *const blst_fp12, n: usize) void {
    c.blst_fp12_frobenius_map(ret, a, n);
}

pub fn blst_fp12_is_equal(a: *const blst_fp12, b: *const blst_fp12) bool {
    return c.blst_fp12_is_equal(a, b);
}

pub fn blst_fp12_is_one(a: *const blst_fp12) bool {
    return c.blst_fp12_is_one(a);
}

pub fn blst_fp12_in_group(a: *const blst_fp12) bool {
    return c.blst_fp12_in_group(a);
}

pub fn blst_fp12_one(ret: *blst_fp12) void {
    c.blst_fp12_one(ret);
}

// /// BLS12-381-specific point operations.
// const blst_p1 = extern struct {
//     x: blst_fp,
//     y: blst_fp,
//     z: blst_fp,
// };
