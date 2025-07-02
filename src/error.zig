const c = @import("c.zig");

pub const BlstError = error{
    BAD_ENCODING,
    POINT_NOT_ON_CURVE,
    POINT_NOT_IN_GROUP,
    AGGR_TYPE_MISMATCH,
    VERIFY_FAIL,
    PK_IS_INFINITY,
    BAD_SCALAR,
    FAILED_PAIRING,
    MEMORY_POOL_ERROR,
    THREAD_POOL_ERROR,
};

// BLST_ERROR max as 7
pub const BLST_FAILED_PAIRING: c_uint = 10;
pub const MEMORY_POOL_ERROR: c_uint = 11;
pub const THREAD_POOL_ERROR: c_uint = 12;

pub fn intFromError(e: BlstError) c_uint {
    return switch (e) {
        BlstError.BAD_ENCODING => c.BLST_BAD_ENCODING,
        BlstError.POINT_NOT_ON_CURVE => c.BLST_POINT_NOT_ON_CURVE,
        BlstError.POINT_NOT_IN_GROUP => c.BLST_POINT_NOT_IN_GROUP,
        BlstError.AGGR_TYPE_MISMATCH => c.BLST_AGGR_TYPE_MISMATCH,
        BlstError.VERIFY_FAIL => c.BLST_VERIFY_FAIL,
        BlstError.PK_IS_INFINITY => c.BLST_PK_IS_INFINITY,
        BlstError.BAD_SCALAR => c.BLST_BAD_SCALAR,
        BlstError.FAILED_PAIRING => BLST_FAILED_PAIRING,
        BlstError.MEMORY_POOL_ERROR => MEMORY_POOL_ERROR,
        BlstError.THREAD_POOL_ERROR => THREAD_POOL_ERROR,
    };
}

pub fn check(err: c_uint) BlstError!void {
    switch (err) {
        c.BLST_BAD_ENCODING => return BlstError.BAD_ENCODING,
        c.BLST_POINT_NOT_ON_CURVE => return BlstError.POINT_NOT_ON_CURVE,
        c.BLST_POINT_NOT_IN_GROUP => return BlstError.POINT_NOT_IN_GROUP,
        c.BLST_AGGR_TYPE_MISMATCH => return BlstError.AGGR_TYPE_MISMATCH,
        c.BLST_VERIFY_FAIL => return BlstError.VERIFY_FAIL,
        c.BLST_PK_IS_INFINITY => return BlstError.PK_IS_INFINITY,
        c.BLST_BAD_SCALAR => return BlstError.BAD_SCALAR,
        BLST_FAILED_PAIRING => return BlstError.FAILED_PAIRING,
        MEMORY_POOL_ERROR => return BlstError.MEMORY_POOL_ERROR,
        THREAD_POOL_ERROR => return BlstError.THREAD_POOL_ERROR,
        else => return,
    }
}
