const c = @cImport({
    @cInclude("blst.h");
});

pub const BlstError = error{
    BadEncoding,
    PointNotOnCurve,
    PointNotInGroup,
    AggrTypeMismatch,
    VerifyFail,
    PkIsInfinity,
    BadScalar,
    FailedPairing,
    MemoryPoolError,
    ThreadPoolError,
};

comptime {
    // BLST_ERROR max as 7
    @import("std").debug.assert(BLST_FAILED_PAIRING == c.BLST_BAD_SCALAR + 1);
}
pub const BLST_FAILED_PAIRING: c_uint = 8;
pub const MEMORY_POOL_ERROR: c_uint = 9;
pub const THREAD_POOL_ERROR: c_uint = 10;

pub fn intFromError(e: BlstError) c_uint {
    return switch (e) {
        BlstError.BadEncoding => c.BLST_BAD_ENCODING,
        BlstError.PointNotOnCurve => c.BLST_POINT_NOT_ON_CURVE,
        BlstError.PointNotInGroup => c.BLST_POINT_NOT_IN_GROUP,
        BlstError.AggrTypeMismatch => c.BLST_AGGR_TYPE_MISMATCH,
        BlstError.VerifyFail => c.BLST_VERIFY_FAIL,
        BlstError.PkIsInfinity => c.BLST_PK_IS_INFINITY,
        BlstError.BadScalar => c.BLST_BAD_SCALAR,
        BlstError.FailedPairing => BLST_FAILED_PAIRING,
        BlstError.MemoryPoolError => MEMORY_POOL_ERROR,
        BlstError.ThreadPoolError => THREAD_POOL_ERROR,
    };
}

pub fn check(err: c_uint) BlstError!void {
    switch (err) {
        c.BLST_BAD_ENCODING => return BlstError.BadEncoding,
        c.BLST_POINT_NOT_ON_CURVE => return BlstError.PointNotOnCurve,
        c.BLST_POINT_NOT_IN_GROUP => return BlstError.PointNotInGroup,
        c.BLST_AGGR_TYPE_MISMATCH => return BlstError.AggrTypeMismatch,
        c.BLST_VERIFY_FAIL => return BlstError.VerifyFail,
        c.BLST_PK_IS_INFINITY => return BlstError.PkIsInfinity,
        c.BLST_BAD_SCALAR => return BlstError.BadScalar,
        BLST_FAILED_PAIRING => return BlstError.FailedPairing,
        MEMORY_POOL_ERROR => return BlstError.MemoryPoolError,
        THREAD_POOL_ERROR => return BlstError.ThreadPoolError,
        else => return,
    }
}
