const c = @cImport({
    @cInclude("blst.h");
});

pub fn default_blst_scalar() c.blst_scalar {
    return c.blst_scalar{
        .b = [_]u8{0} ** 32,
    };
}
