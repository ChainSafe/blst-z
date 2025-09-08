const c = @cImport({
    @cInclude("blst.h");
});

pub const PublicKey = c.blst_p1_affine;
pub const AggPublicKey = c.blst_p1;
pub const Signature = c.blst_p2_affine;
pub const AggSignature = c.blst_p2;
