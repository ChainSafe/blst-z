/// Configuration for minimum pubkey size settings.
const c = @cImport({
    @cInclude("blst.h");
});

pub const PublicKey = c.blst_p1_affine;
pub const AggPublicKey = c.blst_p1;
pub const Signature = c.blst_p2_affine;
pub const AggSignature = c.blst_p2;

pub const PK_COMPRESS_SIZE = 48;
pub const PK_SERIALIZE_SIZE = 96;

pub const SIGNATURE_LENGTH_COMPRESSED = 96;
pub const SIGNATURE_LENGTH_UNCOMPRESSED = 192;
