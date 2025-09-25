//! Configuration for minimum pubkey size settings.
const c = @cImport({
    @cInclude("blst.h");
});

pub const PublicKey = c.blst_p1_affine;
pub const AggPublicKey = c.blst_p1;
pub const Signature = c.blst_p2_affine;
pub const AggSignature = c.blst_p2;

pub const PK_COMPRESS_SIZE = 48;
pub const PK_SERIALIZE_SIZE = 96;
pub const SIG_SERIALIZE_SIZE = 192;
pub const SIG_COMPRESS_SIZE = 96;

/// The domain separation tag (or DST) for the 'minimum pubkey size' signature variant.
///
/// Source: https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
pub const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
