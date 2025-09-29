const std = @import("std");
const testing = std.testing;

pub const Pairing = @import("Pairing.zig");
pub const SecretKey = @import("SecretKey.zig");
pub const PublicKey = @import("public_key.zig").PublicKey;
pub const Signature = @import("signature.zig").Signature;
pub const AggregatePublicKey = @import("AggregatePublicKey.zig");
pub const AggregateSignature = @import("AggregateSignature.zig");

pub const verifyMultipleAggregateSignatures = @import("fast_verify.zig").verifyMultipleAggregateSignatures;

/// Maximum number of signatures that can be aggregated in a single job.
pub const MAX_AGGREGATE_PER_JOB: usize = 128;

/// The domain separation tag (or DST) for the 'minimum pubkey size' signature variant.
///
/// Source: https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
pub const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

test {
    testing.refAllDecls(@This());
}
