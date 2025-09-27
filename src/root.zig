const std = @import("std");
const testing = std.testing;

pub const Pairing = @import("Pairing.zig");
pub const SecretKey = @import("SecretKey.zig");
pub const PublicKey = @import("public_key.zig").PublicKey;
pub const Signature = @import("signature.zig").Signature;
pub const AggregatePublicKey = @import("AggregatePublicKey.zig");
pub const AggregateSignature = @import("AggregateSignature.zig");

/// The domain separation tag (or DST) for the 'minimum pubkey size' signature variant.
///
/// Source: https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/beacon-chain.md#bls-signatures
pub const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

test {
    testing.refAllDecls(@This());
}

test "test_sign_n_verify" {
    // sample code for consumer like on Readme
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(&ikm, null);
    const pk = sk.toPublicKey();

    const dst = DST;
    const msg = "hello foo";
    // aug is null
    const sig = sk.sign(msg, dst, null);

    // aug is null
    try sig.verify(
        true,
        msg,
        dst,
        null,
        &pk,
        true,
    );
}

test "test aggregateVerify" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };

    const dst = DST;
    // aug is null

    const num_sigs = 10;

    var buffer: [3192]u8 = undefined;

    var msgs: [num_sigs][32]u8 = undefined;
    var sks: [num_sigs]SecretKey = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var sigs: [num_sigs]Signature = undefined;

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
        break :blk seed;
    });
    const rand = prng.random();
    for (0..num_sigs) |i| {
        std.Random.bytes(rand, &msgs[i]);
        const sk = try SecretKey.keyGen(&ikm, null);
        const pk = sk.toPublicKey();
        const sig = sk.sign(&msgs[i], dst, null);

        sks[i] = sk;
        pks[i] = pk;
        sigs[i] = sig;
    }

    const agg_sig = try AggregateSignature.aggregate(&sigs, false);
    const sig = Signature.fromAggregate(&agg_sig);

    try std.testing.expect(try sig.aggregateVerify(false, &buffer, &msgs, dst, &pks, false));
}
