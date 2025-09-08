const std = @import("std");
const testing = std.testing;

pub const Pairing = @import("pairing.zig").Pairing;
pub const SecretKey = @import("secret_key.zig").SecretKey;
pub const PublicKey = @import("public_key.zig").PublicKey;
pub const Signature = @import("signature.zig").Signature;
pub const AggregatePublicKey = @import("AggregatePublicKey.zig");
pub const AggregateSignature = @import("AggregateSignature.zig");

pub const MIN_PK_COMPRESS_SIZE = 96;
pub const MIN_PK_SERIALIZE_SIZE = 192;

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

    const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
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
