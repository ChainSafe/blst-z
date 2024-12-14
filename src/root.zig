/// this is equivalent of Rust binding in blst/bindings/rust/src/lib.rs
const std = @import("std");
const testing = std.testing;
const Xoshiro256 = std.rand.Xoshiro256;
const SecretKey = @import("./secret_key.zig").SecretKey;
const PublicKey = @import("./public_key.zig").PublicKey;
const Signature = @import("./signature.zig").Signature;
const AggregateSignature = @import("./signature.zig").AggregateSignature;
const Pairing = @import("./pairing.zig").Pairing;

const c = @cImport({
    @cInclude("blst.h");
});

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

// TODO: implement MultiPoint

fn getRandomKey(rng: *Xoshiro256) SecretKey {
    var value: [32]u8 = [_]u8{0} ** 32;
    rng.random().bytes(value[0..]);
    const sk = SecretKey.keyGen(value[0..], null) catch {
        @panic("SecretKey.keyGen() failed\n");
    };
    return sk;
}

test "test_sign_n_verify" {
    const ikm: [32]u8 = [_]u8{
        0x93, 0xad, 0x7e, 0x65, 0xde, 0xad, 0x05, 0x2a, 0x08, 0x3a,
        0x91, 0x0c, 0x8b, 0x72, 0x85, 0x91, 0x46, 0x4c, 0xca, 0x56,
        0x60, 0x5b, 0xb0, 0x56, 0xed, 0xfe, 0x2b, 0x60, 0xa6, 0x3c,
        0x48, 0x99,
    };
    const sk = try SecretKey.keyGen(ikm[0..], null);
    const pk = sk.skToPk();

    const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    const msg = "hello foo";
    // aug is null
    const sig = sk.sign(msg[0..], dst[0..], null);

    // aug is null
    try sig.verify(true, msg[0..], dst[0..], null, &pk, true);
}

test "test_aggregate" {
    const num_msgs = 10;
    const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    var rng = std.rand.DefaultPrng.init(12345);
    var sks = [_]SecretKey{SecretKey.default()} ** num_msgs;
    for (0..num_msgs) |i| {
        sks[i] = getRandomKey(&rng);
    }

    var pks: [num_msgs]PublicKey = undefined;
    const pksSlice = pks[0..];
    for (0..num_msgs) |i| {
        pksSlice[i] = sks[i].skToPk();
    }

    var pks_ptr: [num_msgs]*PublicKey = undefined;
    var pks_ptr_rev: [num_msgs]*PublicKey = undefined;
    for (pksSlice, 0..num_msgs) |*pk_ptr, i| {
        pks_ptr[i] = pk_ptr;
        pks_ptr_rev[num_msgs - i - 1] = pk_ptr;
    }

    const pk_comp = pksSlice[0].compress();
    _ = try PublicKey.uncompress(pk_comp[0..]);

    var msgs: [num_msgs][]u8 = undefined;
    // random message len
    const msg_lens: [num_msgs]u64 = comptime .{ 33, 34, 39, 22, 43, 1, 24, 60, 2, 41 };

    inline for (0..num_msgs) |i| {
        var msg = [_]u8{0} ** msg_lens[i];
        msgs[i] = msg[0..];
        rng.random().bytes(msgs[i]);
    }

    var sigs: [num_msgs]Signature = undefined;
    for (0..num_msgs) |i| {
        sigs[i] = sks[i].sign(msgs[i], dst, null);
    }

    for (0..num_msgs) |i| {
        try sigs[i].verify(true, msgs[i], dst, null, pks_ptr[i], true);
    }

    // Swap message/public key pairs to create bad signature
    for (0..num_msgs) |i| {
        if (sigs[i].verify(true, msgs[num_msgs - i - 1], dst, null, pks_ptr_rev[i], true)) {
            try std.testing.expect(false);
        } else |err| {
            try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
        }
    }

    var sig_ptrs: [num_msgs]*Signature = undefined;
    for (sigs[0..], 0..num_msgs) |*sig_ptr, i| {
        sig_ptrs[i] = sig_ptr;
    }
    const agg = try AggregateSignature.aggregate(sig_ptrs[0..], true);
    const agg_sig = agg.toSignature();

    var allocator = std.testing.allocator;
    const pairing_buffer = try allocator.alloc(u8, Pairing.sizeOf());
    defer allocator.free(pairing_buffer);

    // positive test
    try agg_sig.aggregate_verify(false, msgs[0..], dst, pks_ptr[0..], false, pairing_buffer);

    // Swap message/public key pairs to create bad signature
    if (agg_sig.aggregate_verify(false, msgs[0..], dst, pks_ptr_rev[0..], false, pairing_buffer)) {
        try std.testing.expect(false);
    } else |err| switch (err) {
        BLST_ERROR.VERIFY_FAIL => {},
        else => try std.testing.expect(false),
    }
}
