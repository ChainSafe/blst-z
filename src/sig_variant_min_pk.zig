const std = @import("std");
const testing = std.testing;
const Xoshiro256 = std.rand.Xoshiro256;
const Pairing = @import("./pairing.zig").Pairing;
const c = @cImport({
    @cInclude("blst.h");
});
const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

// TODO: implement MultiPoint

/// this is equivalent of Rust binding in blst/bindings/rust/src/lib.rs
const createSigVariant = @import("./sig_variant.zig").createSigVariant;
// const SigVariant = createSigVariant(c.blst_p1_affine, util.default_blst_p1_affline, c.blst_p1_affine_is_inf, c.blst_p1_affine_in_g1, c.blst_p1_to_affine, c.blst_p1_affine_compress, c.blst_p1_affine_serialize, c.blst_p1_uncompress, c.blst_p1_deserialize);
pub const MinPk = createSigVariant(
    util.default_blst_p1_affline,
    util.default_blst_p1,
    util.default_blst_p2_affine,
    util.default_blst_p2,
    c.blst_p1,
    c.blst_p1_affine,
    c.blst_p2,
    c.blst_p2_affine,
    c.blst_sk_to_pk2_in_g1,
    true,
    c.blst_hash_to_g2,
    c.blst_sign_pk2_in_g1,
    // c.blst_p1_affine_is_equal,
    // c.blst_p2_affine_is_equal,
    c.blst_core_verify_pk_in_g1,
    c.blst_p1_affine_in_g1,
    c.blst_p1_to_affine,
    c.blst_p1_from_affine,
    c.blst_p1_affine_serialize,
    c.blst_p1_affine_compress,
    c.blst_p1_deserialize,
    c.blst_p1_uncompress,
    48,
    96,
    c.blst_p2_affine_in_g2,
    c.blst_p2_to_affine,
    c.blst_p2_from_affine,
    c.blst_p2_affine_serialize,
    c.blst_p2_affine_compress,
    c.blst_p2_deserialize,
    c.blst_p2_uncompress,
    96,
    192,
    c.blst_p1_add_or_double,
    c.blst_p1_add_or_double_affine,
    c.blst_p2_add_or_double,
    c.blst_p2_add_or_double_affine,
    c.blst_p1_affine_is_inf,
    c.blst_p2_affine_is_inf,
    c.blst_p2_in_g2,
);
pub const PublicKey = MinPk.createPublicKey();
pub const AggregatePublicKey = MinPk.createAggregatePublicKey();
pub const Signature = MinPk.createSignature();
pub const AggregateSignature = MinPk.createAggregateSignature();
pub const SecretKey = MinPk.createSecretKey();

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
    try agg_sig.aggregateVerify(false, msgs[0..], dst, pks_ptr[0..], false, pairing_buffer);

    // Swap message/public key pairs to create bad signature
    if (agg_sig.aggregateVerify(false, msgs[0..], dst, pks_ptr_rev[0..], false, pairing_buffer)) {
        try std.testing.expect(false);
    } else |err| switch (err) {
        BLST_ERROR.VERIFY_FAIL => {},
        else => try std.testing.expect(false),
    }
}

test "test_multiple_agg_sigs" {
    var allocator = std.testing.allocator;
    // single pairing_buffer allocation that could be reused multiple times
    const pairing_buffer = try allocator.alloc(u8, Pairing.sizeOf());
    defer allocator.free(pairing_buffer);

    const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    const num_pks_per_sig = 10;
    const num_sigs = 10;

    var rng = std.rand.DefaultPrng.init(12345);

    var msgs: [num_sigs][]u8 = undefined;
    var sigs: [num_sigs]Signature = undefined;
    var pks: [num_sigs]PublicKey = undefined;
    var rands: [num_sigs][]u8 = undefined;

    // random message len
    const msg_lens: [num_sigs]u64 = comptime .{ 33, 34, 39, 22, 43, 1, 24, 60, 2, 41 };
    const max_len = 64;

    // use inline for to keep scopes of all variable in this function instead of block scope
    inline for (0..num_sigs) |i| {
        var msg = [_]u8{0} ** max_len;
        msgs[i] = msg[0..];
        var rand = [_]u8{0} ** 32;
        rands[i] = rand[0..];
    }

    for (0..num_sigs) |i| {
        // Create public keys
        var sks_i: [num_pks_per_sig]SecretKey = undefined;
        var pks_i: [num_pks_per_sig]PublicKey = undefined;
        var pks_refs_i: [num_pks_per_sig]*PublicKey = undefined;
        for (0..num_pks_per_sig) |j| {
            sks_i[j] = getRandomKey(&rng);
            pks_i[j] = sks_i[j].skToPk();
            pks_refs_i[j] = &pks_i[j];
        }

        // Create random message for pks to all sign
        const msg_len = msg_lens[i];
        msgs[i] = msgs[i][0..msg_len];
        rng.random().bytes(msgs[i]);

        // Generate signature for each key pair
        var sigs_i: [num_pks_per_sig]Signature = undefined;
        for (0..num_pks_per_sig) |j| {
            sigs_i[j] = sks_i[j].sign(msgs[i], dst, null);
        }

        // Test each current single signature
        for (0..num_pks_per_sig) |j| {
            try sigs_i[j].verify(true, msgs[i], dst, null, pks_refs_i[j], true);
        }

        var sig_refs_i: [num_pks_per_sig]*const Signature = undefined;
        for (sigs_i[0..], 0..num_pks_per_sig) |*sig_ptr, j| {
            sig_refs_i[j] = sig_ptr;
        }

        const agg_i = try AggregateSignature.aggregate(sig_refs_i[0..], false);

        // Test current aggregate signature
        sigs[i] = agg_i.toSignature();
        try sigs[i].fastAggregateVerify(false, msgs[i], dst, pks_refs_i[0..], pairing_buffer);

        // negative test
        if (i != 0) {
            const verify_res = sigs[i - 1].fastAggregateVerify(false, msgs[i], dst, pks_refs_i[0..], pairing_buffer);
            if (verify_res) {
                try std.testing.expect(false);
            } else |err| {
                try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
            }
        }

        // aggregate public keys and push into vec
        const pk_i = try AggregatePublicKey.aggregate(pks_refs_i[0..], false);
        pks[i] = pk_i.toPublicKey();

        // Test current aggregate signature with aggregated pks
        try sigs[i].fastAggregateVerifyPreAggregated(false, msgs[i], dst, &pks[i], pairing_buffer);

        // negative test
        if (i != 0) {
            const verify_res = sigs[i - 1].fastAggregateVerifyPreAggregated(false, msgs[i], dst, &pks[i], pairing_buffer);
            if (verify_res) {
                try std.testing.expect(false);
            } else |err| {
                try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
            }
        }

        // create random values
        var rand_i = rands[i];
        // Reinterpret the buffer as an array of 4 u64
        const u64_array = std.mem.bytesAsSlice(u64, rand_i[0..]);

        while (u64_array[0] == 0) {
            // Reject zero as it is used for multiplication.
            rng.random().bytes(rand_i[0..]);
        }
    }

    var pks_refs: [num_sigs]*PublicKey = undefined;
    for (pks[0..], 0..num_sigs) |*pk, i| {
        pks_refs[i] = pk;
    }

    var msgs_rev: [num_sigs][]u8 = undefined;
    for (msgs[0..], 0..num_sigs) |msg, i| {
        msgs_rev[num_sigs - i - 1] = msg;
    }

    var sigs_refs: [num_sigs]*Signature = undefined;
    for (sigs[0..], 0..num_sigs) |*sig, i| {
        sigs_refs[i] = sig;
    }

    var pks_rev: [num_sigs]*PublicKey = undefined;
    for (pks_refs[0..], 0..num_sigs) |pk, i| {
        pks_rev[num_sigs - i - 1] = pk;
    }

    var sig_rev_refs: [num_sigs]*Signature = undefined;
    for (sigs_refs[0..], 0..num_sigs) |sig, i| {
        sig_rev_refs[num_sigs - i - 1] = sig;
    }

    try Signature.verifyMultipleAggregateSignatures(msgs[0..], dst, pks_refs[0..], false, sigs_refs[0..], false, rands[0..], 64, pairing_buffer);

    // negative tests (use reverse msgs, pks, and sigs)
    var verify_res = Signature.verifyMultipleAggregateSignatures(msgs_rev[0..], dst, pks_refs[0..], false, sigs_refs[0..], false, rands[0..], 64, pairing_buffer);
    if (verify_res) {
        try std.testing.expect(false);
    } else |err| {
        try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
    }

    verify_res = Signature.verifyMultipleAggregateSignatures(msgs[0..], dst, pks_rev[0..], false, sigs_refs[0..], false, rands[0..], 64, pairing_buffer);
    if (verify_res) {
        try std.testing.expect(false);
    } else |err| {
        try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
    }

    verify_res = Signature.verifyMultipleAggregateSignatures(msgs[0..], dst, pks_refs[0..], false, sig_rev_refs[0..], false, rands[0..], 64, pairing_buffer);
    if (verify_res) {
        try std.testing.expect(false);
    } else |err| {
        try std.testing.expectEqual(BLST_ERROR.VERIFY_FAIL, err);
    }
}

// TODO test_serialization, test_serde, test_multi_point
