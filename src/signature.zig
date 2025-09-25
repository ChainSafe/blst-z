const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const PublicKey = @import("public_key.zig").PublicKey;
const AggregatePublicKey = @import("AggregatePublicKey.zig");
const AggregateSignature = @import("AggregateSignature.zig");
const Pairing = @import("pairing.zig").Pairing;
const PairingError = @import("pairing.zig").Pairing.Error;
const pairing_size = @import("pairing.zig").pairing_size;

const c = @cImport({
    @cInclude("blst.h");
});
const min_pk = @import("min_pk.zig");

const RAND_BYTES = 8;
const RAND_BITS = 8 * RAND_BYTES;

/// https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
///
/// Returns false if verification fails.
pub fn verifyMultipleAggregateSignatures(
    pairing_buf: *[pairing_size]u8,
    n_elems: usize,
    msgs: [*c]const [32]u8,
    dst: []const u8,
    pks: [*c]const *PublicKey,
    pks_validate: bool,
    sigs: [*c]const *Signature,
    sigs_groupcheck: bool,
    rands: [*c]const [32]u8,
) BlstError!bool {
    if (n_elems == 0) {
        return BlstError.VerifyFail;
    }

    var pairing = Pairing.init(
        pairing_buf,
        true,
        dst,
    );

    for (0..n_elems) |i| {
        try pairing.mulAndAggregate(
            &pks[i].point,
            pks_validate,
            &sigs[i].point,
            sigs_groupcheck,
            &rands[i],
            RAND_BITS,
            &msgs[i],
        );
    }

    pairing.commit();

    return pairing.finalVerify(null);
}

pub const Signature = extern struct {
    point: min_pk.Signature = min_pk.Signature{},

    const Self = @This();

    // sig_infcheck, check for infinity, is a way to avoid going
    // into resource-consuming verification. Passing 'false' is
    // always cryptographically safe, but application might want
    // to guard against obviously bogus individual[!] signatures.
    pub fn validate(self: *const Self, sig_infcheck: bool) BlstError!void {
        if (sig_infcheck and c.blst_p2_affine_is_inf(&self.point)) {
            return BlstError.PkIsInfinity;
        }

        if (!c.blst_p2_affine_in_g2(&self.point)) {
            return BlstError.PointNotInGroup;
        }
    }

    // same to non-std verify in Rust
    pub fn verify(
        self: *const Self,
        sig_groupcheck: bool,
        msg: []const u8,
        dst: []const u8,
        aug: ?[]const u8,
        pk: *const PublicKey,
        pk_validate: bool,
    ) BlstError!void {
        if (sig_groupcheck) try self.validate(false);

        if (pk_validate) try pk.validate();

        if (msg.len == 0 or dst.len == 0) {
            return BlstError.BadEncoding;
        }

        const chk = check(c.blst_core_verify_pk_in_g1(
            @ptrCast(&pk.point),
            @ptrCast(&self.point),
            true,
            @ptrCast(msg),
            msg.len,
            @ptrCast(dst),
            dst.len,
            @ptrCast(aug),
            if (aug) |a| a.len else 0,
        ));

        return chk;
    }

    /// Returns false if verification fails.
    pub fn aggregateVerify(
        self: *const Self,
        sig_groupcheck: bool,
        buffer: *[pairing_size]u8,
        msgs: []const [32]u8,
        dst: []const u8,
        pks: []const PublicKey,
        pks_validate: bool,
    ) BlstError!bool {
        var rands: [32 * 128][32]u8 = undefined;
        var prng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            std.posix.getrandom(std.mem.asBytes(&seed)) catch unreachable;
            break :blk seed;
        });
        const rand = prng.random();

        for (0..32 * 128) |i| {
            std.Random.bytes(rand, &rands[i]);
        }

        const n_elems = pks.len;
        if (n_elems == 0 or msgs.len != n_elems) {
            return BlstError.VerifyFail;
        }
        var pairing = Pairing.init(buffer, true, dst);
        try pairing.aggregate(
            &pks[0].point,
            pks_validate,
            &self.point,
            sig_groupcheck,
            &msgs[0],
            null,
        );

        for (1..n_elems) |i| {
            try pairing.aggregate(
                &pks[i].point,
                pks_validate,
                null,
                sig_groupcheck,
                &msgs[i],
                null,
            );
        }

        pairing.commit();
        var gtsig = c.blst_fp12{};
        Pairing.aggregated(&gtsig, &self.point);

        return pairing.finalVerify(&gtsig);
    }

    /// same to fast_aggregate_verify in Rust with extra `pool` parameter
    pub fn fastAggregateVerify(
        self: *const Self,
        sig_groupcheck: bool,
        buffer: *[pairing_size]u8,
        msg: [32]u8,
        dst: []const u8,
        pks: []const PublicKey,
    ) BlstError!bool {
        const agg_pk = try AggregatePublicKey.aggregate(pks, false);
        const pk = agg_pk.toPublicKey();

        return try self.aggregateVerify(
            sig_groupcheck,
            buffer,
            &[_][32]u8{msg},
            dst,
            &[_]PublicKey{pk},
            false,
        );
    }

    /// same to fast_aggregate_verify_pre_aggregated in Rust
    pub fn fastAggregateVerifyPreAggregated(
        self: *const Self,
        sig_groupcheck: bool,
        buffer: *[pairing_size]u8,
        msg: *const [32]u8,
        dst: []const u8,
        pk: *const PublicKey,
    ) BlstError!void {
        var msgs = [_][]const u8{msg};
        var pks = [_]*const PublicKey{pk};
        try self.aggregateVerify(
            sig_groupcheck,
            buffer,
            msgs[0..],
            dst,
            pks[0..],
            false,
        );
    }

    pub fn fromAggregate(agg_sig: *const AggregateSignature) Self {
        var sig = Self{};
        c.blst_p2_to_affine(&sig.point, &agg_sig.point);
        return sig;
    }

    pub fn compress(self: *const Self) [min_pk.SIG_COMPRESS_SIZE]u8 {
        var sig_comp = [_]u8{0} ** min_pk.SIG_COMPRESS_SIZE;
        c.blst_p2_affine_compress(&sig_comp, &self.point);
        return sig_comp;
    }

    pub fn serialize(self: *const Self) [min_pk.SIG_SERIALIZE_SIZE]u8 {
        var sig_out = [_]u8{0} ** min_pk.SIG_SERIALIZE_SIZE;
        c.blst_p2_affine_serialize(&sig_out, &self.point);
        return sig_out;
    }

    pub fn uncompress(sig_comp: []const u8) BlstError!Self {
        if (sig_comp.len == min_pk.SIG_COMPRESS_SIZE and (sig_comp[0] & 0x80) != 0) {
            var sig = Self{};
            try check(c.blst_p2_uncompress(&sig.point, &sig_comp[0]));
            return sig;
        }

        return BlstError.BadEncoding;
    }

    pub fn deserialize(sig_in: []const u8) BlstError!Self {
        if ((sig_in.len == min_pk.SIG_SERIALIZE_SIZE and (sig_in[0] & 0x80) == 0) or
            (sig_in.len == min_pk.SIG_COMPRESS_SIZE and (sig_in[0] & 0x80) != 0))
        {
            var sig = Self{};
            try check(c.blst_p2_deserialize(&sig.point, &sig_in[0]));
            return sig;
        }

        return BlstError.BadEncoding;
    }

    pub fn subgroupCheck(self: *const Self) bool {
        return c.blst_p2_affine_in_g2(&self.point);
    }

    pub fn isEqual(self: *const Self, other: *const Self) bool {
        return c.blst_p2_affine_is_equal(&self.point, &other.point);
    }
};
