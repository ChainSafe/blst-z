/// Number of random bytes used for verification.
const RAND_BYTES = 8;

/// Number of random bits used for verification.
const RAND_BITS = 8 * RAND_BYTES;

/// Verify multiple aggregate signatures efficiently using random coefficients.
///
/// Source: https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
///
/// Returns true if verification succeeds, false if verification fails, `BlstError` on error.
pub fn verifyMultipleAggregateSignatures(
    pairing_buf: *[pairing_size]u8,
    n_elems: usize,
    msgs: []const [32]u8,
    dst: []const u8,
    pks: []const *PublicKey,
    pks_validate: bool,
    sigs: []const *Signature,
    sigs_groupcheck: bool,
    rands: []const [32]u8,
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
            pks[i],
            pks_validate,
            sigs[i],
            sigs_groupcheck,
            &rands[i],
            RAND_BITS,
            &msgs[i],
        );
    }

    pairing.commit();

    return pairing.finalVerify(null);
}

/// BLS signature for G2 operations.
pub const Signature = extern struct {
    point: c.blst_p2_affine = c.blst_p2_affine{},

    const Self = @This();

    pub const SERIALIZE_SIZE = 192;
    pub const COMPRESS_SIZE = 96;

    /// Checks that the signature is not infinity and is in the correct subgroup.
    /// Validating prior to verification avoids resource-consuming verification process.
    /// Passing 'false' is always cryptographically safe, but application might want
    /// to guard against obviously bogus individual signatures.
    ///
    /// Returns `BlstError` if validation fails.
    pub fn validate(self: *const Self, sig_infcheck: bool) BlstError!void {
        if (sig_infcheck and c.blst_p2_affine_is_inf(&self.point)) return BlstError.PkIsInfinity;
        if (!c.blst_p2_affine_in_g2(&self.point)) return BlstError.PointNotInGroup;
    }

    /// Verify the `Signature` against a `PublicKey` and message.
    ///
    /// Returns `BlstError` if verification fails.
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

    /// Verify an `AggregateSignature` against a single message and a slice of `PublicKey`.
    ///
    /// Returns true if verification succeeds, false if verification fails, `BlstError` on error.
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
            &pks[0],
            pks_validate,
            self,
            sig_groupcheck,
            &msgs[0],
            null,
        );

        for (1..n_elems) |i| {
            try pairing.aggregate(
                &pks[i],
                pks_validate,
                null,
                sig_groupcheck,
                &msgs[i],
                null,
            );
        }

        pairing.commit();
        var gtsig = c.blst_fp12{};
        Pairing.aggregated(&gtsig, self);

        return pairing.finalVerify(&gtsig);
    }

    /// Fast verify an `AggregateSignature` against a single message and a slice of `PublicKey`.
    ///
    /// Returns true if verification succeeds, false if verification fails, `BlstError` on error.
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

    /// Fast verify an `AggregateSignature` against a single message and pre-aggregated `PublicKey`.
    ///
    /// Returns `BlstError` if verification fails.
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

    /// Convert an `AggregateSignature` to a regular `Signature`.
    pub fn fromAggregate(agg_sig: *const AggregateSignature) Self {
        var sig = Self{};
        c.blst_p2_to_affine(&sig.point, &agg_sig.point);
        return sig;
    }

    /// Compress the `Signature` to bytes.
    pub fn compress(self: *const Self) [COMPRESS_SIZE]u8 {
        var sig_comp = [_]u8{0} ** COMPRESS_SIZE;
        c.blst_p2_affine_compress(&sig_comp, &self.point);
        return sig_comp;
    }

    /// Serialize the `Signature` to bytes.
    pub fn serialize(self: *const Self) [SERIALIZE_SIZE]u8 {
        var sig_out = [_]u8{0} ** SERIALIZE_SIZE;
        c.blst_p2_affine_serialize(&sig_out, &self.point);
        return sig_out;
    }

    /// Decompress a `Signature` from compressed bytes.
    ///
    /// Returns `Signature` on success, `BlstError` on failure.
    pub fn uncompress(sig_comp: []const u8) BlstError!Self {
        if (sig_comp.len == COMPRESS_SIZE and (sig_comp[0] & 0x80) != 0) {
            var sig = Self{};
            try check(c.blst_p2_uncompress(&sig.point, &sig_comp[0]));
            return sig;
        }

        return BlstError.BadEncoding;
    }

    /// Deserialize a `Signature` from bytes.
    ///
    /// Returns `Signature` on success, `BlstError` on failure.
    pub fn deserialize(sig_in: []const u8) BlstError!Self {
        if ((sig_in.len == SERIALIZE_SIZE and (sig_in[0] & 0x80) == 0) or
            (sig_in.len == COMPRESS_SIZE and (sig_in[0] & 0x80) != 0))
        {
            var sig = Self{};
            try check(c.blst_p2_deserialize(&sig.point, &sig_in[0]));
            return sig;
        }

        return BlstError.BadEncoding;
    }

    /// Check if the `Signature` is in the correct subgroup.
    pub fn subgroupCheck(self: *const Self) bool {
        return c.blst_p2_affine_in_g2(&self.point);
    }

    /// Check if two signatures are equal.
    pub fn isEqual(self: *const Self, other: *const Self) bool {
        return c.blst_p2_affine_is_equal(&self.point, &other.point);
    }
};

const std = @import("std");
const c = @cImport({
    @cInclude("blst.h");
});
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const PublicKey = @import("public_key.zig").PublicKey;
const AggregatePublicKey = @import("AggregatePublicKey.zig");
const AggregateSignature = @import("AggregateSignature.zig");
const Pairing = @import("pairing.zig").Pairing;
const pairing_size = @import("pairing.zig").pairing_size;
