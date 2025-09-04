const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const Variant = @import("variant.zig").Variant;
const PublicKey = @import("public_key.zig").PublicKey;
const AggregatePublicKey = @import("aggregate_public_key.zig").AggregatePublicKey;
const AggregateSignature = @import("aggregate_signature.zig").AggregateSignature;
const Pairing = @import("pairing.zig").Pairing;
const pairing_size = @import("pairing.zig").pairing_size;

pub fn Signature(comptime variant: Variant) type {
    const V = variant.Types();

    return extern struct {
        point: V.Sig = V.Sig{},

        const Self = @This();

        pub const compress_size = V.sig_compress_size;
        pub const serialize_size = V.sig_serialize_size;

        // sig_infcheck, check for infinity, is a way to avoid going
        // into resource-consuming verification. Passing 'false' is
        // always cryptographically safe, but application might want
        // to guard against obviously bogus individual[!] signatures.
        pub fn validate(self: *const Self, sig_infcheck: bool) BlstError!void {
            if (sig_infcheck and V.sig_is_inf(&self.point)) {
                return BlstError.PK_IS_INFINITY;
            }

            if (!V.sig_in_group(&self.point)) {
                return BlstError.POINT_NOT_IN_GROUP;
            }
        }

        pub fn sigValidate(sig_in: []const u8, sig_infcheck: bool) BlstError!Self {
            var sig = try Self.deserialize(sig_in);
            try sig.validate(sig_infcheck);
            return sig;
        }

        // same to non-std verify in Rust
        pub fn verify(
            self: *const Self,
            sig_groupcheck: bool,
            msg: []const u8,
            dst: []const u8,
            aug: ?[]const u8,
            pk: *const PublicKey(variant),
            pk_validate: bool,
        ) BlstError!void {
            if (sig_groupcheck) {
                try self.validate(false);
            }

            if (pk_validate) {
                try pk.validate();
            }

            if (msg.len == 0 or dst.len == 0) {
                return BlstError.BAD_ENCODING;
            }

            try check(V.sig_verify(
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
        }

        pub fn aggregateVerify(
            self: *const Self,
            sig_groupcheck: bool,
            buffer: *[pairing_size]u8,
            msgs: []const [32]u8,
            dst: []const u8,
            pks: []const *PublicKey(variant),
            pks_validate: bool,
        ) BlstError!void {
            const n_elems = pks.len;
            if (n_elems == 0 or msgs.len != n_elems) {
                return BlstError.VERIFY_FAIL;
            }

            var pairing = try Pairing(variant).init(buffer, true, dst);

            try pairing.aggregate(pks[0], pks_validate, self, sig_groupcheck, msgs[0], null);
            for (1..n_elems) |i| {
                const pk = pks[i];
                const msg = msgs[i];

                try pairing.aggregate(pk, pks_validate, null, sig_groupcheck, msg, null);
            }

            pairing.commit();

            try pairing.finalVerify(null);
        }

        /// same to fast_aggregate_verify in Rust with extra `pool` parameter
        pub fn fastAggregateVerify(
            self: *const Self,
            sig_groupcheck: bool,
            buffer: *[pairing_size]u8,
            msg: *const [32]u8,
            dst: []const u8,
            pks: []*const PublicKey(variant),
        ) BlstError!void {
            const agg_pk = AggregatePublicKey(variant).aggregate(pks, false);
            const pk = agg_pk.toPublicKey();

            try self.aggregateVerify(
                buffer,
                sig_groupcheck,
                &[_][32]u8{msg},
                dst,
                [_]*const PublicKey(variant){&pk},
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
            var pks = [_]*const PublicKey(variant){pk};
            try self.aggregateVerify(
                sig_groupcheck,
                buffer,
                msgs[0..],
                dst,
                pks[0..],
                false,
            );
        }

        /// https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
        pub fn verifyMultipleAggregateSignatures(
            pairing_buf: *[pairing_size]u8,
            msgs: [][]const u8,
            dst: []const u8,
            pks: []const *PublicKey,
            pks_validate: bool,
            sigs: []const *Self,
            sigs_groupcheck: bool,
            rands: [][]const u8,
            rand_bits: usize,
        ) BlstError!void {
            const n_elems = pks.len;
            if (n_elems == 0 or msgs.len != n_elems or sigs.len != n_elems or rands.len != n_elems) {
                return BlstError.VERIFY_FAIL;
            }

            var pairing = try Pairing(variant).init(
                pairing_buf,
                true,
                dst,
            );

            for (0..n_elems) |i| {
                const msg = msgs[i];
                const pk = pks[i];
                const sig = sigs[i];
                const rand = rands[i];

                try pairing.mulAndAggregate(
                    pk,
                    pks_validate,
                    sig.point,
                    sigs_groupcheck,
                    rand,
                    rand_bits,
                    msg,
                    null,
                );
            }

            pairing.commit();

            if (!pairing.finalVerify(null)) {
                return BlstError.VERIFY_FAIL;
            }
        }

        pub fn fromAggregate(agg_sig: *const AggregateSignature(variant)) Self {
            var sig = Self{};
            V.agg_sig_to_sig(&sig.point, &agg_sig.point);
            return sig;
        }

        pub fn compress(self: *const Self) [V.sig_compress_size]u8 {
            var sig_comp = [_]u8{0} ** V.sig_compress_size;
            V.sig_compress(&sig_comp, &self.point);
            return sig_comp;
        }

        pub fn serialize(self: *const Self) [V.sig_serialize_size]u8 {
            var sig_out = [_]u8{0} ** V.sig_serialize_size;
            V.sig_serialize(&sig_out, &self.point);
            return sig_out;
        }

        pub fn uncompress(sig_comp: []const u8) BlstError!Self {
            const len = sig_comp.len;
            if (len == V.sig_compress_size and (sig_comp[0] & 0x80) != 0) {
                var sig = Self{};
                try check(
                    V.sig_uncompress(&sig.point, &sig_comp[0]),
                );
                return sig;
            }

            return BlstError.BAD_ENCODING;
        }

        pub fn deserialize(sig_in: []const u8) BlstError!Self {
            if ((sig_in.len == V.sig_serialize_size and (sig_in[0] & 0x80) == 0) or
                (sig_in.len == V.sig_compress_size and (sig_in[0] & 0x80) != 0))
            {
                var sig = Self{};
                try check(
                    V.sig_deserialize(&sig.point, &sig_in[0]),
                );
                return sig;
            }

            return BlstError.BAD_ENCODING;
        }

        pub fn subgroupCheck(self: *const Self) bool {
            return V.sig_in_group(&self.point);
        }

        pub fn isEqual(self: *const Self, other: *const Self) bool {
            return V.sig_is_equal(&self.point, &other.point);
        }
    };
}
