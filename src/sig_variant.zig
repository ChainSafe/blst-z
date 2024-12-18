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

// pub fn createSigVariant(comptime pk_aff_type: type, default_fn: anytype, pk_is_inf_fn: anytype, pk_in_group_fn: anytype, pk_to_aff_fn: anytype, pk_comp_fn: anytype, pk_ser_fn: anytype, pk_uncomp_fn: anytype, pk_deser_fn: anytype) type {

pub fn createSigVariant(
    default_pubkey_fn: anytype,
    default_agg_pubkey_fn: anytype,
    default_sig_fn: anytype,
    default_agg_sig_fn: anytype,
    comptime pk_type: type,
    comptime pk_aff_type: type,
    comptime sig_type: type,
    comptime sig_aff_type: type,
    sk_to_pk_fn: anytype,
    hash_or_encode: bool,
    hash_or_encode_to_fn: anytype,
    sign_fn: anytype,
    // pk_eq_fn: anytype,
    // sig_eq_fn: anytype,
    verify_fn: anytype,
    pk_in_group_fn: anytype,
    pk_to_aff_fn: anytype,
    pk_from_aff_fn: anytype,
    pk_ser_fn: anytype,
    pk_comp_fn: anytype,
    pk_deser_fn: anytype,
    pk_uncomp_fn: anytype,
    pk_comp_size: usize,
    pk_ser_size: usize,
    sig_in_group_fn: anytype,
    sig_to_aff_fn: anytype,
    sig_from_aff_fn: anytype,
    sig_ser_fn: anytype,
    sig_comp_fn: anytype,
    sig_deser_fn: anytype,
    sig_uncomp_fn: anytype,
    sig_comp_size: usize,
    sig_ser_size: usize,
    pk_add_or_dbl_fn: anytype,
    pk_add_or_dbl_aff_fn: anytype,
    sig_add_or_dbl_fn: anytype,
    sig_add_or_dbl_aff_fn: anytype,
    pk_is_inf_fn: anytype,
    sig_is_inf_fn: anytype,
    sig_aggr_in_group_fn: anytype,
) type {
    // TODO: implement Clone, Copy, Equal
    const PublicKey = struct {
        // point: c.blst_p1_affine,
        point: pk_aff_type,

        pub fn default() @This() {
            return .{
                // .point = util.default_blst_p1_affline(),
                .point = default_pubkey_fn(),
            };
        }

        // Core operations

        // key_validate
        pub fn validate(self: *const @This()) BLST_ERROR!void {
            // if (c.blst_p1_affine_is_inf(&self.point)) {
            if (pk_is_inf_fn(&self.point)) {
                return BLST_ERROR.PK_IS_INFINITY;
            }

            // if (c.blst_p1_affine_in_g1(&self.point) == false) {
            if (pk_in_group_fn(&self.point) == false) {
                return BLST_ERROR.POINT_NOT_IN_GROUP;
            }
        }

        pub fn key_validate(key: []const u8) BLST_ERROR!void {
            const pk = try @This().fromBytes(key);
            try pk.validate();
        }

        pub fn fromAggregate(comptime AggregatePublicKey: type, agg_pk: *const AggregatePublicKey) @This() {
            var pk_aff = @This().default();
            // c.blst_p1_to_affine(&pk_aff.point, &agg_pk.point);
            pk_to_aff_fn(&pk_aff.point, &agg_pk.point);
            return pk_aff;
        }

        // Serdes

        // pub fn compress(self: *const @This()) [48]u8 {
        pub fn compress(self: *const @This()) [pk_comp_size]u8 {
            var pk_comp = [_]u8{0} ** 48;
            // c.blst_p1_affine_compress(&pk_comp[0], &self.point);
            pk_comp_fn(&pk_comp[0], &self.point);
            return pk_comp;
        }

        // pub fn serialize(self: *const @This()) [96]u8 {
        pub fn serialize(self: *const @This()) [pk_ser_size]u8 {
            var pk_out = [_]u8{0} ** pk_ser_size;
            // c.blst_p1_affine_serialize(&pk_out[0], &self.point);
            pk_ser_fn(&pk_out[0], &self.point);
            return pk_out;
        }

        pub fn uncompress(pk_comp: []const u8) BLST_ERROR!@This() {
            if (pk_comp.len == 48 and (pk_comp[0] & 0x80) != 0) {
                var pk = @This().default();
                // const res = c.blst_p1_uncompress(&pk.point, &pk_comp[0]);
                const res = pk_uncomp_fn(&pk.point, &pk_comp[0]);
                const err = toBlstError(res);
                if (err != null) {
                    return err.?;
                }
                return pk;
            }

            return BLST_ERROR.BAD_ENCODING;
        }

        pub fn deserialize(pk_in: []const u8) BLST_ERROR!@This() {
            if ((pk_in.len == 96 and (pk_in[0] & 0x80) == 0) or
                (pk_in.len == 48 and (pk_in[0] & 0x80) != 0))
            {
                var pk = @This().default();
                // const res = c.blst_p1_deserialize(&pk.point, &pk_in[0]);
                const res = pk_deser_fn(&pk.point, &pk_in[0]);
                const err = toBlstError(res);
                if (err != null) {
                    return err.?;
                }
                return pk;
            }

            return BLST_ERROR.BAD_ENCODING;
        }

        pub fn fromBytes(pk_in: []const u8) BLST_ERROR!@This() {
            return @This().deserialize(pk_in);
        }

        pub fn toBytes(self: *const @This()) [48]u8 {
            return self.compress();
        }

        // TODO: Eq, PartialEq, Serialize, Deserialize?
    };

    const AggregatePublicKey = struct {
        // point: c.blst_p1,
        point: pk_type,

        pub fn default() @This() {
            return .{
                // .point = util.default_blst_p1(),
                .point = default_agg_pubkey_fn(),
            };
        }

        pub fn fromPublicKey(pk: *const PublicKey) @This() {
            var agg_pk = @This().default();
            // c.blst_p1_from_affine(&agg_pk.point, &pk.point);
            pk_from_aff_fn(&agg_pk.point, &pk.point);

            return agg_pk;
        }

        pub fn toPublicKey(self: *const @This()) PublicKey {
            var pk = PublicKey.default();
            // c.blst_p1_to_affine(&pk.point, &self.point);
            pk_to_aff_fn(&pk.point, &self.point);
            return pk;
        }

        // Aggregate
        pub fn aggregate(pks: []const *PublicKey, pks_validate: bool) BLST_ERROR!@This() {
            if (pks.len == 0) {
                return BLST_ERROR.AGGR_TYPE_MISMATCH;
            }
            if (pks_validate) {
                try pks[0].validate();
            }

            var agg_pk = @This().fromPublicKey(pks[0]);
            for (pks[1..]) |pk| {
                if (pks_validate) {
                    try pk.validate();
                }

                // c.blst_p1_add_or_double_affine(&agg_pk.point, &agg_pk.point, &pk.point);
                pk_add_or_dbl_aff_fn(&agg_pk.point, &agg_pk.point, &pk.point);
            }

            return agg_pk;
        }

        pub fn aggregateSerialized(pks: [][]const u8, pks_validate: bool) BLST_ERROR!@This() {
            // TODO - threading
            if (pks.len == 0) {
                return BLST_ERROR.AGGR_TYPE_MISMATCH;
            }
            var pk = if (pks_validate) PublicKey.key_validate(pks[0]) else PublicKey.fromBytes(pks[0]);
            var agg_pk = @This().fromPublicKey(&pk);
            for (pks[1..]) |s| {
                pk = if (pks_validate) PublicKey.key_validate(s) else PublicKey.fromBytes(s);
                // c.blst_p1_add_or_double_affine(&agg_pk.point, &agg_pk.point, &pk.point);
                pk_add_or_dbl_aff_fn(&agg_pk.point, &agg_pk.point, &pk.point);
            }

            return agg_pk;
        }

        pub fn addAggregate(self: *@This(), agg_pk: *const @This()) BLST_ERROR!void {
            // c.blst_p1_add_or_double_affine(&self.point, &self.point, &agg_pk.point);
            pk_add_or_dbl_fn(&self.point, &self.point, &agg_pk.point);
        }

        pub fn addPublicKey(self: *@This(), pk: *const PublicKey, pk_validate: bool) BLST_ERROR!void {
            if (pk_validate) {
                try pk.validate();
            }

            // c.blst_p1_add_or_double_affine(&self.point, &self.point, &pk.point);
            pk_add_or_dbl_aff_fn(&self.point, &self.point, &pk.point);
        }
    };

    const Signature = struct {
        // point: c.blst_p2_affine,
        point: sig_aff_type,

        pub fn default() @This() {
            return .{
                // .point = util.default_blst_p2_affine(),
                .point = default_sig_fn(),
            };
        }

        // sig_infcheck, check for infinity, is a way to avoid going
        // into resource-consuming verification. Passing 'false' is
        // always cryptographically safe, but application might want
        // to guard against obviously bogus individual[!] signatures.
        pub fn validate(self: *const @This(), sig_infcheck: bool) BLST_ERROR!void {
            // if (sig_infcheck and c.blst_p2_affine_is_inf(&self.point)) {
            if (sig_infcheck and sig_is_inf_fn(&self.point)) {
                return BLST_ERROR.PK_IS_INFINITY;
            }

            // if (!c.blst_p2_affine_in_g2(&self.point)) {
            if (!sig_in_group_fn(&self.point)) {
                return BLST_ERROR.POINT_NOT_IN_GROUP;
            }
        }

        pub fn sigValidate(sig_in: []const u8, sig_infcheck: bool) BLST_ERROR!@This() {
            var sig = @This().fromBytes(sig_in);
            sig.validate(sig_infcheck);
            return sig;
        }

        // same to non-std verify in Rust
        pub fn verify(self: *const @This(), sig_groupcheck: bool, msg: []const u8, dst: []const u8, aug: ?[]const u8, pk: *const PublicKey, pk_validate: bool) BLST_ERROR!void {
            if (sig_groupcheck) {
                try self.validate(false);
            }

            if (pk_validate) {
                try pk.validate();
            }
            const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
            const aug_len = if (aug != null) aug.?.len else 0;

            // const res = c.blst_core_verify_pk_in_g1(&pk.point, &self.point, true, &msg[0], msg.len, &dst[0], dst.len, aug_ptr, aug_len);
            const res = verify_fn(&pk.point, &self.point, true, &msg[0], msg.len, &dst[0], dst.len, aug_ptr, aug_len);
            const err = toBlstError(res);
            if (err != null) {
                return err.?;
            }
        }

        // TODO: consider thread pool implementation

        /// same to non-std aggregate_verify in Rust, with extra `pairing_buffer` parameter
        pub fn aggregateVerify(self: *const @This(), sig_groupcheck: bool, msgs: [][]const u8, dst: []const u8, pks: []const *PublicKey, pks_validate: bool, pairing_buffer: []u8) BLST_ERROR!void {
            const n_elems = pks.len;
            if (n_elems == 0 or msgs.len != n_elems) {
                return BLST_ERROR.VERIFY_FAIL;
            }

            // const pairing_res = Pairing.new(pairing_buffer, true, dst);
            const pairing_res = Pairing.new(pairing_buffer, hash_or_encode, dst);
            var pairing = if (pairing_res) |pairing| pairing else |err| switch (err) {
                else => return BLST_ERROR.FAILED_PAIRING,
            };

            try pairing.aggregateG1(&pks[0].point, pks_validate, &self.point, sig_groupcheck, msgs[0], null);

            for (1..n_elems) |i| {
                try pairing.aggregateG1(&pks[i].point, pks_validate, null, false, msgs[i], null);
            }

            pairing.commit();

            if (!pairing.finalVerify(null)) {
                return BLST_ERROR.VERIFY_FAIL;
            }
        }

        /// same to fast_aggregate_verify in Rust with extra `pairing_buffer` parameter
        pub fn fastAggregateVerify(self: *const @This(), sig_groupcheck: bool, msg: []const u8, dst: []const u8, pks: []const *PublicKey, pairing_buffer: []u8) BLST_ERROR!void {
            const agg_pk = try AggregatePublicKey.aggregate(pks, false);
            var pk = agg_pk.toPublicKey();
            var msg_arr = [_][]const u8{msg};
            const msgs: [][]const u8 = msg_arr[0..];
            const pk_arr = [_]*PublicKey{&pk};
            try self.aggregateVerify(sig_groupcheck, msgs[0..], dst, pk_arr[0..], false, pairing_buffer);
        }

        /// same to fast_aggregate_verify_pre_aggregated in Rust with extra `pairing_buffer` parameter
        /// TODO: make pk as *const PublicKey, then all other functions should make pks as []const *const PublicKey
        pub fn fastAggregateVerifyPreAggregated(self: *const @This(), sig_groupcheck: bool, msg: []const u8, dst: []const u8, pk: *PublicKey, pairing_buffer: []u8) BLST_ERROR!void {
            var msgs = [_][]const u8{msg};
            var pks = [_]*PublicKey{pk};
            try self.aggregateVerify(sig_groupcheck, msgs[0..], dst, pks[0..], false, pairing_buffer);
        }

        /// https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407
        ///  similar to non-std verify_multiple_aggregate_signatures in Rust with:
        /// - extra `pairing_buffer` parameter
        /// - `rands` parameter type changed to `[][]const u8` instead of []blst_scalar because mulAndAggregateG1() accepts []const u8 anyway
        /// rand_bits is always 64 in all tests
        pub fn verifyMultipleAggregateSignatures(msgs: [][]const u8, dst: []const u8, pks: []const *PublicKey, pks_validate: bool, sigs: []const *@This(), sigs_groupcheck: bool, rands: [][]const u8, rand_bits: usize, pairing_buffer: []u8) BLST_ERROR!void {
            const n_elems = pks.len;
            if (n_elems == 0 or msgs.len != n_elems or sigs.len != n_elems or rands.len != n_elems) {
                return BLST_ERROR.VERIFY_FAIL;
            }

            // TODO - check msg uniqueness?

            // const pairing_res = Pairing.new(pairing_buffer, true, dst);
            const pairing_res = Pairing.new(pairing_buffer, hash_or_encode, dst);
            var pairing = if (pairing_res) |pairing| pairing else |err| switch (err) {
                else => return BLST_ERROR.FAILED_PAIRING,
            };

            for (0..n_elems) |i| {
                try pairing.mulAndAggregateG1(&pks[i].point, pks_validate, &sigs[i].point, sigs_groupcheck, rands[i], rand_bits, msgs[i], null);
            }

            pairing.commit();

            if (!pairing.finalVerify(null)) {
                return BLST_ERROR.VERIFY_FAIL;
            }
        }

        pub fn fromAggregate(comptime AggregateSignature: type, agg_sig: *const AggregateSignature) @This() {
            var sig_aff = @This().default();
            // c.blst_p2_to_affine(&sig_aff.point, &agg_sig.point);
            sig_to_aff_fn(&sig_aff.point, &agg_sig.point);
            return sig_aff;
        }

        // pub fn compress(self: *const @This()) [96]u8 {
        pub fn compress(self: *const @This()) [sig_comp_size]u8 {
            // var sig_comp = [_]u8{0} ** 96;
            var sig_comp = [_]u8{0} ** sig_comp_size;
            // c.blst_p2_affine_compress(&sig_comp[0], &self.point);
            sig_comp_fn(&sig_comp[0], &self.point);
            return sig_comp;
        }

        // pub fn serialize(self: *const @This()) [192]u8 {
        pub fn serialize(self: *const @This()) [sig_ser_size]u8 {
            // var sig_out = [_]u8{0} ** 192;
            var sig_out = [_]u8{0} ** sig_ser_size;
            // c.blst_p2_affine_serialize(&sig_out[0], &self.point);
            sig_ser_fn(&sig_out[0], &self.point);
            return sig_out;
        }

        pub fn uncompress(sig_comp: []const u8) BLST_ERROR!@This() {
            if (sig_comp.len == 96 and (sig_comp[0] & 0x80) != 0) {
                var sig = @This().default();
                // const res = c.blst_p2_uncompress(&sig.point, &sig_comp[0]);
                const res = sig_uncomp_fn(&sig.point, &sig_comp[0]);
                if (res != null) {
                    return res;
                }
                return sig;
            }

            return BLST_ERROR.BAD_ENCODING;
        }

        pub fn deserialize(sig_in: []const u8) BLST_ERROR!@This() {
            if ((sig_in.len == 192 and (sig_in[0] & 0x80) == 0) or (sig_in.len == 96 and sig_in[0] & 0x80) != 0) {
                var sig = @This().default();
                // const res = c.blst_p2_deserialize(&sig.point, &sig_in[0]);
                const res = sig_deser_fn(&sig.point, &sig_in[0]);
                const err = toBlstError(res);
                if (err != null) {
                    return err.?;
                }
                return sig;
            }

            return BLST_ERROR.BAD_ENCODING;
        }

        pub fn fromBytes(sig_in: []const u8) BLST_ERROR!@This() {
            return @This().deserialize(sig_in);
        }

        pub fn toBytes(self: *const @This()) [96]u8 {
            return self.compress();
        }

        pub fn subgroupCheck(self: *const @This()) bool {
            // return c.blst_p2_affine_in_g2(&self.point);
            return sig_in_group_fn(&self.point);
        }

        // TODO: Eq PartialEq, Serialize, Deserialize?
    };

    const AggregateSignature = struct {
        // point: c.blst_p2,
        point: sig_type,

        pub fn default() @This() {
            return .{
                // .point = util.default_blst_p2(),
                .point = default_agg_sig_fn(),
            };
        }

        pub fn validate(self: *const @This()) BLST_ERROR!void {
            // const res = c.blst_p2_in_g2(&self.point);
            const res = sig_aggr_in_group_fn(&self.point);
            const err = toBlstError(res);
            if (err != null) {
                return err.?;
            }
        }

        pub fn fromSignature(sig: *const Signature) @This() {
            var agg_sig = @This().default();
            // c.blst_p2_from_affine(&agg_sig.point, &sig.point);
            sig_from_aff_fn(&agg_sig.point, &sig.point);
            return agg_sig;
        }

        pub fn toSignature(self: *const @This()) Signature {
            var sig = Signature.default();
            // c.blst_p2_to_affine(&sig.point, &self.point);
            sig_to_aff_fn(&sig.point, &self.point);
            return sig;
        }

        // Aggregate
        pub fn aggregate(sigs: []*const Signature, sigs_groupcheck: bool) BLST_ERROR!@This() {
            if (sigs.len == 0) {
                return BLST_ERROR.AGGR_TYPE_MISMATCH;
            }
            if (sigs_groupcheck) {
                // We can't actually judge if input is individual or
                // aggregated signature, so we can't enforce infinity
                // check.
                try sigs[0].validate(false);
            }

            var agg_sig = @This().fromSignature(sigs[0]);
            for (sigs[1..]) |s| {
                if (sigs_groupcheck) {
                    try s.validate(false);
                }
                // c.blst_p2_add_or_double_affine(&agg_sig.point, &agg_sig.point, &s.point);
                sig_add_or_dbl_aff_fn(&agg_sig.point, &agg_sig.point, &s.point);
            }

            return agg_sig;
        }

        // TODO: aggregate_with_randomness

        pub fn aggregateSerialized(sigs: [][]const u8, sigs_groupcheck: bool) BLST_ERROR!@This() {
            // TODO - threading
            if (sigs.len() == 0) {
                return BLST_ERROR.AGGR_TYPE_MISMATCH;
            }

            var sig = if (sigs_groupcheck) Signature.sigValidate(sigs[0], false) else Signature.fromBytes(sigs[0]);

            var agg_sig = @This().fromSignature(&sig);
            for (sigs[1..]) |s| {
                sig = if (sigs_groupcheck) Signature.sigValidate(s, false) else Signature.fromBytes(s);
                // c.blst_p2_add_or_double_affine(&agg_sig.point, &agg_sig.point, &sig.point);
                sig_add_or_dbl_aff_fn(&agg_sig.point, &agg_sig.point, &sig.point);
            }
            return agg_sig;
        }

        pub fn addAggregate(self: *@This(), agg_sig: *const @This()) void {
            // c.blst_p2_add_or_double(&self.point, &self.point, &agg_sig.point);
            sig_add_or_dbl_fn(&self.point, &self.point, &agg_sig.point);
        }

        pub fn addSignature(self: *@This(), sig: *const Signature, sig_groupcheck: bool) BLST_ERROR!void {
            if (sig_groupcheck) {
                try sig.validate(false);
            }
            // c.blst_p2_add_or_double_affine(&self.point, &self.point, &sig.point);
            sig_add_or_dbl_aff_fn(&self.point, &self.point, &sig.point);
        }

        pub fn subgroupCheck(self: *const @This()) bool {
            // return c.blst_p2_in_g2(&self.point);
            return sig_aggr_in_group_fn(&self.point);
        }
    };

    const SecretKey = struct {
        value: c.blst_scalar,

        pub fn default() @This() {
            return .{
                .value = util.default_blst_scalar(),
            };
        }

        pub fn keyGen(ikm: []const u8, key_info: ?[]const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            const key_info_ptr = if (key_info != null) &key_info.?[0] else null;
            const key_info_len = if (key_info != null) key_info.?.len else 0;

            c.blst_keygen(&sk.value, &ikm[0], ikm.len, key_info_ptr, key_info_len);
            return sk;
        }

        pub fn keyGenV3(ikm: []const u8, key_info: ?[]const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            const key_info_ptr = if (key_info != null) &key_info.?[0] else null;
            const key_info_len = if (key_info != null) key_info.?.len else 0;

            c.blst_keygen_v3(&sk.value, &ikm[0], ikm.len, key_info_ptr, key_info_len);
            return sk;
        }

        pub fn keyGenV45(ikm: []const u8, salt: []const u8, info: ?[]const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            const info_ptr = if (info != null and info.?.len > 0) &info.?[0] else null;
            const info_len = if (info != null) info.?.len else 0;

            c.blst_keygen_v4_5(&sk.value, &ikm[0], ikm.len, &salt[0], salt.len, info_ptr, info_len);
            return sk;
        }

        pub fn keyGenV5(ikm: []const u8, salt: []const u8, info: ?[]const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            const info_ptr = if (info != null and info.?.len > 0) &info.?[0] else null;
            const info_len = if (info != null) info.?.len else 0;

            c.blst_keygen_v5(&sk.value, &ikm[0], ikm.len, &salt[0], salt.len, info_ptr, info_len);
            return sk;
        }

        pub fn deriveMasterEip2333(ikm: []const u8) BLST_ERROR!@This() {
            if (ikm.len < 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            var sk = @This().default();
            c.blst_derive_master_eip2333(&sk.value, &ikm[0], ikm.len);
            return sk;
        }

        pub fn deriveChildEip2333(self: *const @This(), child_index: u32) BLST_ERROR!@This() {
            var sk = @This().default();
            c.blst_derive_child_eip2333(&sk.value, &self.value, child_index);
            return sk;
        }

        pub fn skToPk(self: *const @This()) PublicKey {
            var pk_aff = PublicKey.default();
            sk_to_pk_fn(null, &pk_aff.point, &self.value);
            return pk_aff;
        }

        // Sign
        pub fn sign(self: *const @This(), msg: []const u8, dst: []const u8, aug: ?[]const u8) Signature {
            // TODO - would the user like the serialized/compressed sig as well?
            var q = util.default_blst_p2();
            var sig_aff = Signature.default();
            const aug_ptr = if (aug != null and aug.?.len > 0) &aug.?[0] else null;
            const aug_len = if (aug != null) aug.?.len else 0;
            hash_or_encode_to_fn(&q, &msg[0], msg.len, &dst[0], dst.len, aug_ptr, aug_len);
            sign_fn(null, &sig_aff.point, &q, &self.value);
            return sig_aff;
        }

        // TODO - formally speaking application is entitled to have
        // ultimate control over secret key storage, which means that
        // corresponding serialization/deserialization subroutines
        // should accept reference to where to store the result, as
        // opposite to returning one.

        // serialize
        pub fn serialize(self: *const @This()) [32]u8 {
            var sk_out = [_]u8{0} ** 32;
            c.blst_bendian_from_scalar(&sk_out[0], &self.value);
            return sk_out;
        }

        // deserialize
        pub fn deserialize(sk_in: []const u8) BLST_ERROR!@This() {
            var sk = @This().default();
            if (sk_in.len != 32) {
                return BLST_ERROR.BAD_ENCODING;
            }

            c.blst_scalar_from_bendian(&sk.value, &sk_in[0]);
            if (!c.blst_sk_check(&sk.value)) {
                return BLST_ERROR.BAD_ENCODING;
            }

            return sk;
        }

        pub fn toBytes(self: *const @This()) [32]u8 {
            return self.serialize();
        }

        pub fn fromBytes(sk_in: []const u8) BLST_ERROR!@This() {
            return @This().deserialize(sk_in);
        }
    };

    return struct {
        pub fn createSecretKey() type {
            return SecretKey;
        }

        pub fn createPublicKey() type {
            return PublicKey;
        }

        pub fn createAggregatePublicKey() type {
            return AggregatePublicKey;
        }

        pub fn createSignature() type {
            return Signature;
        }

        pub fn createAggregateSignature() type {
            return AggregateSignature;
        }

        pub fn pubkeyFromAggregate(agg_pk: *const AggregatePublicKey) PublicKey {
            var pk_aff = PublicKey.default();
            // c.blst_p1_to_affine(&pk_aff.point, &agg_pk.point);
            pk_to_aff_fn(&pk_aff.point, &agg_pk.point);
            return pk_aff;
        }

        /// testing methods for this lib, should not export to consumers
        pub fn testSignNVerify() !void {
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

        pub fn testAggregate() !void {
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

        pub fn testMultipleAggSigs() !void {
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

        fn getRandomKey(rng: *Xoshiro256) SecretKey {
            var value: [32]u8 = [_]u8{0} ** 32;
            rng.random().bytes(value[0..]);
            const sk = SecretKey.keyGen(value[0..], null) catch {
                @panic("SecretKey.keyGen() failed\n");
            };
            return sk;
        }
    };
}
