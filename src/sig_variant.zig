const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const Xoshiro256 = std.rand.Xoshiro256;
const P = @import("./pairing.zig").Pairing;
const PairingError = @import("./pairing.zig").PairingError;

const c = @cImport({
    @cInclude("blst.h");
});

const util = @import("util.zig");
const BLST_ERROR = util.BLST_ERROR;
const toBlstError = util.toBlstError;

/// generic implementation for both min_pk and min_sig
/// this is equivalent to Rust binding in blst/bindings/rust/src/lib.rs
pub fn createSigVariant(
    // Zig specific default functions
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
    pk_eq_fn: anytype,
    sig_eq_fn: anytype,
    // 2 new zig specific eq functions
    agg_pk_eq_fn: anytype,
    agg_sig_eq_fn: anytype,
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
    // Zig specific multi_points
    pk_add_fn: anytype,
    pk_multi_scalar_mult_fn: anytype,
    pk_scratch_size_of_fn: anytype,
    pk_mult_fn: anytype,
    pk_generator_fn: anytype,
    pk_to_affines_fn: anytype,
    sig_add_fn: anytype,
    sig_multi_scalar_mult_fn: anytype,
    sig_scratch_size_of_fn: anytype,
    sig_mult_fn: anytype,
    sig_generator_fn: anytype,
    sig_to_affines_fn: anytype,
) type {
    // TODO: implement MultiPoint
    const Pairing = struct {
        p: P,
        pub fn new(buffer: []u8, hoe: bool, dst: []const u8) PairingError!@This() {
            const p = try P.new(buffer, hoe, dst);
            return .{ .p = p };
        }

        pub fn sizeOf() usize {
            return P.sizeOf();
        }

        pub fn aggregate(self: *@This(), pk: *const pk_aff_type, pk_validate: bool, sig: ?*const sig_aff_type, sig_groupcheck: bool, msg: []const u8, aug: ?[]u8) BLST_ERROR!void {
            if (pk_comp_size == 48) {
                // min_pk
                return self.p.aggregateG1(pk, pk_validate, sig, sig_groupcheck, msg, aug);
            } else {
                // min_sig
                return self.p.aggregateG2(pk, pk_validate, sig, sig_groupcheck, msg, aug);
            }
        }

        pub fn mulAndAggregate(self: *@This(), pk: *const pk_aff_type, pk_validate: bool, sig: *const sig_aff_type, sig_groupcheck: bool, scalar: []const u8, nbits: usize, msg: []const u8, aug: ?[]u8) BLST_ERROR!void {
            if (pk_comp_size == 48) {
                // min_pk
                return self.p.mulAndAggregateG1(pk, pk_validate, sig, sig_groupcheck, scalar, nbits, msg, aug);
            } else {
                // min_sig
                return self.p.mulAndAggregateG2(pk, pk_validate, sig, sig_groupcheck, scalar, nbits, msg, aug);
            }
        }

        pub fn commit(self: *@This()) void {
            self.p.commit();
        }

        pub fn finalVerify(self: *@This(), ggtsig: ?*const c.blst_fp12) bool {
            return self.p.finalVerify(ggtsig);
        }

        // add more methods here if needed
    };

    // TODO: implement Clone, Copy, Equal
    const PublicKey = struct {
        point: pk_aff_type,

        pub fn default() @This() {
            return .{
                .point = default_pubkey_fn(),
            };
        }

        // Core operations

        // key_validate
        pub fn validate(self: *const @This()) BLST_ERROR!void {
            if (pk_is_inf_fn(&self.point)) {
                return BLST_ERROR.PK_IS_INFINITY;
            }

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
            pk_to_aff_fn(&pk_aff.point, &agg_pk.point);
            return pk_aff;
        }

        // Serdes

        pub fn compress(self: *const @This()) [pk_comp_size]u8 {
            var pk_comp = [_]u8{0} ** pk_comp_size;
            pk_comp_fn(&pk_comp[0], &self.point);
            return pk_comp;
        }

        pub fn serialize(self: *const @This()) [pk_ser_size]u8 {
            var pk_out = [_]u8{0} ** pk_ser_size;
            pk_ser_fn(&pk_out[0], &self.point);
            return pk_out;
        }

        pub fn uncompress(pk_comp: []const u8) BLST_ERROR!@This() {
            if (pk_comp.len == pk_comp_size and (pk_comp[0] & 0x80) != 0) {
                var pk = @This().default();
                const res = pk_uncomp_fn(&pk.point, &pk_comp[0]);
                return toBlstError(res) orelse pk;
            }

            return BLST_ERROR.BAD_ENCODING;
        }

        pub fn deserialize(pk_in: []const u8) BLST_ERROR!@This() {
            if ((pk_in.len == pk_ser_size and (pk_in[0] & 0x80) == 0) or
                (pk_in.len == pk_comp_size and (pk_in[0] & 0x80) != 0))
            {
                var pk = @This().default();
                const res = pk_deser_fn(&pk.point, &pk_in[0]);
                return toBlstError(res) orelse pk;
            }

            return BLST_ERROR.BAD_ENCODING;
        }

        pub fn fromBytes(pk_in: []const u8) BLST_ERROR!@This() {
            return @This().deserialize(pk_in);
        }

        pub fn toBytes(self: *const @This()) [48]u8 {
            return self.compress();
        }

        pub fn isEqual(self: *const @This(), other: *const @This()) bool {
            return pk_eq_fn(&self.point, &other.point);
        }

        // TODO: PartialEq, Serialize, Deserialize?

    };

    const AggregatePublicKey = struct {
        point: pk_type,

        pub fn default() @This() {
            return .{
                .point = default_agg_pubkey_fn(),
            };
        }

        pub fn fromPublicKey(pk: *const PublicKey) @This() {
            var agg_pk = @This().default();
            pk_from_aff_fn(&agg_pk.point, &pk.point);

            return agg_pk;
        }

        pub fn toPublicKey(self: *const @This()) PublicKey {
            var pk = PublicKey.default();
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
                pk_add_or_dbl_aff_fn(&agg_pk.point, &agg_pk.point, &pk.point);
            }

            return agg_pk;
        }

        pub fn addAggregate(self: *@This(), agg_pk: *const @This()) BLST_ERROR!void {
            pk_add_or_dbl_fn(&self.point, &self.point, &agg_pk.point);
        }

        pub fn addPublicKey(self: *@This(), pk: *const PublicKey, pk_validate: bool) BLST_ERROR!void {
            if (pk_validate) {
                try pk.validate();
            }

            pk_add_or_dbl_aff_fn(&self.point, &self.point, &pk.point);
        }

        pub fn isEqual(self: *const @This(), other: *const @This()) bool {
            return agg_pk_eq_fn(&self.point, &other.point);
        }
    };

    const Signature = struct {
        point: sig_aff_type,

        pub fn default() @This() {
            return .{
                .point = default_sig_fn(),
            };
        }

        // sig_infcheck, check for infinity, is a way to avoid going
        // into resource-consuming verification. Passing 'false' is
        // always cryptographically safe, but application might want
        // to guard against obviously bogus individual[!] signatures.
        pub fn validate(self: *const @This(), sig_infcheck: bool) BLST_ERROR!void {
            if (sig_infcheck and sig_is_inf_fn(&self.point)) {
                return BLST_ERROR.PK_IS_INFINITY;
            }

            if (!sig_in_group_fn(&self.point)) {
                return BLST_ERROR.POINT_NOT_IN_GROUP;
            }
        }

        pub fn sigValidate(sig_in: []const u8, sig_infcheck: bool) BLST_ERROR!@This() {
            var sig = try @This().fromBytes(sig_in);
            try sig.validate(sig_infcheck);
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

            const res = verify_fn(&pk.point, &self.point, true, &msg[0], msg.len, &dst[0], dst.len, aug_ptr, aug_len);
            if (toBlstError(res)) |err| {
                return err;
            }
        }

        // TODO: consider thread pool implementation

        /// same to non-std aggregate_verify in Rust, with extra `pairing_buffer` parameter
        pub fn aggregateVerify(self: *const @This(), sig_groupcheck: bool, msgs: [][]const u8, dst: []const u8, pks: []const *PublicKey, pks_validate: bool, pairing_buffer: []u8) BLST_ERROR!void {
            const n_elems = pks.len;
            if (n_elems == 0 or msgs.len != n_elems) {
                return BLST_ERROR.VERIFY_FAIL;
            }

            var pairing = Pairing.new(pairing_buffer, hash_or_encode, dst) catch return BLST_ERROR.FAILED_PAIRING;

            try pairing.aggregate(&pks[0].point, pks_validate, &self.point, sig_groupcheck, msgs[0], null);

            for (1..n_elems) |i| {
                try pairing.aggregate(&pks[i].point, pks_validate, null, false, msgs[i], null);
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

            var pairing = Pairing.new(pairing_buffer, hash_or_encode, dst) catch return BLST_ERROR.FAILED_PAIRING;

            for (0..n_elems) |i| {
                try pairing.mulAndAggregate(&pks[i].point, pks_validate, &sigs[i].point, sigs_groupcheck, rands[i], rand_bits, msgs[i], null);
            }

            pairing.commit();

            if (!pairing.finalVerify(null)) {
                return BLST_ERROR.VERIFY_FAIL;
            }
        }

        pub fn fromAggregate(comptime AggregateSignature: type, agg_sig: *const AggregateSignature) @This() {
            var sig_aff = @This().default();
            sig_to_aff_fn(&sig_aff.point, &agg_sig.point);
            return sig_aff;
        }

        pub fn compress(self: *const @This()) [sig_comp_size]u8 {
            var sig_comp = [_]u8{0} ** sig_comp_size;
            sig_comp_fn(&sig_comp[0], &self.point);
            return sig_comp;
        }

        pub fn serialize(self: *const @This()) [sig_ser_size]u8 {
            var sig_out = [_]u8{0} ** sig_ser_size;
            sig_ser_fn(&sig_out[0], &self.point);
            return sig_out;
        }

        pub fn uncompress(sig_comp: []const u8) BLST_ERROR!@This() {
            if (sig_comp.len == sig_comp_size and (sig_comp[0] & 0x80) != 0) {
                var sig = @This().default();
                const res = sig_uncomp_fn(&sig.point, &sig_comp[0]);
                if (res != null) {
                    return res;
                }
                return sig;
            }

            return BLST_ERROR.BAD_ENCODING;
        }

        pub fn deserialize(sig_in: []const u8) BLST_ERROR!@This() {
            if ((sig_in.len == sig_ser_size and (sig_in[0] & 0x80) == 0) or (sig_in.len == sig_comp_size and sig_in[0] & 0x80 != 0)) {
                var sig = @This().default();
                const res = sig_deser_fn(&sig.point, &sig_in[0]);
                return toBlstError(res) orelse sig;
            }

            return BLST_ERROR.BAD_ENCODING;
        }

        pub fn fromBytes(sig_in: []const u8) BLST_ERROR!@This() {
            return @This().deserialize(sig_in);
        }

        pub fn toBytes(self: *const @This()) [sig_comp_size]u8 {
            return self.compress();
        }

        pub fn subgroupCheck(self: *const @This()) bool {
            return sig_in_group_fn(&self.point);
        }

        pub fn isEqual(self: *const @This(), other: *const @This()) bool {
            return sig_eq_fn(&self.point, &other.point);
        }
    };

    const AggregateSignature = struct {
        point: sig_type,

        pub fn default() @This() {
            return .{
                .point = default_agg_sig_fn(),
            };
        }

        pub fn validate(self: *const @This()) BLST_ERROR!void {
            const res = sig_aggr_in_group_fn(&self.point);
            if (toBlstError(res)) |err| {
                return err;
            }
        }

        pub fn fromSignature(sig: *const Signature) @This() {
            var agg_sig = @This().default();
            sig_from_aff_fn(&agg_sig.point, &sig.point);
            return agg_sig;
        }

        pub fn toSignature(self: *const @This()) Signature {
            var sig = Signature.default();
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
                sig_add_or_dbl_aff_fn(&agg_sig.point, &agg_sig.point, &sig.point);
            }
            return agg_sig;
        }

        pub fn addAggregate(self: *@This(), agg_sig: *const @This()) void {
            sig_add_or_dbl_fn(&self.point, &self.point, &agg_sig.point);
        }

        pub fn addSignature(self: *@This(), sig: *const Signature, sig_groupcheck: bool) BLST_ERROR!void {
            if (sig_groupcheck) {
                try sig.validate(false);
            }
            sig_add_or_dbl_aff_fn(&self.point, &self.point, &sig.point);
        }

        pub fn subgroupCheck(self: *const @This()) bool {
            return sig_aggr_in_group_fn(&self.point);
        }

        pub fn isEqual(self: *const @This(), other: *const @This()) bool {
            return agg_sig_eq_fn(&self.point, &other.point);
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
            var q = default_agg_sig_fn();
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

    const PkAndSerializedSig = struct {
        pk: *PublicKey,
        sig: []const u8,
    };

    // for PublicKey and AggregatePublicKey
    const pk_multi_point = @import("./multi_point.zig").createMultiPoint(
        pk_aff_type,
        pk_type,
        default_pubkey_fn,
        default_agg_pubkey_fn,
        agg_pk_eq_fn,
        pk_add_fn,
        pk_multi_scalar_mult_fn,
        pk_scratch_size_of_fn,
        pk_mult_fn,
        pk_generator_fn,
        pk_to_affines_fn,
        pk_add_or_dbl_fn,
    );

    const PkMultiPoint = pk_multi_point.getMultiPoint();

    const sig_multi_point = @import("./multi_point.zig").createMultiPoint(
        sig_aff_type,
        sig_type,
        default_sig_fn,
        default_agg_sig_fn,
        agg_sig_eq_fn,
        sig_add_fn,
        sig_multi_scalar_mult_fn,
        sig_scratch_size_of_fn,
        sig_mult_fn,
        sig_generator_fn,
        sig_to_affines_fn,
        sig_add_or_dbl_fn,
    );

    const SigMultiPoint = sig_multi_point.getMultiPoint();

    // TODO: consume the above struct to work with public data structures

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
            pk_to_aff_fn(&pk_aff.point, &agg_pk.point);
            return pk_aff;
        }

        /// pk_scratch and sig_scratch are in []u8 to make it friendly to FFI
        /// let consumer decide the best Allocator to use
        pub fn aggregateWithRandomness(allocator: Allocator, sets: []*const PkAndSerializedSig, pk_scratch_u8: []u8, sig_scratch_u8: []u8, pk_out: *PublicKey, sig_out: *Signature) !void {
            if (sets.len == 0) {
                return error.InvalidLen;
            }

            const sig_scratch = try util.asU64Slice(sig_scratch_u8);
            const pk_scratch = try util.asU64Slice(pk_scratch_u8);

            const pks_refs = try allocator.alloc(*PublicKey, sets.len);
            const sigs_refs = try allocator.alloc(*const Signature, sets.len);
            defer allocator.free(pks_refs);
            defer allocator.free(sigs_refs);

            for (sets, 0..) |set, i| {
                pks_refs[i] = set.pk;
                const sig = try Signature.sigValidate(set.sig, true);
                sigs_refs[i] = &sig;
            }

            const rands = try allocator.alloc(u8, 32 * sets.len);
            defer allocator.free(rands);
            randBytes(rands[0..]);

            const scalars_refs = try allocator.alloc(*u8, sets.len);
            defer allocator.free(scalars_refs);

            for (0..sets.len) |i| {
                scalars_refs[i] = &rands[i * 32];
            }

            const n_bits = 64;
            const mult_pk = try multPublicKeys(pks_refs, scalars_refs, n_bits, pk_scratch);
            const pk_from_mult = mult_pk.toPublicKey();
            const mult_sig = try multSignatures(sigs_refs, scalars_refs, n_bits, sig_scratch);
            const sig_from_mult = mult_sig.toSignature();

            pk_out.* = pk_from_mult;
            sig_out.* = sig_from_mult;
        }

        /// Multipoint
        pub fn addPublicKeys(pks: []*const PublicKey) !AggregatePublicKey {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            // Rust does the same thing here
            const pk_aff_points: []*const pk_aff_type = @ptrCast(pks);
            const pk_point = try PkMultiPoint.add(pk_aff_points);
            return .{ .point = pk_point };
        }

        // scratch param is designed to be reused across multiple calls
        pub fn multPublicKeys(pks: []*const PublicKey, scalars: []*const u8, n_bits: usize, scratch: []u64) !AggregatePublicKey {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            // Rust does the same thing here
            const pk_aff_points: []*const pk_aff_type = @ptrCast(pks);
            const pk_point = try PkMultiPoint.mult(pk_aff_points, scalars, n_bits, scratch);
            return .{ .point = pk_point };
        }

        pub fn addSignatures(sigs: []*const Signature) !AggregateSignature {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            // Rust does the same thing here
            const sig_aff_points: []*const sig_aff_type = @ptrCast(sigs);
            const sig_point = try SigMultiPoint.add(sig_aff_points);
            return .{ .point = sig_point };
        }

        // scratch param is designed to be reused across multiple calls
        pub fn multSignatures(sigs: []*const Signature, scalars: []*const u8, n_bits: usize, scratch: []u64) !AggregateSignature {
            // this is unsafe code but we scanned through testTypeAlignment unit test
            // Rust does the same thing here
            const sig_aff_points: []*const sig_aff_type = @ptrCast(sigs);
            const sig_point = try SigMultiPoint.mult(sig_aff_points, scalars, n_bits, scratch);
            return .{ .point = sig_point };
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

        pub fn testSerialization() !void {
            var rng = std.rand.DefaultPrng.init(12345);
            const sk = getRandomKey(&rng);
            const sk2 = getRandomKey(&rng);

            const pk = sk.skToPk();
            const pk_comp = pk.compress();
            const pk_ser = pk.serialize();

            const pk_uncomp = try PublicKey.uncompress(pk_comp[0..]);
            try std.testing.expect(pk_uncomp.isEqual(&pk));

            const pk_deser = try PublicKey.deserialize(pk_ser[0..]);
            try std.testing.expect(pk_deser.isEqual(&pk));

            const pk2 = sk2.skToPk();
            const pk_comp2 = pk2.compress();
            const pk_ser2 = pk2.serialize();

            const pk_uncomp2 = try PublicKey.uncompress(pk_comp2[0..]);
            try std.testing.expect(pk_uncomp2.isEqual(&pk2));

            const pk_deser2 = try PublicKey.deserialize(pk_ser2[0..]);
            try std.testing.expect(pk_deser2.isEqual(&pk2));

            try std.testing.expect(!pk.isEqual(&pk2));
            try std.testing.expect(!pk_uncomp.isEqual(&pk2));
            try std.testing.expect(!pk_deser.isEqual(&pk2));
            try std.testing.expect(!pk_uncomp2.isEqual(&pk));
            try std.testing.expect(!pk_deser2.isEqual(&pk));
        }

        pub fn testSerde() !void {
            var rng = std.rand.DefaultPrng.init(12345);
            const sk = getRandomKey(&rng);
            const pk = sk.skToPk();
            const sig = sk.sign("asdf", "qwer", "zxcv");
            try sig.verify(true, "asdf", "qwer", "zxcv", &pk, true);

            // roundtrip through serde. TODO: do this in Zig
            const pk_ser = pk.serialize();
            const sig_ser = sig.serialize();
            const pk_des = try PublicKey.deserialize(pk_ser[0..]);
            const sig_des = try Signature.deserialize(sig_ser[0..]);

            try std.testing.expect(pk.isEqual(&pk_des));
            try std.testing.expect(sig.isEqual(&sig_des));

            try sig.verify(true, "asdf", "qwer", "zxcv", &pk_des, true);
            try sig_des.verify(true, "asdf", "qwer", "zxcv", &pk, true);

            const sk_ser = sk.serialize();
            const sk_des = try SecretKey.deserialize(sk_ser[0..]);
            const sig2 = sk_des.sign("asdf", "qwer", "zxcv");
            try std.testing.expect(sig.isEqual(&sig2));
        }

        /// additional tests in Zig to make sure our wrapped types point to the same memory as the original types
        /// for example, given a slice of PublicKey, we can pass pointer to the first element to the C function which expect *const pk_aff_type
        pub fn testTypeAlignment() !void {
            // alignOf
            try std.testing.expect(@alignOf(SecretKey) == @alignOf(c.blst_scalar));
            try std.testing.expect(@alignOf(PublicKey) == @alignOf(pk_aff_type));
            try std.testing.expect(@alignOf(AggregatePublicKey) == @alignOf(pk_type));
            try std.testing.expect(@alignOf(Signature) == @alignOf(sig_aff_type));
            try std.testing.expect(@alignOf(AggregateSignature) == @alignOf(sig_type));

            // sizeOf
            try std.testing.expect(@sizeOf(SecretKey) == @sizeOf(c.blst_scalar));
            try std.testing.expect(@sizeOf(PublicKey) == @sizeOf(pk_aff_type));
            try std.testing.expect(@sizeOf(AggregatePublicKey) == @sizeOf(pk_type));
            try std.testing.expect(@sizeOf(Signature) == @sizeOf(sig_aff_type));
            try std.testing.expect(@sizeOf(AggregateSignature) == @sizeOf(sig_type));

            // make sure wrapped structs and C structs point to the same memory so that we can safely use @ptrCast
            var rng = std.rand.DefaultPrng.init(12345);
            const sk = getRandomKey(&rng);
            const pk = sk.skToPk();
            const pk_addr = @intFromPtr(&pk);
            const pk_point_addr = @intFromPtr(&pk.point);
            try std.testing.expect(pk_addr == pk_point_addr);

            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
            const msg = "hello foo";
            const sig = sk.sign(msg[0..], dst[0..], null);
            const sig_addr = @intFromPtr(&sig);
            const point_addr = @intFromPtr(&sig.point);
            try std.testing.expect(sig_addr == point_addr);
        }

        /// multi point
        pub fn testAddPubkey() !void {
            try pk_multi_point.testAdd();
        }

        pub fn testMultPubkey() !void {
            try pk_multi_point.testMult();
        }

        pub fn testAddSig() !void {
            try sig_multi_point.testAdd();
        }

        pub fn testMultSig() !void {
            try sig_multi_point.testMult();
        }

        /// this is the same test to Rust's test_multi_point()
        pub fn testMultiPoint() !void {
            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
            const num_pks = 10;

            var rng = std.rand.DefaultPrng.init(12345);

            // Create public keys
            var sks = [_]SecretKey{SecretKey.default()} ** num_pks;
            for (0..num_pks) |i| {
                sks[i] = getRandomKey(&rng);
            }

            var pks: [num_pks]PublicKey = undefined;
            for (0..num_pks) |i| {
                pks[i] = sks[i].skToPk();
            }
            var pks_refs: [num_pks]*PublicKey = undefined;
            for (pks[0..], 0..num_pks) |*pk, i| {
                pks_refs[i] = pk;
            }

            // Create random message for pks to all sign
            // var msg_len = (rng.next() & 0x3F) + 1;
            // random msg_len
            const msg_len = 50;
            var msg: [msg_len]u8 = undefined;
            rng.random().bytes(msg[0..]);

            // Generate signature for each key pair
            var sigs: [num_pks]Signature = undefined;
            for (0..num_pks) |i| {
                sigs[i] = sks[i].sign(msg[0..], dst, null);
            }
            var sigs_refs: [num_pks]*Signature = undefined;
            for (sigs[0..], 0..num_pks) |*sig, i| {
                sigs_refs[i] = sig;
            }

            // Sanity test each current single signature
            for (0..num_pks) |i| {
                try sigs[i].verify(true, msg[0..], dst, null, pks_refs[i], true);
            }

            // sanity test aggregated signature
            const agg_pk = try AggregatePublicKey.aggregate(pks_refs[0..], false);
            const pk_from_agg = agg_pk.toPublicKey();
            const agg_sig = try AggregateSignature.aggregate(sigs_refs[0..], false);
            const sig_from_agg = agg_sig.toSignature();
            try sig_from_agg.verify(true, msg[0..], dst, null, &pk_from_agg, true);

            // test multi-point aggregation using add
            const added_pk = try addPublicKeys(pks_refs[0..]);
            const pk_from_add = added_pk.toPublicKey();
            const added_sig = try addSignatures(sigs_refs[0..]);
            const sig_from_add = added_sig.toSignature();
            try sig_from_add.verify(true, msg[0..], dst, null, &pk_from_add, true);

            // test multi-point aggregation using mult
            // n_bytes = 32
            const rands_len = 32 * num_pks;
            var rands: [rands_len]u8 = [_]u8{0} ** rands_len;
            rng.random().bytes(rands[0..]);

            var scalars_refs: [num_pks]*const u8 = undefined;
            for (0..num_pks) |i| {
                scalars_refs[i] = &rands[i * 32];
            }

            const n_bits = 64;

            var allocator = std.testing.allocator;
            const pk_scratch = try allocator.alloc(u64, pk_scratch_size_of_fn(num_pks) / 8);
            defer allocator.free(pk_scratch);
            const sig_scratch = try allocator.alloc(u64, sig_scratch_size_of_fn(num_pks) / 8);
            defer allocator.free(sig_scratch);

            const mult_pk = try multPublicKeys(pks_refs[0..], scalars_refs[0..], n_bits, pk_scratch);
            const pk_from_mult = mult_pk.toPublicKey();
            const mult_sig = try multSignatures(sigs_refs[0..], scalars_refs[0..], n_bits, sig_scratch);
            const sig_from_mult = mult_sig.toSignature();
            try sig_from_mult.verify(true, msg[0..], dst, null, &pk_from_mult, true);
        }

        /// specific testing in zig, logic is similar to testMultiPoint() with
        /// - no need to generate random
        /// - provide scratch values in []u8 instead of []u64
        pub fn testAggregateWithRandomness() !void {
            const dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
            const num_pks = 10;

            var rng = std.rand.DefaultPrng.init(12345);

            // Create public keys
            var sks = [_]SecretKey{SecretKey.default()} ** num_pks;
            for (0..num_pks) |i| {
                sks[i] = getRandomKey(&rng);
            }

            var pks: [num_pks]PublicKey = undefined;
            for (0..num_pks) |i| {
                pks[i] = sks[i].skToPk();
            }
            var pks_refs: [num_pks]*PublicKey = undefined;
            for (pks[0..], 0..num_pks) |*pk, i| {
                pks_refs[i] = pk;
            }

            // Create random message for pks to all sign
            // var msg_len = (rng.next() & 0x3F) + 1;
            // random msg_len
            const msg_len = 50;
            var msg: [msg_len]u8 = undefined;
            rng.random().bytes(msg[0..]);

            // Generate signature for each key pair
            var sigs: [num_pks]Signature = undefined;
            for (0..num_pks) |i| {
                sigs[i] = sks[i].sign(msg[0..], dst, null);
            }
            var sigs_refs: [num_pks]*Signature = undefined;
            for (sigs[0..], 0..num_pks) |*sig, i| {
                sigs_refs[i] = sig;
            }

            // Sanity test each current single signature
            for (0..num_pks) |i| {
                try sigs[i].verify(true, msg[0..], dst, null, pks_refs[i], true);
            }

            // out params
            var agg_pk = PublicKey.default();
            var agg_sig = Signature.default();

            var set: [num_pks]*PkAndSerializedSig = undefined;
            for (0..num_pks) |i| {
                const bytes = sigs[i].serialize();
                var s = PkAndSerializedSig{ .pk = &pks[i], .sig = bytes[0..] };
                set[i] = &s;
            }

            // scratch, allocate once and reuse
            var allocator = std.testing.allocator;
            const pk_scratch = try allocator.alloc(u64, pk_scratch_size_of_fn(num_pks) / 8);
            defer allocator.free(pk_scratch);
            const sig_scratch = try allocator.alloc(u64, sig_scratch_size_of_fn(num_pks) / 8);
            defer allocator.free(sig_scratch);

            const pk_scratch_u8 = util.asU8Slice(pk_scratch);
            const sig_scratch_u8 = util.asU8Slice(sig_scratch);

            try aggregateWithRandomness(std.testing.allocator, set[0..], pk_scratch_u8, sig_scratch_u8, &agg_pk, &agg_sig);

            try agg_sig.verify(true, msg[0..], dst, null, &agg_pk, true);
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

var random: ?std.rand.DefaultPrng = null;

fn getRandom() std.rand.DefaultPrng {
    if (random == null) {
        const timestamp: u64 = @intCast(std.time.milliTimestamp());
        random = std.rand.DefaultPrng.init(timestamp);
    }
    return random.?;
}

fn randNonZero() u64 {
    var rand = getRandom();
    var res = rand.int(u64);
    while (res == 0) {
        res = rand.int(u64);
    }
    return res;
}

fn randBytes(bytes: []u8) void {
    var rand = getRandom();
    rand.random().bytes(bytes);
}
