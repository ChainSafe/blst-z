const std = @import("std");
const BlstError = @import("error.zig").BlstError;
const check = @import("error.zig").check;
const Variant = @import("variant.zig").Variant;
const PublicKey = @import("public_key.zig").PublicKey;
const Signature = @import("signature.zig").Signature;
const c = @import("c.zig");

pub fn SecretKey(comptime variant: Variant) type {
    const V = variant.Types();

    return extern struct {
        value: c.blst_scalar = c.blst_scalar{},

        const Self = @This();

        pub const serialize_size = 32;

        pub fn keyGen(ikm: []const u8, key_info: ?[]const u8) BlstError!Self {
            if (ikm.len < 32) {
                return BlstError.BAD_ENCODING;
            }

            var sk = Self{};
            c.blst_keygen(
                &sk.value,
                &ikm[0],
                ikm.len,
                @ptrCast(&key_info),
                if (key_info) |info| info.len else 0,
            );
            return sk;
        }

        pub fn keyGenV3(ikm: []const u8, key_info: ?[]const u8) BlstError!Self {
            if (ikm.len < 32) {
                return BlstError.BAD_ENCODING;
            }

            var sk = Self{};
            c.blst_keygen_v3(
                &sk.value,
                &ikm[0],
                ikm.len,
                @ptrCast(&key_info),
                if (key_info) |info| info.len else 0,
            );
            return sk;
        }

        pub fn keyGenV45(ikm: []const u8, salt: []const u8, info: ?[]const u8) BlstError!Self {
            if (ikm.len < 32) {
                return BlstError.BAD_ENCODING;
            }

            var sk = Self{};
            c.blst_keygen_v4_5(
                &sk.value,
                &ikm[0],
                ikm.len,
                &salt[0],
                salt.len,
                if (info) |i| i.ptr else null,
                if (info) |i| i.len else 0,
            );
            return sk;
        }

        pub fn keyGenV5(ikm: []const u8, salt: []const u8, info: ?[]const u8) BlstError!Self {
            if (ikm.len < 32) {
                return BlstError.BAD_ENCODING;
            }

            var sk = Self{};
            c.blst_keygen_v5(
                &sk.value,
                &ikm[0],
                ikm.len,
                &salt[0],
                salt.len,
                &info,
                if (info) |i| i.len else 0,
            );
            return sk;
        }

        pub fn deriveMasterEip2333(ikm: []const u8) BlstError!Self {
            if (ikm.len < 32) {
                return BlstError.BAD_ENCODING;
            }

            var sk = Self{};
            c.blst_derive_master_eip2333(&sk.value, ikm.ptr, ikm.len);
            return sk;
        }

        pub fn deriveChildEip2333(self: *const Self, child_index: u32) BlstError!Self {
            var sk = Self{};
            c.blst_derive_child_eip2333(&sk.value, &self.value, child_index);
            return sk;
        }

        pub fn toPublicKey(self: *const Self) PublicKey(variant) {
            var pk = PublicKey(variant){};
            V.sk_to_pk(null, &pk.point, &self.value);
            return pk;
        }

        // Sign
        pub fn sign(self: *const Self, msg: []const u8, dst: []const u8, aug: ?[]const u8) Signature(variant) {
            var sig = Signature(variant){};
            var q = V.AggSig{};
            V.hash(
                &q,
                @ptrCast(msg.ptr),
                msg.len,
                @ptrCast(dst.ptr),
                dst.len,
                if (aug) |a| @ptrCast(a.ptr) else null,
                if (aug) |a| a.len else 0,
            );
            V.sign(null, &sig.point, &q, &self.value);
            return sig;
        }

        pub fn serialize(self: *const Self) [32]u8 {
            var sk_out = [_]u8{0} ** 32;
            c.blst_bendian_from_scalar(&sk_out[0], &self.value);
            return sk_out;
        }

        pub fn deserialize(sk_in: *const [32]u8) BlstError!Self {
            var sk = Self{};
            c.blst_scalar_from_bendian(&sk, sk_in);
            if (!c.blst_sk_check(&sk)) {
                return BlstError.BAD_ENCODING;
            }
            return sk;
        }
    };
}
