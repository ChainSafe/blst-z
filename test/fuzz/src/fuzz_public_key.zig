const std = @import("std");
const assert = std.debug.assert;
const blst = @import("blst");
const utils = @import("utils");

const PublicKey = blst.PublicKey;
const BlstError = blst.BlstError;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len == 0 or len > PublicKey.SERIALIZE_SIZE) return;
    const input = buf[0..len];

    const pk = PublicKey.deserialize(input) catch |err| {
        if (utils.errorIn(err, .{
            BlstError.BadEncoding,
            BlstError.PointNotOnCurve,
            BlstError.PointNotInGroup,
            BlstError.PkIsInfinity,
        })) return;
        @panic("unexpected public key decode error");
    };

    pk.validate() catch |err| {
        if (err == BlstError.PointNotInGroup or err == BlstError.PkIsInfinity) return;
        @panic("unexpected public key validation error");
    };

    const encoded = pk.serialize();
    const pk2 = PublicKey.deserialize(&encoded) catch return;
    const encoded2 = pk2.serialize();
    assert(std.mem.eql(u8, &encoded, &encoded2));
}
