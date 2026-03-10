const std = @import("std");
const assert = std.debug.assert;
const blst = @import("blst");
const utils = @import("utils");

const Signature = blst.Signature;
const BlstError = blst.BlstError;

pub export fn zig_fuzz_init() callconv(.c) void {}

pub export fn zig_fuzz_test(
    buf: [*]const u8,
    len: usize,
) callconv(.c) void {
    if (len == 0 or len > Signature.SERIALIZE_SIZE) return;
    const input = buf[0..len];

    const sig = Signature.deserialize(input) catch |err| {
        if (utils.errorIn(err, .{
            BlstError.BadEncoding,
            BlstError.PointNotOnCurve,
            BlstError.PointNotInGroup,
            BlstError.PkIsInfinity,
        })) return;
        @panic("unexpected signature decode error");
    };

    sig.validate(true) catch |err| {
        if (err == BlstError.PointNotInGroup or err == BlstError.PkIsInfinity) return;
        @panic("unexpected signature validation error");
    };

    const encoded = sig.serialize();
    const sig2 = Signature.deserialize(&encoded) catch return;
    const encoded2 = sig2.serialize();
    assert(std.mem.eql(u8, &encoded, &encoded2));
}
