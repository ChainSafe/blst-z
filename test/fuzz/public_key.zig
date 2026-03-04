const std = @import("std");
const blst = @import("blst");
const fuzzUtils = @import("fuzzUtils");

const PublicKey = blst.PublicKey;
const BlstError = blst.BlstError;

fn ignoreDecodeError(err: anyerror) bool {
    return fuzzUtils.errorIn(err, .{
        BlstError.BadEncoding,
        BlstError.PointNotOnCurve,
        BlstError.PointNotInGroup,
        BlstError.PkIsInfinity,
    });
}

fn deserializePublicKey(input: []const u8) !void {
    const result = PublicKey.deserialize(input);
    if (result) |pk| {
        pk.validate() catch {};
    } else |err| {
        if (!ignoreDecodeError(err)) return err;
    }
}

fn decodePublicKeyFromReader(_: std.mem.Allocator, reader: anytype) !PublicKey {
    var buf: [PublicKey.SERIALIZE_SIZE]u8 = undefined;
    const len = try reader.readAll(&buf);
    return PublicKey.deserialize(buf[0..len]);
}

fn encodePublicKeyToWriter(writer: anytype, pk: PublicKey) !void {
    const encoded = pk.serialize();
    try writer.writeAll(&encoded);
}

test "fuzz public key deserialize" {
    const Ctx = struct {
        fn testOne(_: @This(), input: []const u8) !void {
            if (input.len > PublicKey.SERIALIZE_SIZE) return;
            try deserializePublicKey(input);
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{});
}

test "fuzz public key roundtrip" {
    try fuzzUtils.runBinaryFuzz(
        PublicKey,
        .{
            .max_input_bytes = PublicKey.SERIALIZE_SIZE,
            .check_canonical = true,
            .ignore_decode_error = ignoreDecodeError,
        },
        decodePublicKeyFromReader,
        encodePublicKeyToWriter,
    );
}
