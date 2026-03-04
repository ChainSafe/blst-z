const std = @import("std");
const blst = @import("blst");
const fuzzUtils = @import("fuzzUtils");

const Signature = blst.Signature;
const BlstError = blst.BlstError;

fn deserializeSignature(input: []const u8) !void {
    const result = Signature.deserialize(input);
    if (result) |sig| {
        sig.validate(true) catch |err| {
            if (!fuzzUtils.errorIn(err, .{
                BlstError.PointNotInGroup,
                BlstError.PkIsInfinity,
            })) return err;
        };
    } else |err| {
        if (!ignoreDecodeError(err)) return err;
    }
}

fn decodeSignatureFromReader(_: std.mem.Allocator, reader: anytype) !Signature {
    var buf: [Signature.SERIALIZE_SIZE]u8 = undefined;
    const len = try reader.readAll(&buf);
    return Signature.deserialize(buf[0..len]);
}

fn encodeSignatureToWriter(writer: anytype, sig: Signature) !void {
    const encoded = sig.serialize();
    try writer.writeAll(&encoded);
}

fn ignoreDecodeError(err: anyerror) bool {
    return fuzzUtils.errorIn(err, .{
        BlstError.BadEncoding,
        BlstError.PointNotInGroup,
        BlstError.PkIsInfinity,
    });
}

test "fuzz signature deserialize" {
    const Ctx = struct {
        fn testOne(_: @This(), input: []const u8) !void {
            if (input.len > Signature.SERIALIZE_SIZE) return;
            try deserializeSignature(input);
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{});
}

test "fuzz signature roundtrip" {
    try fuzzUtils.runBinaryFuzz(
        Signature,
        .{
            .max_input_bytes = Signature.SERIALIZE_SIZE,
            .check_canonical = true,
            .ignore_decode_error = ignoreDecodeError,
        },
        decodeSignatureFromReader,
        encodeSignatureToWriter,
    );
}
