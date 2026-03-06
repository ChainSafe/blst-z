const std = @import("std");
const blst = @import("blst");
const fuzzUtils = @import("fuzzUtils");

const Signature = blst.Signature;
const AggregateSignature = blst.AggregateSignature;
const BlstError = blst.BlstError;
const MAX_AGGREGATE_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;

test "fuzz aggregate signature aggregate" {
    const Ctx = struct {
        fn testOne(_: @This(), input: []const u8) !void {
            const sig_size = Signature.COMPRESS_SIZE;
            const n = @min(input.len / sig_size, MAX_AGGREGATE_PER_JOB);
            if (n == 0) return;

            var sigs: [MAX_AGGREGATE_PER_JOB]Signature = undefined;
            var count: usize = 0;
            for (0..n) |i| {
                const chunk = input[i * sig_size .. (i + 1) * sig_size];
                const sig = Signature.deserialize(chunk) catch continue;
                sigs[count] = sig;
                count += 1;
            }

            if (count == 0) return;
            _ = AggregateSignature.aggregate(sigs[0..count], false) catch |err| {
                if (!fuzzUtils.errorIn(err, .{BlstError.AggrTypeMismatch})) return err;
            };
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{});
}

test "fuzz aggregate signature aggregateWithRandomness" {
    const Ctx = struct {
        fn testOne(_: @This(), input: []const u8) !void {
            const sig_size = Signature.COMPRESS_SIZE;
            const rand_size = 32;
            const item_size = sig_size + rand_size;

            if (input.len < item_size) return;
            const n = @min(input.len / item_size, MAX_AGGREGATE_PER_JOB);
            if (n == 0) return;

            var sigs: [MAX_AGGREGATE_PER_JOB]Signature = undefined;
            var sigs_refs: [MAX_AGGREGATE_PER_JOB]*const Signature = undefined;
            var randomness: [MAX_AGGREGATE_PER_JOB * rand_size]u8 = undefined;
            var count: usize = 0;

            for (0..n) |i| {
                const off = i * item_size;
                const sig_chunk = input[off .. off + sig_size];
                const rand_chunk = input[off + sig_size .. off + item_size];

                const sig = Signature.deserialize(sig_chunk) catch continue;
                sigs[count] = sig;
                sigs_refs[count] = &sigs[count];
                @memcpy(randomness[count * rand_size .. (count + 1) * rand_size], rand_chunk);
                count += 1;
            }

            if (count == 0) return;

            const scratch = try std.testing.allocator.alloc(u64, 1 << 16);
            defer std.testing.allocator.free(scratch);

            _ = AggregateSignature.aggregateWithRandomness(
                sigs_refs[0..count],
                randomness[0 .. count * rand_size],
                false,
                scratch,
            ) catch |err| {
                if (!fuzzUtils.errorIn(err, .{BlstError.AggrTypeMismatch})) return err;
                return;
            };

            _ = AggregateSignature.aggregateWithRandomness(
                sigs_refs[0..count],
                randomness[0 .. count * rand_size],
                false,
                &[_]u64{},
            ) catch |err| {
                if (err == BlstError.AggrTypeMismatch) return;
                return err;
            };
            return error.UnexpectedResult;
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{});
}
