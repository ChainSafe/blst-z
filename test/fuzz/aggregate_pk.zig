const std = @import("std");
const fuzzUtils = @import("fuzzUtils");
const blst = @import("blst");

const PublicKey = blst.PublicKey;
const AggregatePublicKey = blst.AggregatePublicKey;
const BlstError = blst.BlstError;
const MAX_AGGREGATE_PER_JOB = blst.MAX_AGGREGATE_PER_JOB;

test "fuzz aggregate public key aggregate" {
    const Ctx = struct {
        fn testOne(_: @This(), input: []const u8) !void {
            const pk_size = PublicKey.SERIALIZE_SIZE;
            if (input.len < pk_size or input.len > pk_size * MAX_AGGREGATE_PER_JOB) return;
            const n = @min(input.len / pk_size, MAX_AGGREGATE_PER_JOB);
            if (n == 0) return;

            var pks: [MAX_AGGREGATE_PER_JOB]PublicKey = undefined;
            var count: usize = 0;
            for (0..n) |i| {
                const chunk = input[i * pk_size .. (i + 1) * pk_size];
                const pk = PublicKey.deserialize(chunk) catch continue;
                pks[count] = pk;
                count += 1;
            }

            if (count == 0) return;
            _ = AggregatePublicKey.aggregate(pks[0..count], false) catch |err| {
                if (!fuzzUtils.errorIn(err, .{BlstError.AggrTypeMismatch})) return err;
            };
        }
    };
    try std.testing.fuzz(Ctx{}, Ctx.testOne, .{});
}

test "fuzz aggregate public key aggregateWithRandomness" {
    const Ctx = struct {
        fn testOne(_: @This(), input: []const u8) !void {
            const pk_size = PublicKey.SERIALIZE_SIZE;
            const rand_size = 32;
            const item_size = pk_size + rand_size;

            if (input.len < item_size) return;
            const n = @min(input.len / item_size, MAX_AGGREGATE_PER_JOB);
            if (n == 0) return;

            var pks: [MAX_AGGREGATE_PER_JOB]PublicKey = undefined;
            var pks_refs: [MAX_AGGREGATE_PER_JOB]*const PublicKey = undefined;
            var randomness: [MAX_AGGREGATE_PER_JOB * rand_size]u8 = undefined;
            var count: usize = 0;

            for (0..n) |i| {
                const off = i * item_size;
                const pk_chunk = input[off .. off + pk_size];
                const rand_chunk = input[off + pk_size .. off + item_size];

                const pk = PublicKey.deserialize(pk_chunk) catch continue;
                pks[count] = pk;
                pks_refs[count] = &pks[count];
                @memcpy(randomness[count * rand_size .. (count + 1) * rand_size], rand_chunk);
                count += 1;
            }

            if (count == 0) return;

            const scratch = try std.testing.allocator.alloc(u64, 1 << 14);
            defer std.testing.allocator.free(scratch);

            const agg1 = AggregatePublicKey.aggregateWithRandomness(
                pks_refs[0..count],
                randomness[0 .. count * rand_size],
                false,
                scratch,
            ) catch |err| {
                if (!fuzzUtils.errorIn(err, .{BlstError.AggrTypeMismatch})) return err;
                return;
            };

            const agg2 = try AggregatePublicKey.aggregateWithRandomness(
                pks_refs[0..count],
                randomness[0 .. count * rand_size],
                false,
                scratch,
            );

            const pk1 = agg1.toPublicKey();
            const pk2 = agg2.toPublicKey();
            try std.testing.expectEqualSlices(u8, &pk1.serialize(), &pk2.serialize());

            _ = AggregatePublicKey.aggregateWithRandomness(
                pks_refs[0..count],
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
