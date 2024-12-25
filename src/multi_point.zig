const std = @import("std");

/// Create MultiPoint struct, this follows non-std implementation of Rust binding
/// equivalent to blst/bindings/rust/src/pippenger-no_std.rs
/// IT: input type, for example PublicKey
/// OT: output type, for example AggregatePublicKey
pub fn createMultiPoint(comptime IT: type, comptime OT: type, it_default_fn: anytype, ot_default_fn: anytype, out_eql_fn: anytype, add_fn: anytype, multi_scalar_mult_fn: anytype, scratch_sizeof_fn: anytype, mult_fn: anytype, generator_fn: anytype, to_affines_fn: anytype, add_or_double_fn: anytype) type {
    const MultiPoint = struct {
        /// Skip from([]OT) api
        /// Rust accepts []OT here which make it convenient for test_add
        /// bringing that here makes us deal with allocator
        /// instead of that, it accepts []IT, the conversion of []IT to []OT is done at consumer side
        pub fn add(points: []*const IT) !OT {
            if (points.len == 0) {
                return error.ZeroPoints;
            }

            var result = ot_default_fn();
            // consumer usually need to convert []IT to []*IT which is not required in Rust
            add_fn(&result, &points[0], points.len);
            return result;
        }

        /// scratch parameter is designed to be reused here
        pub fn mult(points: []*const IT, scalars: []*const u8, n_bits: usize, scratch: []u64) !OT {
            if (points.len == 0) {
                return error.ZeroPoints;
            }

            const n_points = points.len;
            // this is different from Rust but it helps the test passed
            if (scalars.len < n_points) {
                return error.ScalarLenMismatch;
            }

            if (scratch.len < (scratch_sizeof_fn(n_points) / 8)) {
                return error.ScratchLenMismatch;
            }

            var result = ot_default_fn();
            multi_scalar_mult_fn(&result, &points[0], points.len, &scalars[0], n_bits, &scratch[0]);

            return result;
        }
    };

    return struct {
        MultiPoint: MultiPoint,

        pub fn testAdd() !void {
            const n_points = 2000;
            const n_bits = 32;
            const n_bytes = (n_bits + 7) / 8;

            var scalars = [_]u8{0} ** (n_points * n_bytes);

            var rng = std.rand.DefaultPrng.init(12345);
            rng.random().bytes(scalars[0..]);

            var points: [n_points]OT = undefined;
            var naive: OT = ot_default_fn();

            for (0..n_points) |i| {
                mult_fn(&points[i], generator_fn(), &scalars[i * n_bytes], 32);
                add_or_double_fn(&naive, &naive, &points[i]);
            }

            var points_refs: [n_points]*OT = undefined;
            for (points[0..], 0..) |*point, i| {
                points_refs[i] = point;
            }

            // convert []OT to []IT
            var aff_points_refs: [n_points]*IT = undefined;
            var aff_points: [n_points]IT = [_]IT{it_default_fn()} ** n_points;
            for (aff_points[0..], 0..) |*point, i| {
                aff_points_refs[i] = point;
            }

            to_affines_fn(aff_points_refs[0], &points_refs, n_points);

            const add_res = MultiPoint.add(aff_points_refs[0..]) catch return error.TestAddFailed;
            try std.testing.expect(out_eql_fn(&naive, &add_res));
        }

        pub fn testMult() !void {
            const n_points = 2000;
            const n_bits = 160;
            const n_bytes = (n_bits + 7) / 8;

            var scalars = [_]u8{0} ** (n_points * n_bytes);
            var rng = std.rand.DefaultPrng.init(12345);
            rng.random().bytes(scalars[0..]);

            var scalars_refs: [n_points]*const u8 = undefined;
            for (0..n_points) |i| {
                scalars_refs[i] = &scalars[i * n_bytes];
            }

            // std.debug.print("scratch_sizeof_fn(n_points) / 8: {}\n", .{scratch_sizeof_fn(n_points) / 8});
            var allocator = std.testing.allocator;
            const scratch = try allocator.alloc(u64, scratch_sizeof_fn(n_points) / 8);
            defer allocator.free(scratch);

            var points: [n_points]OT = [_]OT{ot_default_fn()} ** n_points;

            // convert []OT to []IT
            var aff_points_refs: [n_points]*IT = undefined;
            var aff_points: [n_points]IT = [_]IT{it_default_fn()} ** n_points;
            for (aff_points[0..], 0..) |*point, i| {
                aff_points_refs[i] = point;
            }

            var naive = ot_default_fn();
            var points_refs: [n_points]*OT = undefined;

            for (0..n_points) |i| {
                mult_fn(&points[i], generator_fn(), &scalars[i * n_bytes], @min(32, n_bits));
                points_refs[i] = &points[i];
                var t = ot_default_fn();
                mult_fn(&t, &points[i], &scalars[i * n_bytes], n_bits);
                add_or_double_fn(&naive, &naive, &t);

                // TODO: this is not efficient as it contains duplicate works
                to_affines_fn(aff_points_refs[0], &points_refs, (i + 1));
                if (i < 27) {
                    const mult_res = MultiPoint.mult(aff_points_refs[0..(i + 1)], scalars_refs[0..], n_bits, scratch) catch return error.TestMultFailed;
                    try std.testing.expect(out_eql_fn(&naive, &mult_res));
                }
            }

            for (points[0..], 0..) |*point, i| {
                points_refs[i] = point;
            }

            to_affines_fn(aff_points_refs[0], &points_refs, n_points);

            const mult_res = MultiPoint.mult(aff_points_refs[0..], scalars_refs[0..], n_bits, scratch) catch return error.TestMultFailed;
            try std.testing.expect(out_eql_fn(&naive, &mult_res));
        }
    };
}
