const std = @import("std");

pub fn FuzzOptions(comptime T: type) type {
    return struct {
        min_input_bytes: usize = 0,
        max_input_bytes: usize = 1 << 17,
        check_canonical: bool = false,
        pre_filter: ?*const fn ([]const u8) bool = null,
        validate: ?*const fn (T) anyerror!void = null,
        ignore_decode_error: ?*const fn (anyerror) bool = null,
    };
}

pub fn errorIn(err: anyerror, comptime allowed: anytype) bool {
    inline for (allowed) |allowed_err| {
        if (err == allowed_err) return true;
    }
    return false;
}

pub fn runRoundTripFuzz(
    comptime T: type,
    options: FuzzOptions(T),
    decode_fn: *const fn (std.mem.Allocator, []const u8) anyerror!T,
    encode_fn: *const fn (std.mem.Allocator, T) anyerror![]u8,
) !void {
    const Context = struct {
        options: FuzzOptions(T),
        decode_fn: *const fn (std.mem.Allocator, []const u8) anyerror!T,
        encode_fn: *const fn (std.mem.Allocator, T) anyerror![]u8,

        fn testOne(self: @This(), input: []const u8) !void {
            const options_local = self.options;
            if (input.len < options_local.min_input_bytes or input.len > options_local.max_input_bytes) return;
            if (options_local.pre_filter) |pre_filter| {
                if (!pre_filter(input)) return;
            }

            var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            const value = self.decode_fn(arena, input) catch |err| {
                if (options_local.ignore_decode_error) |ignore_decode_error| {
                    if (ignore_decode_error(err)) return;
                }
                return err;
            };

            if (options_local.validate) |validate| {
                try validate(value);
            }

            const encoded = try self.encode_fn(arena, value);
            const value2 = try self.decode_fn(arena, encoded);
            if (options_local.validate) |validate| {
                try validate(value2);
            }
            try std.testing.expectEqualDeep(value, value2);

            if (options_local.check_canonical) {
                const encoded2 = try self.encode_fn(arena, value2);
                try std.testing.expectEqualSlices(u8, encoded, encoded2);
            }
        }
    };

    try std.testing.fuzz(Context{
        .options = options,
        .decode_fn = decode_fn,
        .encode_fn = encode_fn,
    }, Context.testOne, .{});
}

pub fn runBinaryFuzz(
    comptime T: type,
    options: FuzzOptions(T),
    comptime decode_from_reader: anytype,
    comptime encode_to_writer: anytype,
) !void {
    const Decode = struct {
        fn run(allocator: std.mem.Allocator, input: []const u8) !T {
            var stream = std.io.fixedBufferStream(input);
            return decode_from_reader(allocator, stream.reader());
        }
    };

    const Encode = struct {
        fn run(allocator: std.mem.Allocator, value: T) ![]u8 {
            var list = std.ArrayList(u8).init(allocator);
            errdefer list.deinit();
            try encode_to_writer(list.writer(), value);
            return try list.toOwnedSlice();
        }
    };

    try runRoundTripFuzz(T, options, Decode.run, Encode.run);
}
