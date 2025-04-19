const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Val = usize; // or whatever you're using
pub const Key = [48]u8; // assuming fixed-length key for example
const AutoHashMap = std.AutoHashMap(Key, Val);

/// a generic implementation for both zig application and Bun ffi
pub const PubkeyIndexMap = struct {
    map: AutoHashMap,

    pub fn init(allocator: Allocator) !*PubkeyIndexMap {
        const instance = try allocator.create(PubkeyIndexMap);
        instance.* = .{ .map = AutoHashMap.init(allocator) };
        return instance;
    }

    pub fn deinit(self: *PubkeyIndexMap) void {
        const allocator = self.map.allocator;
        self.map.deinit();
        allocator.destroy(self);
    }

    pub fn set(self: *PubkeyIndexMap, key: []const u8, value: Val) !void {
        var fixed_key: Key = undefined;
        @memcpy(&fixed_key, key);
        try self.map.put(fixed_key, value);
    }

    pub fn get(self: *PubkeyIndexMap, key: []const u8) ?Val {
        var fixed_key: Key = undefined;
        @memcpy(&fixed_key, key);
        return self.map.get(fixed_key);
    }

    // implement has, delete, size, clear, etc...
};

test "PubkeyIndexMap" {
    const allocator = std.testing.allocator;
    const instance = try PubkeyIndexMap.init(allocator);
    defer instance.deinit();

    var key: [48]u8 = [_]u8{5} ** 48;
    const value = 42;
    try instance.set(key[0..], value);
    var result = instance.get(key[0..]);
    if (result) |v| {
        try std.testing.expectEqual(v, value);
    } else {
        try std.testing.expect(false);
    }

    // C pointer
    var key_ptr: [*c]const u8 = key[0..].ptr;
    result = instance.get(key_ptr[0..key.len]);
    if (result) |v| {
        try std.testing.expectEqual(v, value);
    } else {
        try std.testing.expect(false);
    }

    key[1] = 1; // change key
    result = instance.get(key[0..]);
    try std.testing.expect(result == null);

    // C pointer
    result = instance.get(key_ptr[0..key.len]);
    try std.testing.expect(result == null);

    // new instance with same value
    const key2: [48]u8 = [_]u8{5} ** 48;
    result = instance.get(key2[0..]);
    if (result) |v| {
        try std.testing.expectEqual(v, value);
    } else {
        try std.testing.expect(false);
    }

    // C pointer
    key_ptr = key2[0..].ptr;
    if (result) |v| {
        try std.testing.expectEqual(v, value);
    } else {
        try std.testing.expect(false);
    }
}
