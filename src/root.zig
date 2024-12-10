const std = @import("std");
const testing = std.testing;
const blst_scalar_from_uint32 = @import("bindings.zig").blst_scalar_from_uint32;

// const c = @cImport({
//     @cInclude("blst.h");
// });

export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
