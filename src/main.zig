const std = @import("std");

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    std.debug.print("asyncTest 000 at zig: {}\n", .{2025});

    const thread = std.Thread.spawn(.{}, struct {
        fn run(int_t: c_uint) void {
            std.debug.print("asyncTest 111 at zig: {}\n", .{int_t});
        }
    }.run, .{2025}) catch |err| {
        std.debug.print("Thread spawn failed: {} \n", .{err});
        return;
    };

    thread.join();
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
