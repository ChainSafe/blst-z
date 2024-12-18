const std = @import("std");
const testing = std.testing;
pub const MinPk = @import("./sig_variant_min_pk.zig").MinPk;

test {
    testing.refAllDecls(@This());
}
