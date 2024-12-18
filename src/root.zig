const std = @import("std");
const testing = std.testing;
pub const MinPk = @import("./sig_variant_min_pk.zig").SigVariant;

test {
    testing.refAllDecls(@This());
}
