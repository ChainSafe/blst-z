const std = @import("std");
const Compile = std.Build.Step.Compile;
const ResolvedTarget = std.Build.ResolvedTarget;
const OptimizeMode = std.builtin.OptimizeMode;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const blst_c = b.dependency("blst", .{
        .portable = b.option(bool, "portable", "turn on portable mode") orelse false,
    });

    const lib_blst_c = blst_c.artifact("blst");

    // blst module (for downstream zig consumers)
    const blst_mod = b.addModule("blst", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    blst_mod.linkLibrary(lib_blst_c);
    blst_mod.addIncludePath(blst_c.path("include"));

    b.installArtifact(lib_blst_c);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_unit_tests.linkLibrary(lib_blst_c);
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
