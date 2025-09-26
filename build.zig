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

    // blst dynamic library (for bun consumers)
    const blst_dylib = b.addLibrary(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root_c_abi_min_pk.zig"),
            .target = target,
            .optimize = optimize,
            // blst does not need libc, however we need to link it to enable threading
            // see https://github.com/ChainSafe/blst-bun/issues/4
            .link_libc = true,
            .pic = true,
        }),
        .name = "eth_blst",
        .linkage = .dynamic,
    });
    blst_dylib.linkLibrary(lib_blst_c);

    b.installArtifact(blst_dylib);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_unit_tests.linkLibrary(lib_blst_c);
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe_unit_tests.linkLibrary(lib_blst_c);
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}
