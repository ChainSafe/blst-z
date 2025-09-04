const std = @import("std");
const Compile = std.Build.Step.Compile;
const ResolvedTarget = std.Build.ResolvedTarget;
const OptimizeMode = std.builtin.OptimizeMode;

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const portable = b.option(bool, "portable", "turn on portable mode") orelse false;

    // blst module (for downstream zig consumers)
    const blst_mod = b.addModule("blst", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,

        // blst does not need libc, however we need to link it to enable threading
        // see https://github.com/ChainSafe/blst-bun/issues/4
        .link_libc = true,
    });
    try configureBlst(b, blst_mod, target, portable);

    // blst dynamic library (for bun consumers)
    const blst_dylib = b.addLibrary(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/eth_c_abi.zig"),
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
    try configureBlst(b, blst_dylib.root_module, target, portable);

    b.installArtifact(blst_dylib);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const unit_tests = b.addTest(.{
        .root_module = blst_mod,
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}

/// Configure the blst module, based on the upstream build.sh and build.rs
/// reference https://github.com/supranational/blst/blob/v0.3.13/build.sh
/// and https://github.com/supranational/blst/blob/v0.3.13/bindings/rust/build.rs
/// TODO: port all missing flows
fn configureBlst(b: *std.Build, blst_mod: *std.Build.Module, target: ResolvedTarget, portable: bool) !void {
    var cflags = std.ArrayList([]const u8).init(b.allocator);
    defer cflags.deinit();

    try cflags.append("-fno-builtin");
    try cflags.append("-Wno-unused-function");
    try cflags.append("-Wno-unused-command-line-argument");
    if (target.result.cpu.arch == .x86_64) {
        try cflags.append("-mno-avx"); // avoid costly transitions
    }

    if (portable) {
        blst_mod.addCMacro("__BLST_PORTABLE__", "");
    } else {
        if (std.Target.x86.featureSetHas(target.result.cpu.features, .adx)) {
            blst_mod.addCMacro("__ADX__", "");
        }
    }
    if (target.result.cpu.arch != .x86_64 and target.result.cpu.arch != .aarch64) {
        blst_mod.addCMacro("__BLST_NO_ASM__", "");
    }

    blst_mod.addIncludePath(b.path("blst/bindings"));
    blst_mod.addCSourceFiles(.{
        .root = b.path("blst"),
        .files = &[_][]const u8{
            "src/server.c",
            "build/assembly.S",
        },
        .flags = cflags.items,
    });

    // // TODO: we may not need this since we linkLibC() above
    // const os = target.result.os;
    // // fix this error on Linux: 'stdlib.h' file not found
    // // otherwise blst-bun cannot load the shared library on Linux
    // // with error "Failed to open library. This is usually caused by a missing library or an invalid library path"
    // if (os.tag == .linux) {
    //     // since "zig cc" works fine, we just follow it
    //     // zig cc -E -Wp,-v -
    //     blst_mod.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
    //     blst_mod.addIncludePath(.{ .cwd_relative = "/usr/include" });
    //     if (arch == .x86_64) {
    //         blst_mod.addIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
    //     } else if (arch == .aarch64) {
    //         blst_mod.addIncludePath(.{ .cwd_relative = "/usr/include/aarch64-linux-gnu" });
    //     }
    // }
}
