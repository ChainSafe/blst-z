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

    // download spec tests

    const options_spec_test_options = b.addOptions();
    const option_spec_test_url = b.option([]const u8, "spec_test_url", "") orelse "https://github.com/ethereum/consensus-spec-tests";
    options_spec_test_options.addOption([]const u8, "spec_test_url", option_spec_test_url);
    const option_spec_test_version = b.option([]const u8, "spec_test_version", "") orelse "v1.5.0";
    options_spec_test_options.addOption([]const u8, "spec_test_version", option_spec_test_version);
    const option_spec_test_out_dir = b.option([]const u8, "spec_test_out_dir", "") orelse "test/spec/spec_tests";
    options_spec_test_options.addOption([]const u8, "spec_test_out_dir", option_spec_test_out_dir);
    const options_module_spec_test_options = options_spec_test_options.createModule();

    const exe_download_spec_tests = b.addExecutable(.{
        .name = "download_spec_tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/spec/download_spec_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe_download_spec_tests.root_module.addImport("spec_test_options", options_module_spec_test_options);

    const run_exe_download_spec_tests = b.addRunArtifact(exe_download_spec_tests);
    if (b.args) |args| run_exe_download_spec_tests.addArgs(args);
    const tls_run_exe_download_spec_tests = b.step("download_spec_tests", "Run the download_spec_tests executable");
    tls_run_exe_download_spec_tests.dependOn(&run_exe_download_spec_tests.step);

    // write spec tests

    const exe_write_spec_tests = b.addExecutable(.{
        .name = "write_spec_tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/spec/write_spec_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe_write_spec_tests.root_module.addImport("spec_test_options", options_module_spec_test_options);

    const run_exe_write_spec_tests = b.addRunArtifact(exe_write_spec_tests);
    if (b.args) |args| run_exe_write_spec_tests.addArgs(args);
    const tls_run_exe_write_spec_tests = b.step("write_spec_tests", "Run the write_spec_tests executable");
    tls_run_exe_write_spec_tests.dependOn(&run_exe_write_spec_tests.step);

    // run spec tests

    const spec_tests = b.addTest(.{
        .root_source_file = b.path("test/spec/spec_tests.zig"),
        .target = target,
        .optimize = optimize,
        .filter = b.option([]const u8, "spec_test_filter", "Spec test filter"),
    });
    spec_tests.root_module.addImport("spec_test_options", options_module_spec_test_options);
    spec_tests.root_module.addImport("blst", blst_mod);
    spec_tests.root_module.addImport("yaml", b.dependency("yaml", .{}).module("yaml"));

    const run_spec_tests = b.addRunArtifact(spec_tests);
    if (b.args) |args| run_spec_tests.addArgs(args);
    const tls_run_spec_tests = b.step("run_spec_tests", "Run the spec tests");
    tls_run_spec_tests.dependOn(&run_spec_tests.step);
}
