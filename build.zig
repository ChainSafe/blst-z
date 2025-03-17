const std = @import("std");
const Compile = std.Build.Step.Compile;
const ResolvedTarget = std.Build.ResolvedTarget;
const OptimizeMode = std.builtin.OptimizeMode;

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // build blst-z static library
    const staticLib = b.addStaticLibrary(.{
        .name = "blst",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // passed by "zig build -Dportable=true"
    const portable = b.option(bool, "portable", "Enable portable implementation") orelse false;
    // passed by "zig build -Dforce-adx=true"
    const force_adx = b.option(bool, "force-adx", "Enable ADX optimizations") orelse false;

    try withBlst(b, staticLib, target, false, portable, force_adx);

    // the folder where blst.h is located
    staticLib.addIncludePath(b.path("blst/bindings"));

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(staticLib);

    // build blst-z shared library
    const sharedLib = b.addSharedLibrary(.{
        .name = "blst_min_pk",
        .root_source_file = b.path("src/sig_variant_min_pk.zig"),
        .target = target,
        .optimize = optimize,
    });
    // sharedLib.addObjectFile(b.path(blst_file_path));
    try withBlst(b, sharedLib, target, true, portable, force_adx);
    sharedLib.addIncludePath(b.path("blst/bindings"));
    b.installArtifact(sharedLib);

    const exe = b.addExecutable(.{
        .name = "blst-z",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_unit_tests.linkLibrary(staticLib);
    lib_unit_tests.addIncludePath(b.path("blst/bindings"));

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);
}

/// instead of treating blst as a dependency lib, build and link it, we add its resource to our libs
/// and zig will handle a mixture of C, assembly and Zig code
///  reference to https://github.com/supranational/blst/blob/v0.3.13/bindings/rust/build.rs
fn withBlst(b: *std.Build, blst_z_lib: *Compile, target: ResolvedTarget, is_shared_lib: bool, portable: bool, force_adx: bool) !void {
    // add later, once we have cflags
    const arch = target.result.cpu.arch;

    // TODO: how to get target_env?
    // TODO: may have a separate build version for adx
    // then at Bun side, it has to detect if the target is x86_64 and has adx or not
    if (portable == true and force_adx == false) {
        // TODO: panic if target_env is sgx
        // use this instead
        blst_z_lib.root_module.addCMacro("__BLST_PORTABLE__", "");
    } else if (portable == false and force_adx == true) {
        if (arch == .x86_64) {
            blst_z_lib.root_module.addCMacro("__ADX__", "");
        } else {
            std.debug.print("`force-adx` is ignored for non-x86_64 targets \n", .{});
        }
    } else if (portable == false and force_adx == false) {
        // TODO: how to detect adx like this Rust call
        // if std::is_x86_feature_detected!("adx") {
        if (arch == .x86_64) {
            std.debug.print("ADX is turned on by default for x86_64 targets \n", .{});
            blst_z_lib.root_module.addCMacro("__ADX__", "");
        }
        // otherwise get: "undefined symbol redcx_mont_256" when run tests in Linux
    } else {
        // both are true
        @panic("Cannot set both `portable` and `force-adx` to true");
    }

    blst_z_lib.no_builtin = true;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    defer _ = gpa.deinit();

    var cflags = std.ArrayList([]const u8).init(allocator);
    defer cflags.deinit();

    // get this error in Mac arm: unsupported option '-mno-avx' for target 'aarch64-unknown-macosx15.1.0-unknown'
    if (arch == .x86_64) {
        try cflags.append("-mno-avx"); // avoid costly transitions
    }
    // the no_builtin should help, set here just to make sure
    try cflags.append("-fno-builtin");
    try cflags.append("-Wno-unused-function");
    try cflags.append("-Wno-unused-command-line-argument");

    if (is_shared_lib) {
        try cflags.append("-fPIC");
    }

    blst_z_lib.addCSourceFile(.{ .file = b.path("blst/src/server.c"), .flags = cflags.items });
    blst_z_lib.addCSourceFile(.{ .file = b.path("blst/build/assembly.S"), .flags = cflags.items });

    // fix this error on Linux: 'stdlib.h' file not found
    // since "zig cc" works fine, we just follow it
    // zig cc -E -Wp,-v -
    //   /usr/local/include
    //   /usr/include/x86_64-linux-gnu
    //   /usr/include
    blst_z_lib.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
    blst_z_lib.addIncludePath(.{ .cwd_relative = "/usr/include/x86_64-linux-gnu" });
    blst_z_lib.addIncludePath(.{ .cwd_relative = "/usr/include" });
}
