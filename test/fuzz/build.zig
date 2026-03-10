const std = @import("std");
const afl = @import("afl");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const blst_z = b.dependency("blst_z", .{
        .target = target,
        .optimize = optimize,
    });

    const utils_mod = b.addModule("utils", .{
        .root_source_file = b.path("src/utils.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Tool: extract corpus seeds from spec test YAML files.
    {
        const extract_mod = b.createModule(.{
            .root_source_file = b.path("tools/extract_spec_corpus.zig"),
            .target = target,
            .optimize = optimize,
        });
        extract_mod.addImport("utils", utils_mod);
        extract_mod.addImport("spec_test_options", blst_z.module("spec_test_options"));
        const extract_exe = b.addExecutable(.{
            .name = "extract_spec_corpus",
            .root_module = extract_mod,
        });
        const run_extract = b.addRunArtifact(extract_exe);
        run_extract.setCwd(b.path("."));
        const extract_step = b.step(
            "extract-corpus",
            "Extract spec test YAML files as corpus seeds",
        );
        extract_step.dependOn(&run_extract.step);
    }

    const Fuzzer = struct {
        name: []const u8,

        // TODO: change to cmin
        fn corpus(comptime self: @This()) []const u8 {
            return "corpus/" ++ self.name ++ "-initial";
        }

        fn source(comptime self: @This()) []const u8 {
            return "src/fuzz_" ++ self.name ++ ".zig";
        }
    };

    const fuzzers = &[_]Fuzzer{
        .{ .name = "public_key" },
        .{ .name = "signature" },
        .{ .name = "aggregate_pk" },
        .{ .name = "aggregate_sig" },
    };

    inline for (fuzzers) |fuzzer| {
        const run_step = b.step(
            b.fmt("fuzz-{s}", .{fuzzer.name}),
            b.fmt("Run {s} with afl-fuzz", .{fuzzer.name}),
        );

        const lib_mod = b.createModule(.{
            .root_source_file = b.path(fuzzer.source()),
            .target = target,
            .optimize = optimize,
        });
        lib_mod.addImport("blst", blst_z.module("blst"));
        lib_mod.addImport("utils", utils_mod);

        const lib = b.addLibrary(.{
            .name = fuzzer.name,
            .root_module = lib_mod,
        });
        lib.root_module.stack_check = false;
        lib.root_module.fuzz = true;

        const lib_blst_c = blst_z.artifact("blst");
        const exe = afl.addInstrumentedExe(b, lib, &.{lib_blst_c.getEmittedBin()});
        const mkdir = b.addSystemCommand(&.{
            "mkdir", "-p",
        });
        mkdir.addDirectoryArg(
            b.path(b.fmt("afl-out/{s}", .{fuzzer.name})),
        );

        const run = afl.addFuzzerRun(
            b,
            exe,
            b.path(fuzzer.corpus()),
            b.path(b.fmt("afl-out/{s}", .{fuzzer.name})),
        );
        run.step.dependOn(&mkdir.step);
        run_step.dependOn(&run.step);

        const install = b.addInstallBinFile(
            exe,
            "fuzz-" ++ fuzzer.name,
        );
        b.getInstallStep().dependOn(&install.step);
    }
}
