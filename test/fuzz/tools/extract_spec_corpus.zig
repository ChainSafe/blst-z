// Extract BLS public keys and signatures from Ethereum consensus spec test
// YAML files and write them as binary corpus seeds for the AFL++ fuzz targets.
// Before running, make sure to download the spec tests data, and run:
//   `zig build extract-corpus`

const std = @import("std");
const spec_test_options = @import("spec_test_options");

// BLS G1 compressed public key: 48 bytes
const PK_BYTES = 48;
const PK_HEX_LEN = PK_BYTES * 2;

// BLS G2 compressed signature: 96 bytes
const SIG_BYTES = 96;
const SIG_HEX_LEN = SIG_BYTES * 2;

const spec_base = spec_base: {
    const out_dir = spec_test_options.spec_test_out_dir;
    const version = spec_test_options.spec_test_version;
    break :spec_base if (std.fs.path.isAbsolute(out_dir))
        std.fmt.comptimePrint("{s}/{s}/general/tests/general", .{ out_dir, version })
    else
        std.fmt.comptimePrint("../../{s}/{s}/general/tests/general", .{ out_dir, version });
};

// What to extract from each test type's data.yaml.
// Defined explicitly per test type so extraction is semantically driven —
// we know from the directory name what kinds of BLS objects each YAML contains,
// rather than relying on hex string length to distinguish pubkeys from sigs.
const Extract = struct { pubkeys: bool, sigs: bool };

const BLSTestType = struct {
    name: []const u8,
    extract: Extract,
};

const phase0_test_types = [_]BLSTestType{
    // input: { pubkey, message, signature }
    .{ .name = "verify", .extract = .{ .pubkeys = true, .sigs = true } },
    // input: { pubkeys[], message, signature }
    .{ .name = "fast_aggregate_verify", .extract = .{ .pubkeys = true, .sigs = true } },
    // input: { pubkeys[], messages[], signature }
    .{ .name = "aggregate_verify", .extract = .{ .pubkeys = true, .sigs = true } },
    // input: signatures[], output: aggregated_sig | null
    .{ .name = "aggregate", .extract = .{ .pubkeys = false, .sigs = true } },
    // input: { privkey, message }, output: signature
    .{ .name = "sign", .extract = .{ .pubkeys = false, .sigs = true } },
};

const altair_test_types = [_]BLSTestType{
    // input: pubkeys[], output: aggregated_pk | null
    .{ .name = "eth_aggregate_pubkeys", .extract = .{ .pubkeys = true, .sigs = false } },
    // input: { pubkeys[], message, signature }
    .{ .name = "eth_fast_aggregate_verify", .extract = .{ .pubkeys = true, .sigs = true } },
};

/// Find "0x" in `line` followed by exactly `hex_len` hex characters where
/// the character immediately after is not a hex digit (guards against
/// matching a prefix of a longer hex string on the same line).
/// Returns the hex slice (without "0x"), or null.
fn findExactHex(line: []const u8, hex_len: usize) ?[]const u8 {
    var i: usize = 0;
    while (i + 2 + hex_len <= line.len) : (i += 1) {
        if (line[i] != '0' or line[i + 1] != 'x') continue;

        const hex = line[i + 2 .. i + 2 + hex_len];
        var valid = true;
        for (hex) |c| {
            if (!std.ascii.isHex(c)) {
                valid = false;
                break;
            }
        }
        if (!valid) continue;

        // Ensure this is not a prefix of a longer hex string.
        const after = i + 2 + hex_len;
        if (after < line.len and std.ascii.isHex(line[after])) continue;

        return hex;
    }
    return null;
}

fn writeBytes(dir: std.fs.Dir, name: []const u8, data: []const u8) !void {
    const file = try dir.createFile(name, .{});
    defer file.close();
    try file.writeAll(data);
}

const Ctx = struct {
    pk_dir: std.fs.Dir,
    sig_dir: std.fs.Dir,
    agg_pk_dir: std.fs.Dir,
    agg_sig_dir: std.fs.Dir,
    seen_pks: std.StringHashMap(void),
    seen_sigs: std.StringHashMap(void),
    pk_count: u32 = 0,
    sig_count: u32 = 0,
    agg_pk_count: u32 = 0,
    agg_sig_count: u32 = 0,
    name_buf: [64]u8 = undefined,
    yaml_buf: []u8,
    concat_buf: []u8,
    arena: std.mem.Allocator,

    fn processTestType(ctx: *Ctx, bls_dir: std.fs.Dir, test_type: BLSTestType) !void {
        var type_dir = bls_dir.openDir(test_type.name, .{}) catch return;
        defer type_dir.close();
        var inner_dir = type_dir.openDir("bls", .{ .iterate = true }) catch return;
        defer inner_dir.close();

        var case_iter = inner_dir.iterate();
        while (try case_iter.next()) |case_entry| {
            if (case_entry.kind != .directory) continue;
            var case_dir = inner_dir.openDir(case_entry.name, .{}) catch continue;
            defer case_dir.close();

            const yaml = case_dir.readFile("data.yaml", ctx.yaml_buf) catch continue;
            var lines = std.mem.splitScalar(u8, yaml, '\n');

            // Collect all pubkeys/sigs from this test case for aggregate corpus.
            var pk_concat_len: usize = 0;
            var sig_concat_len: usize = 0;

            while (lines.next()) |line| {
                if (test_type.extract.pubkeys) {
                    if (findExactHex(line, PK_HEX_LEN)) |hex| {
                        // Individual pubkey → public_key-initial/.
                        try ctx.writeIndividualPk(hex);
                        // Append to concat buffer for aggregate corpus.
                        var bytes: [PK_BYTES]u8 = undefined;
                        _ = try std.fmt.hexToBytes(&bytes, hex);
                        @memcpy(ctx.concat_buf[pk_concat_len..][0..PK_BYTES], &bytes);
                        pk_concat_len += PK_BYTES;
                    }
                }
                if (test_type.extract.sigs) {
                    if (findExactHex(line, SIG_HEX_LEN)) |hex| {
                        // Individual signature → signature-initial/.
                        try ctx.writeIndividualSig(hex);
                        // Append to concat buffer for aggregate corpus.
                        const offset = ctx.concat_buf.len / 2 + sig_concat_len;
                        var bytes: [SIG_BYTES]u8 = undefined;
                        _ = try std.fmt.hexToBytes(&bytes, hex);
                        @memcpy(ctx.concat_buf[offset..][0..SIG_BYTES], &bytes);
                        sig_concat_len += SIG_BYTES;
                    }
                }
            }

            // Write concatenated multi-element files for aggregate targets.
            if (pk_concat_len > 0) {
                const name = try std.fmt.bufPrint(
                    &ctx.name_buf,
                    "spec-agg-pk-{d:0>4}",
                    .{ctx.agg_pk_count},
                );
                try writeBytes(ctx.agg_pk_dir, name, ctx.concat_buf[0..pk_concat_len]);
                ctx.agg_pk_count += 1;
            }
            if (sig_concat_len > 0) {
                const offset = ctx.concat_buf.len / 2;
                const name = try std.fmt.bufPrint(
                    &ctx.name_buf,
                    "spec-agg-sig-{d:0>4}",
                    .{ctx.agg_sig_count},
                );
                try writeBytes(ctx.agg_sig_dir, name, ctx.concat_buf[offset..][0..sig_concat_len]);
                ctx.agg_sig_count += 1;
            }
        }
    }

    fn writeIndividualPk(ctx: *Ctx, hex: []const u8) !void {
        if (ctx.seen_pks.contains(hex)) return;
        try ctx.seen_pks.put(try ctx.arena.dupe(u8, hex), {});
        var bytes: [PK_BYTES]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, hex);
        const name = try std.fmt.bufPrint(&ctx.name_buf, "spec-pk-{d:0>4}", .{ctx.pk_count});
        try writeBytes(ctx.pk_dir, name, &bytes);
        ctx.pk_count += 1;
    }

    fn writeIndividualSig(ctx: *Ctx, hex: []const u8) !void {
        if (ctx.seen_sigs.contains(hex)) return;
        try ctx.seen_sigs.put(try ctx.arena.dupe(u8, hex), {});
        var bytes: [SIG_BYTES]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes, hex);
        const name = try std.fmt.bufPrint(&ctx.name_buf, "spec-sig-{d:0>4}", .{ctx.sig_count});
        try writeBytes(ctx.sig_dir, name, &bytes);
        ctx.sig_count += 1;
    }
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    const cwd = std.fs.cwd();

    // concat_buf: first half for pubkeys, second half for signatures.
    // 128 pubkeys * 48 bytes = 6144, 128 sigs * 96 bytes = 12288.
    const concat_buf = try allocator.alloc(u8, 128 * PK_BYTES + 128 * SIG_BYTES);
    defer allocator.free(concat_buf);

    var ctx = Ctx{
        .pk_dir = try cwd.openDir("corpus/public_key-initial", .{}),
        .sig_dir = try cwd.openDir("corpus/signature-initial", .{}),
        .agg_pk_dir = try cwd.openDir("corpus/aggregate_pk-initial", .{}),
        .agg_sig_dir = try cwd.openDir("corpus/aggregate_sig-initial", .{}),
        .seen_pks = std.StringHashMap(void).init(allocator),
        .seen_sigs = std.StringHashMap(void).init(allocator),
        .yaml_buf = try allocator.alloc(u8, 1 << 20),
        .concat_buf = concat_buf,
        .arena = arena_state.allocator(),
    };
    defer {
        ctx.pk_dir.close();
        ctx.sig_dir.close();
        ctx.agg_pk_dir.close();
        ctx.agg_sig_dir.close();
        ctx.seen_pks.deinit();
        ctx.seen_sigs.deinit();
        allocator.free(ctx.yaml_buf);
    }

    {
        const path = spec_base ++ "/phase0/bls";
        var bls_dir = cwd.openDir(path, .{}) catch |err| {
            std.debug.print("Cannot open {s}: {}\nRun: zig build download_spec_tests\n", .{ path, err });
            return err;
        };
        defer bls_dir.close();
        for (phase0_test_types) |tt| try ctx.processTestType(bls_dir, tt);
    }

    {
        const path = spec_base ++ "/altair/bls";
        var bls_dir = cwd.openDir(path, .{}) catch |err| {
            std.debug.print("Cannot open {s}: {}\nRun: zig build download_spec_tests\n", .{ path, err });
            return err;
        };
        defer bls_dir.close();
        for (altair_test_types) |tt| try ctx.processTestType(bls_dir, tt);
    }

    std.debug.print(
        "Extracted:\n" ++
            "  {d} public keys     → public_key-initial/\n" ++
            "  {d} signatures      → signature-initial/\n" ++
            "  {d} aggregate seeds → aggregate_pk-initial/  (multi-pk per file)\n" ++
            "  {d} aggregate seeds → aggregate_sig-initial/ (multi-sig per file)\n",
        .{ ctx.pk_count, ctx.sig_count, ctx.agg_pk_count, ctx.agg_sig_count },
    );
}
