# AFL++ Fuzzer for blst-z

This directory contains [AFL++](https://aflplus.plus/) fuzzing harnesses
for key/signature deserialization and aggregation paths in blst-z.

## Fuzz Targets

| Target | Binary | Description |
|--------|--------|-------------|
| `public_key` | `fuzz-public_key` | Public key deserialize + validate + canonical re-encode |
| `signature` | `fuzz-signature` | Signature deserialize + validate + canonical re-encode |
| `aggregate_pk` | `fuzz-aggregate_pk` | Aggregate public key + aggregateWithRandomness |
| `aggregate_sig` | `fuzz-aggregate_sig` | Aggregate signature + aggregateWithRandomness |

## Prerequisites

Install AFL++ so `afl-cc` and `afl-fuzz` are on your `PATH`.

> **This only works on Linux machine currently.** 

## Building

From this directory (`test/fuzz`):

```sh
zig build
```

This emits AFL++ instrumented binaries to `zig-out/bin/fuzz-*`.

## Running

```sh
zig build run-public_key
zig build run-signature
zig build run-aggregate_pk
zig build run-aggregate_sig
```

Or run manually:

```sh
afl-fuzz -i corpus/public_key-initial -o afl-out/public_key \
  -- zig-out/bin/fuzz-public_key
```

## Replay crashes

```sh
./replay-crashes.sh
./replay-crashes.sh public_key
```
