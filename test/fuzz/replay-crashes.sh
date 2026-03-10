#!/bin/bash
set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="${FUZZ_DIR}/zig-out/bin"
AFL_OUT="${FUZZ_DIR}/afl-out"

targets=(public_key signature aggregate_pk aggregate_sig)

if [ $# -ge 1 ]; then
    targets=("$1")
fi

total_crashes=0
total_replayed=0

for target in "${targets[@]}"; do
    crash_dir="${AFL_OUT}/${target}/default/crashes"
    bin="${BIN_DIR}/fuzz-${target}"

    if [ ! -d "$crash_dir" ]; then
        echo "OK   ${target}: no crashes directory"
        continue
    fi

    if [ ! -x "$bin" ]; then
        echo "SKIP ${target}: binary not found at ${bin}"
        continue
    fi

    crashes=("$crash_dir"/id:*)
    if [ ! -e "${crashes[0]}" ]; then
        echo "OK   ${target}: no crashes"
        continue
    fi

    for f in "${crashes[@]}"; do
        fname=$(basename "$f")
        total_crashes=$((total_crashes + 1))

        if __AFL_DEFER_FORKSRV=1 "$bin" < "$f" 2>/dev/null; then
            echo "PASS ${target}: ${fname} (no longer crashes)"
        else
            echo "FAIL ${target}: ${fname} (still crashes)"
        fi
        total_replayed=$((total_replayed + 1))
    done
done

echo ""
echo "Replayed ${total_replayed}/${total_crashes} crash files."
