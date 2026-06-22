#!/usr/bin/env bash
#
# Cross-implementation interop test.
#
# Builds the C reference implementation (tests/interop/cref) and verifies that
# ciphertext is interchangeable with the Rust binary in BOTH directions, across
# empty, single-chunk and multi-chunk inputs. Because the chunk size is 4 MiB,
# the multi-chunk cases also exercise the chunk-index / final-flag handling and
# the salt header.
#
# Usage:
#   tests/interop/run_interop.sh [RUST_BIN]
#
# RUST_BIN defaults to target/release/shakeupwrap-rs. XKCP_TARGET is honoured so
# the same script works on x86-64 and arm64 CI runners.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"

RUST_BIN="${1:-$root/target/release/shakeupwrap-rs}"
XKCP_TARGET="${XKCP_TARGET:-x86-64}"

if [[ ! -x "$RUST_BIN" ]]; then
    echo "rust binary not found/executable: $RUST_BIN" >&2
    exit 1
fi

echo "Building C reference (XKCP_TARGET=$XKCP_TARGET) ..."
make -C "$here/cref" XKCP_TARGET="$XKCP_TARGET" >/dev/null
CREF="$here/cref/cref"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Sizes: empty, tiny, sub-chunk, exact chunk, chunk+1, two chunks+1.
CHUNK=$((4 * 1024 * 1024))
sizes=(0 1 1000 "$CHUNK" $((CHUNK + 1)) $((2 * CHUNK + 1)))

fail=0
for sz in "${sizes[@]}"; do
    pt="$work/pt"
    head -c "$sz" /dev/urandom > "$pt" 2>/dev/null || : > "$pt"

    # Direction 1: C encrypts, Rust decrypts.
    rm -f "$work/k1" "$work/c1" "$work/o1"
    "$CREF"     -e -k "$work/k1" -o "$work/c1" < "$pt"
    "$RUST_BIN" -d -k "$work/k1" -o "$work/o1" < "$work/c1"
    if cmp -s "$pt" "$work/o1"; then c2r=ok; else c2r=FAIL; fail=1; fi

    # Direction 2: Rust encrypts, C decrypts.
    rm -f "$work/k2" "$work/c2" "$work/o2"
    "$RUST_BIN" -e -k "$work/k2" -o "$work/c2" < "$pt"
    "$CREF"     -d -k "$work/k2" -o "$work/o2" < "$work/c2"
    if cmp -s "$pt" "$work/o2"; then r2c=ok; else r2c=FAIL; fail=1; fi

    printf 'size=%-9s C->Rust:%-4s Rust->C:%-4s\n' "$sz" "$c2r" "$r2c"
done

if [[ "$fail" -ne 0 ]]; then
    echo "INTEROP FAILED" >&2
    exit 1
fi
echo "interop OK"
