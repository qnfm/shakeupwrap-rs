# shakeupwrap-rs

A standalone, parallel file encryption/decryption tool built on
[XKCP](https://github.com/XKCP/XKCP)'s ShakingUpAE (`SHAKE_Wrap`) primitive.

The crypto comes from XKCP (linked as a static library, built from a pinned git
submodule); the CLI, streaming I/O, and multi-core pipeline are implemented in
Rust. It is the standalone evolution of the in-tree `util/ShakeUpWrap` utility.

## Format

* 64-byte random key per file, stored separately (`-k`).
* 32-byte random salt header per file, bound into every chunk's AAD.
* Plaintext split into independent 4 MiB chunks; each chunk is wrapped from a
  clone of the keyed instance with AAD = `salt || chunk_index || final_flag`.
* 64-byte tag per chunk. Independent chunks are what make parallel processing
  possible while keeping truncation/reorder/tamper detection.

This matches the C `parallel_pipe_suw` format, so ciphertext is interoperable
between the two implementations.

## Concurrency

A streaming pipeline that overlaps I/O with compute:

```
reader thread  ->  bounded crossbeam channel  ->  N worker threads  ->  ordered writer
```

Bounded channels provide back-pressure (memory stays bounded regardless of file
size); workers each clone the keyed base and mutate only their own copy; the main
thread reassembles results in sequence order and writes them. Output is atomic
(temp file + rename) and refuses to overwrite an existing target. The design is
data-race-free by construction — no hand-written mutex/condvar machinery.

## Build

XKCP is vendored as a pinned git submodule and built automatically by
`build.rs`. Requires `make`, `gcc` and `xsltproc` (XKCP's build system) plus a
Rust toolchain.

```sh
git clone <this repo>
cd shakeupwrap-rs
git submodule update --init --recursive --depth 1   # fetch XKCP + XKCBuild
cargo build --release
```

`build.rs` runs `make x86-64/libXKCP.a` inside the submodule the first time, then
links it. Overrides:

* `XKCP_DIR` — use an existing XKCP checkout instead of the submodule.
* `XKCP_TARGET` — XKCP build target (default `x86-64`).

## Usage

```sh
shakeupwrap-rs -e -k KEYFILE [-o OUTFILE] < plaintext
shakeupwrap-rs -d -k KEYFILE [-o OUTFILE] < ciphertext
```

Input is read from stdin; output goes to stdout unless `-o` is given. The key
file is created on encryption (it must not already exist) and read on decryption.

## Tests

`tests/` contains the `bats` conformance suite (roundtrips across chunk
boundaries, truncation/tamper rejection, CLI behaviour):

```sh
SUW_BIN=$(pwd)/target/release/shakeupwrap-rs bats tests
```

### Cross-implementation interop

`tests/interop/` checks that the Rust binary and an independent C reference
implementation (`tests/interop/cref`, the `parallel_pipe_suw` variant, pinned)
produce mutually decryptable ciphertext in both directions across empty,
single-chunk and multi-chunk inputs:

```sh
cargo build --release
./tests/interop/run_interop.sh
```

### CI

`.github/workflows/ci.yml` builds, runs the conformance suite, and runs the
interop test on **both `x86_64` and `arm64`** (the latter on a native
`ubuntu-24.04-arm` runner with `XKCP_TARGET=generic64`). Running the interop
test on both architectures also confirms the on-disk format is byte-portable
across endianness/word-size assumptions.

`.github/workflows/update-xkcp.yml` runs daily, bumps the pinned XKCP submodule
to upstream `master`, and opens a pull request when there is a change (so the
update only lands after CI — including interop on both arches — passes).

## Layout

```
build.rs            # builds + links libXKCP.a from the submodule
c_shim/suw_ffi.c    # struct-agnostic C ABI over SHAKE_Wrap_*
src/xkcp.rs         # safe Rust wrapper over the shim
src/main.rs         # CLI + streaming parallel pipeline
tests/*.bats        # conformance tests
tests/interop/      # cross-implementation interop (Rust <-> C reference)
third_party/xkcp    # XKCP, pinned git submodule (the crypto)
```
