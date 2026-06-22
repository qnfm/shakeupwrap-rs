# C reference implementation (interop fixture)

This directory vendors the C `ShakeUpWrap` implementation that the Rust crate is
designed to interoperate with — the `parallel_pipe_suw` variant: 4 MiB
independent chunks, a 32-byte per-file salt header, and AAD = `salt ||
chunk_index || final_flag`.

It exists **only** so CI can verify that the Rust binary and an independent C
implementation produce mutually decryptable ciphertext (see
`tests/interop/run_interop.sh`). It is built against the same pinned XKCP
submodule used by the crate.

Treat these files as a pinned reference: if the Rust implementation's on-disk
format ever diverges, the interop test fails — which is the point. They are not
compiled into the Rust binary.

Build manually with:

```sh
make            # produces ./cref, linking ../../../third_party/xkcp libXKCP.a
```
