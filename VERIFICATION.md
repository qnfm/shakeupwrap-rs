# shakeupwrap-rs — Formal Verification Report

Crate: `shakeupwrap-rs` (salted, chunked file-encryption CLI: 4 MiB chunks, 64-byte SHAKE_Wrap (ShakingUpAE) tag, 32-byte salt in the header, AAD-bound chunk index + final flag).

Toolchain used: **Kani 0.68.0** (CBMC backend) for code-level verification, **ProVerif** (opam, default switch) for symbolic protocol-level verification.

---

## 1. What was verified and how

Two complementary layers:

| Layer | Tool | Target | Result |
|---|---|---|---|
| Code-level property proofs | Kani 0.68.0 | `src/main.rs` (`make_aad`, `validate_dec`, `read_full`) | 10/10 harnesses SUCCESS |
| Protocol-level model | ProVerif | `verification/proverif/suw.pv`, `suw_nosalt.pv` | suw.pv: both queries TRUE; nosalt control: integrity FALSE (as designed) |
| Regression / interop | bats | `tests/*.bats` | 26/26 pass |
| Release build | cargo | `cargo build --release` | clean |

Commands:

```sh
cargo kani                       # all harnesses
cargo build --release
SUW_BIN=$(pwd)/target/release/shakeupwrap-rs bats tests
cd verification/proverif && proverif suw.pv && proverif suw_nosalt.pv
```

---

## 2. Kani harness results (all SUCCESS)

| # | Harness | Property |
|---|---|---|
| 1 | `aad_injective_in_index_and_final` | AAD differs for distinct chunk indices (index injection, `i1 != i2` symbolic) |
| 2 | `aad_injective_in_final_flag` | final-flag byte separates final from non-final AAD |
| 3 | `aad_injective_in_salt` | AAD differs for files with distinct 32-byte salts (anti-splice core property) |
| 4 | `aad_boundary_indices_reachable` | cover points for index 0 and `u64::MAX` |
| 5 | `validate_dec_accepts_only_producible_lengths` | accepted (len, final, index) tuples imply producer-canonical lengths; empty final chunk only at index 0 |
| 6 | `validate_dec_accepts_all_producible_lengths` | completeness: every producible length is accepted |
| 7 | `truncated_nonfinal_chunk_rejected` | any `len < ENC_CHUNK` rejected for non-final chunks |
| 8 | `extended_final_chunk_rejected` | `len > CHUNK + TAGLEN` final chunks rejected (bounded `extra <= 64`) |
| 9 | `read_full_bounded` | concrete loop `n = 0..=17`: `read_full` reads exactly `min(n, 16)` bytes, leaves tail zeroed |
| 10 | `no_panic_arbitrary_inputs` | no panic on arbitrary salt/index/flag/len; AAD layout exact (index LE bytes at 32..40, flag at 40, rest zero) |

Supporting code added for verification only:

- `#[cfg(kani)]` twin `read_full_slice` mirrors `read_full` semantics on a slice; the real `impl Read` deref chain blows up the solver.
- Harness 9 uses a small concrete loop instead of a symbolic bound: symbolic 4M-iteration chunk loops time out (600 s), so large-loop coverage is delegated to the bats integration tests, while Kani keeps tiny domains exhaustive (0..=17 covers short-read, exact-fill and over-long cases).
- Symbolic arithmetic needs explicit `kani::assume` bounds (e.g. `extra <= 64` in harness 8); without them CBMC explores overflow paths that cannot be discharged.
- `Cargo.toml` carries an `[lints.rust]` `unexpected_cfgs` allowance for `cfg(kani)`.
- Lessons learned the hard way: an early `plen = 0` counterexample was a **harness bug** (unrealistic encoding assumption), not an implementation bug — it was fixed by tightening the harness, and is the reason harness 6 asserts the endpoint-only set of producible lengths.

---

## 3. ProVerif models

Files (in `verification/proverif/`):

- **`suw.pv`** — real design: 32-byte salt in the header, bound into every chunk's AAD via `aad(salt, index, final)` (injective constructor, cf. Kani harness 3).
- **`suw_nosalt.pv`** — negative control: identical model but `aad_nosalt(index, final)` — the AAD contains **no salt**.

Both models contain: an encryptor (2 chunks: index 0 non-final, index 1 final), a decryptor, a second file with the **same key** (delivered over per-consumer private channels `c_kd`/`c_ke2`/`c_kd2`) and a fresh salt, and a key-leak process leaking a *distinct* key `kL` on the public channel `c_leak`.

### Results

| Model | Integrity `accepts ⇒ sends` | Confidentiality `sends ∧ attacker(m) ⇒ key_leaked` |
|---|---|---|
| `suw.pv` | **true** | **true** |
| `suw_nosalt.pv` | **false** (concrete attack trace) | true |

### Why the negative control fails (the attack)

With the salt out of the AAD, the attacker splices across files — ProVerif finds a concrete trace:

1. The encryptor honestly emits chunk 0 `seal(k, aad_nosalt(idx(0), final_false), m0)` and the final chunk `seal(k, aad_nosalt(idx(1), final_true), m1)` under its salt `s`; the attacker records both (cipher channel is public).
2. The attacker feeds file 2's *public* header salt `s2` to `decryptor2` and replays file 1's final chunk on the cipher channel.
3. `unseal(k, aad_nosalt(idx(1), final_true), c)` succeeds — the AAD carries no salt — so `accepts(k, s2, idx(1), final_true, m1)` fires while the encryptor recorded `sends(k, s, idx(1), final_true, m1)`: file 1's final chunk is accepted as file 2's final chunk under a different salt.
4. `accepts ⇒ sends` is violated; ProVerif reports the query **false** with the derivation above.

In `suw.pv` the identical splice fails: the chunk is sealed under `aad(s, …)` but the spliced decryptor checks `aad(s2, …)`, and since `aad` is injective in its salt argument (proved exhaustively by Kani harness 3) no `unseal` succeeds. Both queries remain **true**.

### Modelling notes

- Both files share one key, fanned out on one private channel per consumer (`c_kd`, `c_ke2`, `c_kd2`): a private channel in ProVerif carries a single message, so a single shared key channel would let only one of the three consumers read it and make the model degenerate. Salts stay per-file and public, so the salt is the *only* difference between the two files and the integrity queries isolate exactly the property under test.
- Plaintexts are fresh `new m` values chosen by the encryptors rather than attacker-supplied inputs: an earlier draft used a private plaintext channel with no producer, which silently blocked every encryptor and made all "true" results **vacuous** — always check that the honest `sends` events are reachable before trusting a correspondence query.
- The leak process releases a **distinct** key `kL`, not the file key `k`: leaking `k` itself lets the attacker forge `seal(k, aad(s2, …), m)` from scratch, which trivially breaks integrity under any design and is out of scope for the chunk-binding property being modelled. (An earlier draft leaked `k` and made even `suw.pv` false — that "failure" was the model, not the design.)
- Chunk-data and key/salt types are abstract (constructors `seal`/`unseal`/`aad`); ProVerif checks reachability over the symbolic Dolev–Yao attacker.

---

## 4. Comparison: shakeupwrap-rs vs Cobblestone-128

Prose comparison only: Cobblestone was not installed, built or modelled here, so its column reflects its published design description and was not independently verified.

| Dimension | shakeupwrap-rs | Cobblestone-128 |
|---|---|---|
| Chunk size | 4 MiB (2²²) | 16 KiB (2¹⁴) |
| Tag overhead | 64 B SHAKE_Wrap tag per 4 MiB chunk ≈ 0.0015% | 16 B tag per 16 KiB chunk ≈ 0.1% |
| Header entropy | 32 B salt (public, in header) bound to every AAD | 24 B salt + 32 B key commitment bound to every AAD |
| Context binding | salt + chunk index + final flag only — no file/path name, no algorithm version | HKDF-derived context binding (info string ties chunks to the file identity) |
| Random access | none: sequential reader loop; decrypt requires streaming from the start | yes: `ReaderAt` semantics — seek to any chunk and decrypt it independently |
| Parallelism | multi-threaded pipeline (reader → worker pool → writer with `AtomicBool` error stop) | per-chunk parallel decryption |
| Key reuse model | one key + per-file salt; integrity of cross-file splicing rests on salt-in-AAD (proved above) | key commitment + HKDF info binding gives stronger cross-context separation |
| Verification performed here | 10 Kani proofs + 2 ProVerif models (one negative control) | none performed here |

**Trade-off summary.** shakeupwrap-rs wins on throughput-oriented geometry (huge chunks ⇒ negligible per-chunk overhead and a simple parallel pipeline) and on having machine-checked evidence that its salt-in-AAD scheme defeats cross-file splicing. Cobblestone-128 wins on flexibility (true random access via 16 KiB chunks, `ReaderAt`) and on richer key material (key commitment + HKDF info gives per-file context separation beyond a bare salt). The ProVerif negative control is the sharpest demonstration of the difference: remove the salt from the AAD — i.e. move one step toward a bare-index scheme — and integrity collapses to an expressible splice attack.

---

## 5. Limitations

- **Symbolic idealisation.** ProVerif works in the Dolev–Yao model with perfect-crypto `seal`/`unseal`; it proves structural binding, not bit-level crypto strength (no birthday, nonce-reuse or side-channel analysis).
- **Bounded harness domains.** Kani harnesses exhaustively cover the AAD layout and validator logic, but large-loop chunk I/O is covered by integration tests rather than symbolic execution (4M-iteration loops exceed the 600 s budget).
- **Model-vs-code gap.** The ProVerif `aad(salt, index, final)` constructor corresponds to `make_aad`/`validate_dec`, which Kani proves injective and canonical; the bridge between the two layers is by-construction, not mechanically checked.
- **Vacuity risk.** Three modelling drafts produced misleading results (vacuous TRUE from a blocked encryptor, FALSE from leaking the file key) before the final models above; the reported results are from the versions in `verification/proverif/`.
- **Scope.** No verification of the header parser, thread pipeline, or CLI surface; the key-leak query models compromise of *other* keys only (see §3 notes).

---

## 6. Reproduction

```sh
export PATH=$HOME/.cargo/bin:$PATH
cargo kani                                        # 10/10 SUCCESS
cargo build --release
SUW_BIN=$(pwd)/target/release/shakeupwrap-rs bats tests   # 26/26
eval $(opam env --switch=default)
cd verification/proverif
proverif suw.pv          # integrity true, confidentiality true
proverif suw_nosalt.pv   # integrity false (splice attack found), confidentiality true
```
