# Upstream / fork anchor

`crypto-core/` is a fork of the crypto embedded in **hathor-core**. hathor-core
is the running node and the **source of truth**: client-generated proofs and
commitments MUST verify under the node, and any semantic divergence is
potentially consensus-breaking.

The node's crypto currently lives at **`htr-rs/crates/htr-lib/src/`** on the
`experimental/shielded-outputs-alpha-*` branch line. It moved there from the
now-retired `hathor-ct-crypto/src/` path — update any tooling that still points
at the old location.

## Tracked upstream tip

- Upstream repo: `HathorNetwork/hathor-core`
- Branch: **`experimental/shielded-outputs-alpha-v4`**
- Tracked tip: **`b24229ffbbd2d9c15f7c003e8062e0a95bd75a4c`** (`b24229ff`),
  verified 2026-07-16.

Verified by content at this tip (`htr-rs/crates/htr-lib/src/` vs
`crypto-core/src/`):

- `error.rs`, `types.rs` — **byte-identical**.
- `generators.rs` — identical logic; differs only cosmetically (import order and
  a `genr`→`gen` parameter rename).
- `balance.rs` — semantically identical, including the `excess_blinding_factor`
  full-unshield path; differs only by control-flow-equivalent phrasing
  (nested `if let` vs let-chains).
- `pedersen.rs`, `rangeproof.rs`, `surjection.rs`, `ecdh.rs`, `lib.rs` — differ
  only by the documented intentional deltas below.

The fork originated on this same `experimental/shielded-outputs-alpha-*` branch
line. An exact fork-base commit is not asserted here: the crate has since moved
paths, so the anchor is defined by the content parity above against the tracked
tip, not by a base SHA.

## Known intentional deltas from upstream

All are either strictly *restrictive* (they can only reject inputs the node
would otherwise accept-then-abort on) or non-behavioral — none changes the bytes
of a producible artifact or a verification outcome:

- `rangeproof.rs`: explicit 40-bit amount cap (`MAX_PROVABLE_AMOUNT` = 2⁴⁰) and a
  deserialization size cap (`MAX_RANGE_PROOF_SIZE` = 3328 bytes). The range-proof
  params (`min_value = 1`, `exp = 0`, `min_bits = 40`) are unchanged from the
  node. **The cap is CREATE-side only** — it refuses to *build* an oversize
  proof. `verify_range_proof` deliberately does NOT enforce an upper bound,
  because the node enforces none either (see "Known limitations" below);
  enforcing it client-side would diverge from consensus.
- `pedersen.rs`: identity-point guards on the commitment constructors — reject
  the zero-amount / zero-blinding identity point that upstream would
  `assert!`-abort on across the FFI boundary.
- `surjection.rs`: domain-size cap (`MAX_SURJECTION_DOMAIN` = 256, mirrors
  libsecp256k1's `SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS`) + bounded retry +
  deserialization size cap (`MAX_SURJECTION_PROOF_SIZE` = 4096 bytes).
- `ecdh.rs`: rejection-sampling blinding generator + best-effort zeroization of
  secret material.
- `lib.rs`: drops the node-only `signed_amount` / `unsigned_amount` modules and
  the 64-bit-target `compile_error!` guard (so the crate also builds for
  `wasm32`), and adds a `pub use types::*;` glob re-export. No consensus impact.
- `balance.rs` / NAPI `verify_balance`: no semantic delta — kept in lockstep
  with the node's `excess_blinding_factor` (full-unshield) support; the only
  textual difference is control-flow-equivalent phrasing.

### Node-only modules intentionally NOT ported

`signed_amount.rs` and `unsigned_amount.rs` exist upstream but are node-internal
amount-arithmetic types that play no part in client proof/commitment generation.
They are deliberately absent from `crypto-core/`; their appearance here would be
drift (the `make check-drift` guard flags it).

**Watch item:** every crypto API still takes a plain `u64`. If a future upstream
normalized-amount design (e.g. 10¹⁶ scaling factors) ever flows into
commitments, it would dwarf the fork's 2⁴⁰ cap — re-evaluate the cap if that
lands.

## Known limitations (deferred upstream)

- **M-1 — range-proof verify has no upper bound.** `verify_range_proof` /
  `batch_verify_range_proofs` check only `range.start >= 1`; they never check
  `range.end`, so a proof crafted out-of-tree with a wider `min_bits`/`exp`
  proves a value in `[1, ~2⁶⁴)` and still verifies — contradicting the
  documented `[1, 2⁴⁰)` invariant. This is **not exploitable** (the balance
  equation binds mod the curve order `n ≈ 2²⁵⁶`; wrapping it needs ~2¹⁹²
  outputs) and the hathor-core node has the byte-identical gap, so client and
  node agree. The fix must land **upstream** in hathor-core's
  `verify_range_proof` (add `range.end <= MAX_PROVABLE_AMOUNT + 1`) so node and
  clients tighten in lockstep; adding it only in this fork's bindings would make
  the wallet stricter than the node and reject node-accepted outputs — a
  divergence `SECURITY.md` rates high. Do NOT add a client-side upper-bound
  guard; the create-side cap already prevents this ecosystem from producing such
  proofs, which is the safe, non-divergent direction.

## Staying in sync

The node moves. The missing `excess_blinding_factor` parameter happened
precisely because the fork silently fell behind core commits `30b4d147` /
`f708c8dc` / `e696effd`.

That drift is guarded by **`make check-drift`** (script:
[`scripts/check-drift.sh`](scripts/check-drift.sh)), a maintainer-run check to
run before every sync. It is deliberately **local, not a public CI job**: it
reads hathor-core's non-public experimental shielded-outputs branch, so
publishing it to CI would require exposing that upstream and giving public CI
access to it. (A ready-to-enable CI form is kept locally at
`.github/workflows/core-sync.yml` for if the check ever moves to a private CI.)
Point it at a local hathor-core checkout with `HATHOR_CORE_DIR=…` (defaults to
`../hathor-core`). It compares `htr-rs/crates/htr-lib/src/` on the tracked branch
against `crypto-core/src/` and:

- **hard-fails** if `error.rs` or `types.rs` (the zero-delta files) diverge at
  all;
- **surfaces the diff for mandatory review** on the delta-bearing files
  (`generators.rs`, `balance.rs`, `pedersen.rs`, `rangeproof.rs`,
  `surjection.rs`, `ecdh.rs`, `lib.rs`) — a plain diff cannot separate the
  blessed deltas above from new drift, so a human confirms every diff stays
  within the deltas listed here before merging;
- **flags** any new upstream module, or a node-only module leaking into the
  fork.

When it fires: diff `htr-rs/crates/htr-lib/src/` against `crypto-core/src/`,
review the delta beyond the intentional ones above, port it here in lockstep,
update this file, and bump `CORE_REF` (and the tracked-tip SHA above) if the
upstream tip moved. The long-term plan is to upstream the hardening deltas and
depend on the node's crate directly, eliminating the fork.
