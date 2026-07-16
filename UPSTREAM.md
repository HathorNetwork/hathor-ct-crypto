# Upstream / fork anchor

`crypto-core/` is a fork of the crypto embedded in **hathor-core** at
`hathor-ct-crypto/src/`. hathor-core is the running node and the **source of
truth**: client-generated proofs and commitments MUST verify under the node, and
any semantic divergence is potentially consensus-breaking.

## Fork base

- Upstream repo: `HathorNetwork/hathor-core`
- Fork base commit: **`da513712`** (branch line `experimental/shielded-outputs-alpha-*`)
  — identified by content: at this commit `balance.rs`, `pedersen.rs`,
  `surjection.rs`, `generators.rs`, `types.rs`, `error.rs` are byte-identical to
  this repo's `crypto-core/src/`, `ecdh.rs` differs only by rustfmt reflow, and
  `rangeproof.rs` only by documentation/const-type drift.

## Known intentional deltas from the fork base

- `rangeproof.rs`: added an explicit 40-bit amount cap (`MAX_PROVABLE_AMOUNT`)
  and a deserialization size cap (`MAX_RANGE_PROOF_SIZE`).
- `pedersen.rs`: identity-point guards on the commitment constructors.
- `surjection.rs`: domain-size cap + bounded retry + deser size cap.
- `ecdh.rs`: rejection-sampling blinding generator + zeroization.
- `balance.rs` / NAPI `verify_balance`: kept in sync with core's
  `excess_blinding_factor` (full-unshield) support.

## Staying in sync

The node moves. The missing `excess_blinding_factor` parameter happened
precisely because the fork silently fell behind core commits
`30b4d147` / `f708c8dc` / `e696effd`.

Until an automated drift check lands in CI, syncing is a maintainer
discipline: when hathor-core's crypto changes (today at
`htr-rs/crates/htr-lib/src/` on the shielded-outputs branch line), diff it
against `crypto-core/src/`, review the delta beyond the intentional ones
listed above, port it here in lockstep, and update this file. The long-term
plan is to upstream the hardening deltas and depend on the node's crate
directly, eliminating the fork.
