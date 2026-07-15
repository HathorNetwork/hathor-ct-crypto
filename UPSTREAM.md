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
  and a deserialization size cap (`MAX_RANGE_PROOF_SIZE`) [CRY-02 / ROB-02].
- `pedersen.rs`: identity-point guards on the commitment constructors [MEM-01].
- `surjection.rs`: domain-size cap + bounded retry + deser size cap
  [MEM-02 / NEW-06 / ROB-02].
- `ecdh.rs`: rejection-sampling blinding generator + zeroization [NEW-07 / SEC-03].
- `balance.rs` / NAPI `verify_balance`: kept in sync with core's
  `excess_blinding_factor` (full-unshield) support [DIV-01].

## Staying in sync

The node moves. DIV-01 (the missing `excess_blinding_factor` parameter) happened
precisely because the fork silently fell behind core commits
`30b4d147` / `f708c8dc` / `e696effd`.

CI runs a **core-sync drift check** (`.github/workflows/core-sync.yml`): it clones
hathor-core at a pinned ref and diffs `hathor-ct-crypto/src/*.rs` against
`crypto-core/src/*.rs`, allowlisting the intentional deltas above and rustfmt
reflow, failing on any new semantic divergence. When it fails, review the node's
change and port it here in lockstep (and update this file's pinned ref).
