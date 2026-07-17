# hathor-ct-crypto — maintainer tasks
#
# check-drift is the LOCAL consensus-drift guard: it compares crypto-core/src
# against hathor-core's embedded crypto (experimental shielded-outputs branch)
# and fails on genuine drift. It is intentionally not a public CI job because it
# reads a non-public upstream branch — run it before syncing. See UPSTREAM.md.

HATHOR_CORE_DIR ?= ../hathor-core
CORE_REF        ?= experimental/shielded-outputs-alpha-v4

.PHONY: check-drift test

## check-drift: diff crypto-core against hathor-core; fail on drift (override HATHOR_CORE_DIR/CORE_REF as needed)
check-drift:
	@HATHOR_CORE_DIR="$(HATHOR_CORE_DIR)" CORE_REF="$(CORE_REF)" ./scripts/check-drift.sh

## test: run the Rust workspace tests as CI does
test:
	cargo test --workspace --locked --features hathor-ct-crypto-node/napi
