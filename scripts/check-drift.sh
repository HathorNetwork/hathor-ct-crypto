#!/usr/bin/env bash
#
# Local consensus-drift check: compare crypto-core/src against hathor-core's
# embedded crypto and fail on genuine drift.
#
# This is the LOCAL, maintainer-run form of the check (see UPSTREAM.md). It is
# deliberately not a public CI workflow: the check reads hathor-core's
# experimental shielded-outputs branch, which is not public. Run it before
# syncing, and whenever hathor-core's crypto may have moved.
#
# Usage:
#   make check-drift                       # uses ../hathor-core, branch alpha-v4
#   HATHOR_CORE_DIR=/path/to/hathor-core make check-drift
#   scripts/check-drift.sh /path/to/hathor-core [core-ref]
#
# Tiers mirror .github/workflows/core-sync.yml exactly:
#   Tier 1 (error.rs, types.rs)  -> must be byte-identical; any diff FAILS.
#   Tier 2 (7 delta-bearing files) -> surfaced for MANDATORY human review.
#   Node-only modules must stay ABSENT from the fork.
#   New upstream modules are surfaced as warnings.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HATHOR_CORE_DIR="${1:-${HATHOR_CORE_DIR:-$REPO_ROOT/../hathor-core}}"
CORE_REF="${2:-${CORE_REF:-experimental/shielded-outputs-alpha-v4}}"

MONO="$REPO_ROOT/crypto-core/src"

if [ ! -d "$HATHOR_CORE_DIR/.git" ]; then
  echo "error: hathor-core git checkout not found at '$HATHOR_CORE_DIR'." >&2
  echo "       pass its path as arg 1 or set HATHOR_CORE_DIR." >&2
  exit 2
fi

# Best-effort refresh so we check the live tip (offline: fall back to local ref).
git -C "$HATHOR_CORE_DIR" fetch --quiet origin "$CORE_REF" 2>/dev/null || \
  echo "note: could not fetch origin/$CORE_REF (offline?) — using local ref." >&2

RESOLVED="$(git -C "$HATHOR_CORE_DIR" rev-parse --verify --quiet "FETCH_HEAD" 2>/dev/null || true)"
[ -n "$RESOLVED" ] || RESOLVED="$(git -C "$HATHOR_CORE_DIR" rev-parse --verify --quiet "$CORE_REF" 2>/dev/null || true)"
if [ -z "$RESOLVED" ]; then
  echo "error: could not resolve ref '$CORE_REF' in $HATHOR_CORE_DIR." >&2
  exit 2
fi

# Extract the upstream crypto tree at the resolved ref WITHOUT touching the
# hathor-core working tree or its checked-out branch.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
UPSTREAM_SUBDIR="htr-rs/crates/htr-lib/src"
if ! git -C "$HATHOR_CORE_DIR" archive "$RESOLVED" "$UPSTREAM_SUBDIR" 2>/dev/null | tar -x -C "$TMP" 2>/dev/null; then
  echo "error: upstream crypto path $UPSTREAM_SUBDIR not found at $CORE_REF — hathor-core moved the crate again; update this script, core-sync.yml and UPSTREAM.md." >&2
  exit 1
fi
CORE="$TMP/$UPSTREAM_SUBDIR"

echo "drift check: fork=$MONO"
echo "             upstream=$HATHOR_CORE_DIR @ $CORE_REF (${RESOLVED:0:12})"
status=0

# --- Tier 1: must stay byte-identical ---
for f in error.rs types.rs; do
  if [ ! -f "$CORE/$f" ] || [ ! -f "$MONO/$f" ]; then
    echo "FAIL: $f missing on one side — module set changed, review"; status=1; continue
  fi
  if ! diff -q "$CORE/$f" "$MONO/$f" >/dev/null; then
    echo "FAIL: crypto-core/src/$f diverged from hathor-core (must be byte-identical):"
    diff -u "$CORE/$f" "$MONO/$f" || true
    status=1
  else
    echo "ok:   $f byte-identical"
  fi
done

# --- Tier 2: documented intentional deltas — surface for mandatory review ---
for f in generators.rs balance.rs pedersen.rs rangeproof.rs surjection.rs ecdh.rs lib.rs; do
  if [ ! -f "$CORE/$f" ] || [ ! -f "$MONO/$f" ]; then
    echo "FAIL: $f missing on one side — module set changed, review"; status=1; continue
  fi
  if diff -q "$CORE/$f" "$MONO/$f" >/dev/null; then
    echo "WARN: $f identical to upstream — node adopted the delta or the fork's hardening was reverted; review + update UPSTREAM.md"
  else
    echo "REVIEW: $f differs (must stay within UPSTREAM.md deltas) — run: diff -u <upstream>/$f crypto-core/src/$f"
  fi
done

# --- Node-only modules must stay absent ---
for f in signed_amount.rs unsigned_amount.rs; do
  if [ -f "$MONO/$f" ]; then
    echo "FAIL: $f leaked into crypto-core/src — node-only module, review"; status=1
  fi
done

# --- New upstream modules not tracked yet ---
known=" balance.rs ecdh.rs error.rs generators.rs lib.rs pedersen.rs rangeproof.rs surjection.rs types.rs signed_amount.rs unsigned_amount.rs "
for path in "$CORE"/*.rs; do
  base="$(basename "$path")"
  case "$known" in
    *" $base "*) : ;;
    *) echo "WARN: upstream added $base — new htr-lib module not tracked; review whether it belongs in crypto-core + update UPSTREAM.md" ;;
  esac
done

if [ "$status" -ne 0 ]; then
  echo "drift check FAILED — sync crypto-core with hathor-core and update UPSTREAM.md."
else
  echo "drift check passed (review any REVIEW/WARN lines above)."
fi
exit $status
