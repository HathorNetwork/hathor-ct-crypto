# Releasing

All four packages (`@hathor/ct-crypto-provider`, `@hathor/ct-crypto-node`,
`@hathor/ct-crypto-mobile`, `@hathor/ct-crypto-wasm`) release in lockstep
under one version. Native binaries are always CI-built; publishing to npm is
run by a maintainer from a machine with npm 2FA.

## 1. Prepare

On a clean `master` checkout:

1. Bump the `version` field (and the internal `@hathor/ct-crypto-provider`
   dependency pin) in all four `packages/*/package.json`, and refresh
   `package-lock.json` (`npm install --package-lock-only`).
2. Commit (signed), push to `master`, then create and push a signed tag
   `vX.Y.Z`.

Pushing the tag triggers the CI builds:

- `build-node.yml` → the 7 NAPI prebuilds, completeness assert, `SHA256SUMS`,
  uploaded as the `npm-package` artifact;
- `build-mobile.yml` → the iOS XCFramework + Android jniLibs, completeness
  assert, `SHA256SUMS`, uploaded as the `npm-package-mobile` artifact.

## 2. Publish (after both workflows are green on the tag)

1. Download the `npm-package` and `npm-package-mobile` artifacts from the
   tag's workflow runs and verify each contains the version being released
   and every native binary (the artifacts are ready-to-publish package
   directories).
2. Build the provider locally (`npm ci && npm run build` in
   `packages/ct-crypto-provider`).
3. Build the wasm package locally (`scripts/build-wasm.sh` inside the nix dev
   shell) — it stamps the version from the package manifest into `pkg/`.
4. `npm publish --tag latest --access public`, in order: provider → node
   (from the artifact) → mobile (from the artifact) → wasm (from `pkg/`).
   The provider goes first so the other three packages' dependency pin
   resolves immediately.

Never `npm publish` node or mobile from the repo checkout: the native
binaries are gitignored, npm silently skips missing `files` entries, and the
resulting tarball would install everywhere and fail at the first native call
(the mobile package's `prepublishOnly` guard refuses for this reason).

Maintainers typically drive both phases with a local helper script (kept out
of the repo, like the commit helpers — see `.gitignore`); the steps above are
the source of truth.
