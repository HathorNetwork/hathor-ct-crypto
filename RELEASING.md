# Releasing

All four packages (`@hathor/ct-crypto-provider`, `@hathor/ct-crypto-node`,
`@hathor/ct-crypto-mobile`, `@hathor/ct-crypto-wasm`) release in lockstep
under one version. Native binaries are always CI-built.

- **`@hathor/ct-crypto-node`** is now built AND published entirely from CI via
  napi-rs (per-platform packages + `optionalDependencies` + npm provenance).
- **`@hathor/ct-crypto-mobile`** and **`@hathor/ct-crypto-wasm`** are CI-built;
  a maintainer publishes them from a machine with npm 2FA (below).
- **`@hathor/ct-crypto-provider`** is a pure-TS package built and published
  locally.

Use the `shielded` dist-tag, NOT `latest`, while these are `-shielded`
prereleases (review finding M-6): publishing a prerelease to `latest` makes a
plain `npm install` resolve to the experimental build. Consumers opt in with
`@shielded`. Move to `latest` only once a stable version ships.

## 1. Prepare

On a clean `master` checkout:

1. Bump the `version` field (and the internal `@hathor/ct-crypto-provider`
   dependency pin) in all four `packages/*/package.json`, and refresh
   `package-lock.json` (`npm install --package-lock-only`).
2. Commit (signed), push to `master`, then create and push a signed tag
   `vX.Y.Z`. The tag triggers the CI build+test gates.

## 2. Publish `@hathor/ct-crypto-node` (from CI)

Run the **`Build native addon (napi)`** workflow via *workflow_dispatch* with
the `version` input and `dry-run: true` first:

1. It builds the addon for all 7 targets, then the `publish` job (gated on the
   `npm-publish` environment — a reviewer must approve) validates the tarball.
2. Re-run with `dry-run: false` to publish. `napi prepublish` publishes each
   per-platform package (`@hathor/ct-crypto-node-<target>`) and wires the main
   package's `optionalDependencies`; the main package is then published with
   `--provenance --tag shielded`. No binaries are committed, and there is no
   "publish from a laptop" path for node anymore.

One-time setup: in repo Settings create the `npm-publish` environment with the
allowed publishers as *Required reviewers* and `NPM_TOKEN` as an environment
secret.

## 3. Publish provider, mobile, wasm (maintainer, npm 2FA)

After the node package is live:

1. Provider: `npm ci && npm run build` in `packages/ct-crypto-provider`, then
   `npm publish --tag shielded --access public`. Publish this **first** so the
   other packages' dependency pin resolves.
2. Mobile: download the `npm-package-mobile` artifact from the tag's
   `build-mobile.yml` run (iOS XCFramework + Android jniLibs + completeness
   assert), verify it, then `npm publish --tag shielded --access public` from
   the artifact. Its `prepublishOnly` guard refuses if the native binaries are
   missing (never publish mobile from the repo checkout — the binaries are
   gitignored and npm would silently ship a broken tarball).
3. Wasm: build locally (`scripts/build-wasm.sh` inside the nix dev shell,
   which stamps the version into `pkg/`), then `npm publish --tag shielded
   --access public` from `pkg/`.

Maintainers typically drive steps 3 with a local helper script (kept out of the
repo, like the commit helpers — see `.gitignore`); the steps above are the
source of truth.
