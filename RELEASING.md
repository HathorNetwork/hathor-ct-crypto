# Releasing

The four packages (`@hathor/ct-crypto-provider`, `@hathor/ct-crypto-node`,
`@hathor/ct-crypto-mobile`, `@hathor/ct-crypto-wasm`) release in lockstep under
one version. On npm that is 11 packages, because the node addon ships one
package per platform:

| npm package | Contents | Built by | Published from |
|---|---|---|---|
| `@hathor/ct-crypto-provider` | TypeScript interface + abstract class | `tsc`, locally and in `build-wasm.yml` | tarball packed from the tag |
| `@hathor/ct-crypto-node-<platform>` (7) | one napi binary each | `build-node.yml` on the tag | that run's `bindings-<target>` artifacts |
| `@hathor/ct-crypto-node` | committed JS loader, typings, provider adapter | — | tarball packed from the tag |
| `@hathor/ct-crypto-mobile` | RN bridge, UniFFI bindings, XCFramework, jniLibs | `build-mobile.yml` on the tag | that run's `npm-package-mobile` artifact |
| `@hathor/ct-crypto-wasm` | wasm-bindgen browser verifier | `build-wasm.yml` on the tag | that run's `wasm-pkg` artifact |

Every native binary is built by CI from the release tag, and a maintainer
publishes all 11 packages from their machine with npm 2FA. Nothing is published
from CI and CI holds no npm token, so the packages carry no npm provenance
attestation. Review finding M-6 had closed that gap with a CI publish job; that
job was dropped by decision, so the provenance half of M-6 is open again. What
stands in for it:

- every native binary, and the provider's compiled `lib/`, is byte-identical
  to the tag's CI build;
- the wasm package (binary, wasm-bindgen JS glue, typings and generated
  `package.json`) is the tag's CI artifact as built;
- the JS, typings, Swift, Kotlin and headers that live in the repository are
  byte-identical to the tagged sources;
- after publishing, the registry's checksums are compared with the tarballs.

While versions are `-shielded` prereleases, publish to the `shielded` dist-tag,
never `latest` (review finding M-6): a prerelease on `latest` is what a plain
`npm install` resolves to. Consumers opt in with `@shielded`. A package's first
publish also sets `latest`, and it stays there until someone moves it on
purpose.

## Before the first release from a machine

- An npm account in the `hathor` org with publish rights and 2FA. It must be
  allowed to create packages in the scope: a release can be the first publish
  of `@hathor/ct-crypto-mobile` or of a platform package.
- Push access to `master` and to tags, `gh` logged in, and commit and tag
  signing (`git commit -S`, `git tag -s`).
- Node.js 22, Rust via rustup (the bump builds the addon), and Docker for the
  container smoke tests.
- For the helper script: bash 4.4 or newer (`brew install bash`; macOS ships
  3.2).

## With the helper script

Maintainers drive this with a local helper, `release-publish.sh`, kept out of
git like the other interactive helpers (see `.gitignore`). It runs the steps
below in order, stops before anything irreversible to ask, and resumes where
it left off when run again. Run it in a terminal, without piping its output:
npm only asks for 2FA when it is attached to one.

```sh
./release-publish.sh status 0.0.2-shielded   # where the release stands
./release-publish.sh 0.0.2-shielded          # prepare, tag, stage, publish
```

A rehearsal that pushes and publishes nothing: `--dry-run prepare <next>`
builds the bump commit in a throwaway worktree. `--ref master stage <current>`
followed by `--ref master --dry-run publish <current>` stages and dry-run
publishes the version already on master, in `.release/rehearsal-v<current>/`.

The steps below are the procedure the helper automates. The helper also runs
every check in step 3 mechanically: exact file lists, byte comparisons and
manifest rules. Prefer it over doing them by hand.

## 1. Bump (on `master`)

Start from a green `master`: all four workflows below must pass on the commit
the bump goes on top of.

The bump is a pure version substitution in exactly six files:

- `version` in `packages/ct-crypto-{provider,node,mobile,wasm}/package.json`;
- the exact `@hathor/ct-crypto-provider` pin in the node, mobile and wasm
  manifests;
- `package-lock.json` (`npm install --package-lock-only`);
- the version literals in `packages/ct-crypto-node/index.js`, the
  napi-generated loader. It is committed and shipped as is, and with
  `NAPI_RS_ENFORCE_VERSION_CHECK=1` it checks each platform package's version
  against its own.

Regenerate the loader rather than hand-editing it: once the manifests and
`package-lock.json` are bumped, `npm ci && npm run build:debug -w
@hathor/ct-crypto-node` rewrites `index.js`. If that changes more than the
version literals, land the regenerated loader in its own commit first.
(`build-node.yml` fails any commit whose committed loader or typings differ
from what the build generates.)

Leave `Cargo.toml` and `Cargo.lock` alone: no published artifact reads the
crate versions (`build-wasm.sh` stamps `pkg/package.json` from the npm
manifest). Don't use `npm version --workspaces` (it leaves the provider pins
behind) or `npm version patch|minor|major` (it drops the `-shielded` suffix).

Commit the six files signed, push to `master`, and wait for all four workflows
on that commit to be green: `ci.yml`, `build-node.yml`, `build-mobile.yml`,
`build-wasm.yml`. `ci.yml` does not run on tags, so this is the only point
where the jest suites, the bindings-drift check and the audits see the release
commit.

If one fails and re-running it doesn't help, nothing is tagged or published
yet: revert the bump on `master`, land the fix, and bump again on top of it
(the helper notices the revert and bumps again when re-run). Never tag a commit
whose checks are red.

## 2. Tag

```sh
git tag -s v<version> -m "Release v<version>" <bump commit>
git push origin v<version>
```

The tag name is `v` plus the exact package version: the podspec's `:tag` is
derived from it. The tag triggers `build-node.yml`, `build-mobile.yml` and
`build-wasm.yml`; wait for all three. Their artifacts are what gets published.
If one fails, re-run its failed jobs. A pushed tag never moves, so a failure
that needs a code change means releasing the next version instead.

GitHub re-runs a run only within 30 days, and the artifacts expire after 90.
Keep `.release/v<version>/` until all 11 packages are published: you can
publish from it at any age. If it is gone, re-stage while the artifacts last.
Once they have expired with packages still unpublished, cut a new version.

## 3. Stage and verify

Nothing is published in this step. Pack every package as a tarball into one
directory (`OUT` below), check the tarballs, and record their hashes.

- **Find the tag's runs.** For each of the three workflows:

  ```sh
  gh run list -R HathorNetwork/hathor-ct-crypto -w <workflow> -b v<version> -e push \
    --json databaseId,headSha,conclusion
  ```

  `headSha` must be the tag's commit. Never take artifacts from a `master`
  run: a master run can be for a later commit that carries the same version.
- **Download** each artifact into its own directory (`gh run download <run>
  -n <name> -D <dir>`):
  - `bindings-*` from the node run (`-p 'bindings-*'`);
  - `npm-package-mobile`, `mobile-sha256sums`, `mobile-ios-xcframework` (a
    zip: unzip `HathorCtCrypto.xcframework.zip`) and `mobile-android-jnilibs`
    from the mobile run;
  - `wasm-pkg` and `provider-lib` from the wasm run.
- **Provider**: in a clean checkout of the tag, `npm ci`, then in
  `packages/ct-crypto-provider` run `npm run clean && npm run build`. `lib/`
  must be identical to `provider-lib` (`diff -r`). Copy the root `LICENSE` in,
  then `npm pack --ignore-scripts --pack-destination "$OUT"`.
- **Node**: in `packages/ct-crypto-node` of that checkout:
  1. Run `npx napi create-npm-dirs`.
  2. Copy the downloaded `.node` files into `artifacts/` and run
     `npx napi artifacts --output-dir artifacts`. The path must be relative,
     because the CLI joins it onto its working directory.
  3. Add the platform packages as optional dependencies:

     ```sh
     for d in npm/*/; do
       npm pkg set "optionalDependencies.@hathor/ct-crypto-node-$(basename "$d")=<version>"
     done
     ```

     Don't use `napi prepublish` for this: it also publishes every
     `npm/<platform>/` directory itself, unchecked and without `--tag`.
  4. Copy `LICENSE` into the package and into each `npm/<platform>/`.
  5. Run `npm pack --ignore-scripts --pack-destination "$OUT"` in each
     `npm/<platform>/`, then in the package.
- **Mobile**:
  - The `SHA256SUMS` inside `npm-package-mobile` must equal the
    `mobile-sha256sums` copy, and `shasum -a 256 -c SHA256SUMS` must pass.
  - Its XCFramework and `.so` files must equal those in
    `mobile-ios-xcframework` and `mobile-android-jnilibs`, with only
    `libhathor_ct_crypto_mobile.so` in each ABI.
  - Then `npm pack --ignore-scripts --pack-destination "$OUT"` the artifact.
- **Wasm**: `npm pack --ignore-scripts --pack-destination "$OUT"` the
  `wasm-pkg` artifact as is. Don't rebuild locally: a local build does not
  reproduce the binary that passed CI's smoke test and `test:real`.

Check each tarball before going on:

- **Version**: every manifest carries the release version, and the provider
  pins match it.
- **Manifest content**: no manifest sets `tag` (it would override `--tag`),
  has a `publishConfig` other than `{"access": "public"}`, has install
  scripts, or has `bin`.
- **Node package**: it lists the seven platform packages at the release
  version, and its `index.js` carries no other version. Its manifest is the
  tagged one plus `optionalDependencies`.
- **Platform binaries**: each is byte-identical to its CI artifact, and its
  format matches its `os`, `cpu` and `libc` (`file` / `lipo -archs`; glibc
  builds reference `GLIBC_` symbols, musl builds don't).
- **Sources**: files that exist in the tag are byte-identical to it. The
  XCFramework's `Headers/hathor_ct_cryptoFFI.h` and `Headers/module.modulemap`
  are the tag's `ios/hathor_ct_cryptoFFI.h` and `ios/hathor_ct_cryptoFFI.modulemap`.
- **File sets**: nothing stray. Each tarball holds exactly these files:

  | package | files |
  |---|---|
  | provider | `lib/**`, `package.json`, `README.md`, `LICENSE` |
  | each platform package | `ct-crypto.<platform>.node`, `package.json`, `README.md`, `LICENSE` |
  | node | `index.js`, `index.d.ts`, `provider.js`, `provider.d.ts`, `package.json`, `README.md`, `LICENSE` |
  | mobile | what `npm pack --dry-run` lists for the tag's `packages/ct-crypto-mobile`, plus `LICENSE`, `SHA256SUMS`, the XCFramework, and one `.so` per ABI |
  | wasm | `hathor_ct_crypto_wasm{.js,.d.ts,_bg.wasm,_bg.wasm.d.ts}`, `provider.js`, `provider.d.ts`, `package.json`, `README.md`, `LICENSE` |

Then smoke-test the node packages. In `$OUT`, unpack the provider, node and one
platform package into a `node_modules` and run them:

```sh
P=darwin-arm64 V=<version>
mkdir -p smoke && cd smoke
for p in provider node node-$P; do
  mkdir -p node_modules/@hathor/ct-crypto-$p
  tar -xzf ../hathor-ct-crypto-$p-$V.tgz -C node_modules/@hathor/ct-crypto-$p --strip-components=1
done
NAPI_RS_ENFORCE_VERSION_CHECK=1 node -e '
  const ct = require("@hathor/ct-crypto-node");
  const c = ct.createCommitment(1n, ct.generateRandomBlindingFactor(), ct.htrAssetTag());
  if (!ct.validateCommitment(c)) throw new Error("commitment does not validate");
  require("@hathor/ct-crypto-node/provider").createDefaultShieldedCryptoProvider();'
```

Run it on the Mac (the helper sandboxes this: no network, writes only to its
scratch directory), and in containers for the Linux packages, for example:

```sh
docker run --rm --platform linux/arm64 -v "$OUT:/t:ro" node:22-alpine sh -c '<the same steps, with P=linux-arm64-musl and ../ replaced by /t/>'
```

Run it for linux-x64-gnu and linux-arm64-gnu in `node:22-bookworm-slim`, and
for linux-x64-musl and linux-arm64-musl in `node:22-alpine`. CI also runs the
darwin-arm64, linux-x64-gnu and win32-x64 binaries it builds. darwin-x64 is
only format-checked.

Packing is reproducible: staging the same tag runs the same way again yields
byte-identical tarballs.

## 4. Publish

Check that npm publishes to npmjs.com: `npm config get @hathor:registry` must
be `undefined` or `https://registry.npmjs.org/`. Record the current dist-tags
(`npm view <package> dist-tags --json` for all 11), so step 5 can tell whether
`latest` moved.

Publish the tarballs, in this order, each with npm 2FA:

1. `@hathor/ct-crypto-provider`: the other three pin it exactly.
2. The seven `@hathor/ct-crypto-node-<platform>` packages.
3. `@hathor/ct-crypto-node`, which pulls them in through
   `optionalDependencies`.
4. `@hathor/ct-crypto-mobile`.
5. `@hathor/ct-crypto-wasm`.

```sh
npm publish "$OUT/<tarball>.tgz" --tag shielded --access public --provenance=false \
  --registry=https://registry.npmjs.org/
```

Publishing a tarball runs no lifecycle scripts and uploads exactly those
bytes. Never `npm publish` from a directory. From `packages/ct-crypto-node`,
for example, the package would go out without its `optionalDependencies`, so
no platform binary would install. The node, mobile and provider manifests
refuse a directory publish in `prepublishOnly` (`--ignore-scripts` bypasses
that). The `npm/<platform>/` directories and the downloaded artifacts have no
such guard.

npm never accepts the same version twice. If a publish fails part-way, fix
the cause and publish the remaining tarballs, using the same files (or
re-stage from the same tag runs the same way, which reproduces them
byte-for-byte). Never fix a published release in place: cut a new version.

## 5. Verify

- `npm view <package>@<version> dist.shasum` equals the sha1 of its tarball,
  for all 11.
- `shielded` points at the new version everywhere, and `latest` did not move
  on packages that already existed. A package published for the first time
  also gets `latest`: the registry adds it on a first publish whatever `--tag`
  says.
- `npm install @hathor/ct-crypto-node@<version>` in an empty directory, on
  macOS and in a linux-x64 container, loads and runs.
- Downstream: hathor-wallet-lib pins `@hathor/ct-crypto-provider` and
  `@hathor/ct-crypto-node` exactly. Bump them to the new version.
