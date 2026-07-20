#!/usr/bin/env node
'use strict';
//
// prepublishOnly guard (review finding M-6): refuse to publish unless every
// platform prebuild is present. A `npm publish` from a repo checkout has only
// the locally-built prebuild (one platform); npm silently drops the missing
// `prebuilds/*` entries from the tarball, shipping a package that fails to load
// on every other platform. Publish from the CI `npm-package-node` artifact,
// which assembles all targets. Mirrors ct-crypto-mobile's prepublishOnly.
//
const fs = require('fs');
const path = require('path');

// Must match build-node.yml's EXPECTED matrix and index.js's supported targets.
const EXPECTED = [
  'darwin-arm64',
  'darwin-x64',
  'linux-x64-glibc',
  'linux-arm64-glibc',
  'linux-x64-musl',
  'linux-arm64-musl',
  'win32-x64',
];

const pkgRoot = path.resolve(__dirname, '..');
const missing = EXPECTED.filter(
  (dir) => !fs.existsSync(path.join(pkgRoot, 'prebuilds', dir, 'ct-crypto.node'))
);

if (missing.length) {
  console.error(
    'refusing to publish @hathor/ct-crypto-node — missing prebuilds: ' +
      missing.join(', ') +
      '\n  Publish from the CI npm-package-node artifact (all platforms), ' +
      'not a repo checkout.'
  );
  process.exit(1);
}
console.log('[check-prebuilds] all ' + EXPECTED.length + ' platform prebuilds present.');
