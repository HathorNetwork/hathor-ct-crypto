#!/usr/bin/env node
'use strict';
//
// Post-build step: copy the freshly-built cdylib into
// prebuilds/<platform-dir>/ct-crypto.node, where index.js's loader looks for it.
// Without this, `npm run build` (cargo build) leaves the addon only in
// target/release/ and the documented local build produces nothing loadable
// (review finding L7). The prebuild-dir naming MUST match index.js:prebuildDir().
//
const fs = require('fs');
const os = require('os');
const path = require('path');

function detectLibc() {
  // Mirror index.js: musl vs glibc on Linux (best-effort).
  if (os.platform() !== 'linux') return '';
  try {
    const report = typeof process.report?.getReport === 'function' ? process.report.getReport() : null;
    const glibcVersionRuntime = report?.header?.glibcVersionRuntime;
    if (!glibcVersionRuntime) return 'musl';
  } catch (_) { /* ignore */ }
  return 'glibc';
}

function prebuildDir() {
  const platform = os.platform();
  const arch = os.arch();
  if (platform === 'linux') return `linux-${arch}-${detectLibc()}`;
  return `${platform}-${arch}`; // darwin / win32
}

// cargo names the cdylib libhathor_ct_crypto.{dylib,so} or hathor_ct_crypto.dll.
function builtArtifact(releaseDir) {
  const candidates = [
    'libhathor_ct_crypto.dylib', // macOS
    'libhathor_ct_crypto.so',    // Linux
    'hathor_ct_crypto.dll',      // Windows
  ];
  for (const name of candidates) {
    const p = path.join(releaseDir, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function main() {
  const pkgRoot = path.resolve(__dirname, '..');
  // Cargo target dir: workspace root is two levels up from the package.
  const targetRoot = path.resolve(pkgRoot, '..', '..', 'target');
  // Prefer release (npm run build) over debug (npm run build:debug).
  const src = builtArtifact(path.join(targetRoot, 'release')) ||
              builtArtifact(path.join(targetRoot, 'debug'));
  if (!src) {
    console.error(
      `[copy-prebuild] no built cdylib found in ${targetRoot}/{release,debug}.\n` +
      `  Run \`npm run build\` (cargo build --features napi --release) first.`
    );
    process.exit(1);
  }
  const dir = prebuildDir();
  const destDir = path.join(pkgRoot, 'prebuilds', dir);
  fs.mkdirSync(destDir, { recursive: true });
  const dest = path.join(destDir, 'ct-crypto.node');
  fs.copyFileSync(src, dest);
  console.log(`[copy-prebuild] ${path.relative(pkgRoot, src)} -> ${path.relative(pkgRoot, dest)}`);
}

main();
