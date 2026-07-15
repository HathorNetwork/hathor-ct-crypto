/**
 * Loader for @hathor/ct-crypto-node NAPI addon.
 * Loads the prebuilt .node binary for the current platform.
 */
'use strict';

const path = require('path');
const os = require('os');

/**
 * NEW-02: on Linux the C ABI is not captured by os.platform()/os.arch() — a
 * glibc-linked `.so` cannot be dlopen'd on a musl system (e.g. Alpine, which is
 * wallet-headless's official Docker base) and vice-versa. Detect libc so we
 * resolve `linux-x64-glibc` vs `linux-x64-musl` instead of a single
 * `linux-x64` that silently ships the wrong binary.
 */
function detectLibc() {
  // The most reliable in-process signal: the Node report exposes the runtime
  // glibc version on glibc systems, and leaves it undefined on musl.
  try {
    const report = process.report.getReport();
    const glibc = report && report.header && report.header.glibcVersionRuntime;
    return glibc ? 'glibc' : 'musl';
  } catch (_) {
    // Fall back to the toolchain marker in process.config.
    try {
      // eslint-disable-next-line global-require
      if (process.config && process.config.variables && process.config.variables.libc) {
        return process.config.variables.libc === 'musl' ? 'musl' : 'glibc';
      }
    } catch (_) { /* ignore */ }
    return 'glibc';
  }
}

function prebuildDir() {
  const platform = os.platform();
  const arch = os.arch();
  if (platform === 'linux') {
    return `linux-${arch}-${detectLibc()}`;
  }
  // darwin / win32: ABI is determined by platform+arch alone.
  return `${platform}-${arch}`;
}

function loadNative() {
  const dir = prebuildDir();
  const prebuildPath = path.join(__dirname, 'prebuilds', dir, 'ct-crypto.node');

  try {
    return require(prebuildPath);
  } catch (e) {
    throw new Error(
      `Failed to load @hathor/ct-crypto-node native addon for ${dir}.\n` +
      `Tried: ${prebuildPath}\n` +
      `Error: ${e.message}\n\n` +
      `Make sure the prebuild for your platform is included in the package.\n` +
      `Supported: darwin-arm64, darwin-x64, ` +
      `linux-x64-glibc, linux-arm64-glibc, linux-x64-musl, linux-arm64-musl, win32-x64`
    );
  }
}

// Load and re-export all NAPI functions
const native = loadNative();
module.exports = native;
module.exports.loadNative = loadNative;
