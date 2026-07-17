/**
 * Jest config for the REAL wasm-crypto integration tests.
 *
 * Unlike jest.config.cjs (which redirects `./hathor_ct_crypto_wasm.js` to a
 * stub so the provider marshaling can be unit-tested without a build), this
 * config has NO moduleNameMapper — the tests load the ACTUAL built `pkg/`
 * artifact and exercise real cryptography.
 *
 * The wasm-pack `--target web` glue is native ESM (uses `import.meta.url`), so
 * these tests run as ESM with no transform. Invoke with:
 *
 *   NODE_OPTIONS=--experimental-vm-modules jest -c jest.real.config.cjs
 *
 * (see the `test:real` npm script). They SKIP with a clear message when the
 * built artifact is absent, so they never silently pass against the stub.
 */
/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/__tests__/real/**/*.realtest.mjs'],
  // No transform: the .mjs test + the pkg/ ESM glue load as native ES modules
  // under --experimental-vm-modules. Transforming to CJS would break
  // `import.meta.url` in the wasm-pack loader.
  transform: {},
};
