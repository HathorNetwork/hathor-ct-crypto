/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/__tests__/**/*.test.js'],
  transform: {
    '^.+\\.m?js$': 'babel-jest',
  },
  // The provider.js does `import * as wasm from './hathor_ct_crypto_wasm.js'`
  // — at test time we redirect that import to a stub via moduleNameMapper.
  moduleNameMapper: {
    '^\\./hathor_ct_crypto_wasm\\.js$': '<rootDir>/__tests__/wasm-stub.js',
  },
};
