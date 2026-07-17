/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/__tests__/**/*.test.js'],
  // Coverage is collected only when run with --coverage (CI passes it). The
  // floor is enforced per-file on provider.js — the crypto-facing wrapper whose
  // behavior must stay tested (review finding L11). index.js is a platform
  // loader whose per-platform branches are unreachable on any single runner, so
  // it is collected for visibility but not thresholded.
  collectCoverageFrom: ['provider.js', 'index.js'],
  coverageThreshold: {
    './provider.js': { statements: 75, branches: 68, functions: 72, lines: 75 },
  },
};
