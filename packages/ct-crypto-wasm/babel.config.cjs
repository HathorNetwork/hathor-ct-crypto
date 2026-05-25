/**
 * Babel config for Jest only. The package itself ships as ESM (matching
 * wasm-pack's output); Jest's ts-jest / babel-jest pipeline transpiles
 * to CJS so tests can run in Node without `--experimental-vm-modules`.
 */
module.exports = {
  presets: [['@babel/preset-env', { targets: { node: 'current' } }]],
};
