// Serves the benchmark page cross-origin isolated (COOP/COEP), so bb.js can
// use threads, and lets it import the package build and the repo's fixtures.
export default {
  server: {
    port: 5199,
    strictPort: true,
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
    fs: { allow: ['../../../..'] },
  },
  optimizeDeps: {
    exclude: ['@aztec/bb.js', '@noir-lang/noirc_abi', '@noir-lang/acvm_js'],
    esbuildOptions: { target: 'esnext' },
  },
};
