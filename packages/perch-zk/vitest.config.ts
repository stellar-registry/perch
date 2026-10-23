import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // bb.js spins up WASM workers; keep proving tests from competing.
    fileParallelism: false,
    testTimeout: 120_000,
  },
});
