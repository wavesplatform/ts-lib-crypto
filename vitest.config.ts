// vitest.config.ts
import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  resolve: {
    alias: [
      {
        find: '@noble/curves/bls12-381',
        replacement: path.resolve(__dirname, 'node_modules/@noble/curves/bls12-381.js'),
      },
      {
        find: '@noble/hashes/hkdf',
        replacement: path.resolve(__dirname, 'node_modules/@noble/hashes/hkdf.js'),
      },
      {
        find: '@noble/hashes/sha2',
        replacement: path.resolve(__dirname, 'node_modules/@noble/hashes/sha2.js'),
      },
      {
        find: '@noble/curves/utils',
        replacement: path.resolve(__dirname, 'node_modules/@noble/curves/utils.js'),
      },
    ],
  },
  test: {
    environment: 'node',
    globals: true,
    include: ['test/**/*.test.ts', 'test/**/*.spec.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    deps: {
      inline: ['@noble/curves', '@noble/hashes'],
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/libs/**', '**/*.d.ts'],
    },
  },
})
