import { defineConfig } from 'tsup'

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['cjs'],
    outDir: 'dist/cjs',
    outExtension: () => ({ js: '.cjs' }),
    sourcemap: true,
    dts: false,
    clean: false,
  },
  {
    entry: ['src/index.ts'],
    format: ['esm'],
    outDir: 'dist/esm',
    outExtension: () => ({ js: '.mjs' }),
    sourcemap: true,
    dts: false,
    clean: false,
  },
])
