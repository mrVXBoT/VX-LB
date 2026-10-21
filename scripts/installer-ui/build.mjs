import { build } from 'esbuild'
await build({
  entryPoints: ['renderer.mjs'], bundle: true, platform: 'node', format: 'esm',
  target: 'node18', minify: true, legalComments: 'eof', outfile: 'renderer.bundle.mjs',
  banner: { js: 'import { createRequire } from "node:module"; const require = createRequire(import.meta.url);' },
})
