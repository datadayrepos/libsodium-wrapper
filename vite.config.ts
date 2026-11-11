import fs from 'node:fs'
import path from 'node:path'
import { defineConfig } from 'vite'
import topLevelAwait from 'vite-plugin-top-level-await'
import wasm from 'vite-plugin-wasm'

export default defineConfig(({ command }) => ({
  plugins: [
    wasm(),
    topLevelAwait(), // Allows use of 'await' at the top level
  ],
  build: {
    copyPublicDir: false,
    lib: {
      entry: path.resolve(__dirname, 'src/index.ts'),
      name: 'libsodium',
      formats: ['es'], // Generating only ES module
      fileName: () => 'esm/index.js',
    },
    rollupOptions: {
      external: [], // specify external dependencies here if any
      plugins: [
      ],
      // No need to specify globals or format since it's only ES module
    },
  },
  server: command === 'serve' ? {
    port: Number.parseInt('4044', 10), // Converts the string to an integer
    host: '0.0.0.0',
    https: {
      key: fs.readFileSync('./.cert/key.pem'),
      cert: fs.readFileSync('./.cert/cert.pem'),
    },

  } : undefined,
  // Set the public directory to 'test' so it serves static files from there
  publicDir: 'test',
}))
