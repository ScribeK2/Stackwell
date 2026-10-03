import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// Dev: run `go run ./cmd/stackwell -port 7777` alongside `npm run dev`.
export default defineConfig({
  plugins: [svelte(), tailwindcss()],
  server: { proxy: { '/api': 'http://127.0.0.1:7777' } },
})
