import { defineConfig } from '@playwright/test'

// Seam 2: drives the real Go binary with the built UI embedded.
// `npm run e2e` builds the UI first; the binary is built here.
export default defineConfig({
  testDir: 'e2e',
  workers: 1, // one shared server with one active Case: tests must not interleave
  use: { baseURL: 'http://127.0.0.1:4790' },
  webServer: {
    command:
      'cd .. && go build -o build/e2e-stackwell ./cmd/stackwell && ' +
      'XDG_DATA_HOME=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d) XDG_RUNTIME_DIR=$(mktemp -d) build/e2e-stackwell --no-browser --no-keyring -update-url= -port 4790',
    url: 'http://127.0.0.1:4790/api/health',
    reuseExistingServer: false,
  },
})
