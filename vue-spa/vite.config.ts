/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// go-webservice (:8080) has no CORS — the dev proxy makes /api requests
// same-origin so the browser never needs it.
const proxy = {
  '/api': {
    target: 'http://localhost:8080',
    changeOrigin: true,
  },
}

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    // The redirect URI and Signet's CORS origin are registered for this exact
    // port — silently falling back to 5174 would break both.
    strictPort: true,
    proxy,
  },
  // vite preview defaults to 4173, a different origin than the one registered
  // with Signet. Pin it so the production bundle can complete a sign-in too.
  preview: {
    port: 5173,
    strictPort: true,
    proxy,
  },
  test: {
    environment: 'node',
    // Pin the browser-facing config the tests assert on. Without this, a
    // developer's own .env (which the README tells them to create) would leak
    // in through Vite's env loading and fail the suite.
    env: {
      VITE_SIGNET_URL: 'https://signet.test',
      VITE_CLIENT_ID: 'spa-client',
      VITE_REDIRECT_URI: '',
      VITE_API_BASE: '',
    },
  },
})
