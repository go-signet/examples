<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuth } from '../auth/useAuth'
import { userManager, signetUrl, clientId } from '../auth/userManager'

const router = useRouter()
const { isAuthenticated, loadUser, login } = useAuth()

const configMissing = !signetUrl || !clientId
const origin = window.location.origin
const discoveryError = ref('')
const loginError = ref('')
const probing = ref(false)

// Probe discovery up front: if this fails, the most likely cause is CORS being
// disabled on the Signet side, or a TLS certificate the browser does not trust
// — surface actionable guidance instead of leaving a cryptic error in the
// console. Going through the library's metadataService (rather than a raw
// fetch) normalizes the URL, applies the configured timeout, and caches the
// result, so sign-in reuses it instead of fetching the document a second time.
async function checkDiscovery() {
  if (configMissing) return
  probing.value = true
  discoveryError.value = ''
  try {
    await userManager.metadataService.getMetadata()
  } catch (err) {
    discoveryError.value =
      `Could not load ${signetUrl}/.well-known/openid-configuration from the browser ` +
      `(${err instanceof Error ? err.message : String(err)}). Two usual causes: Signet was ` +
      `not started with CORS_ENABLED=true and CORS_ALLOWED_ORIGINS=${origin}, or its TLS ` +
      `certificate is not trusted by the browser — open ${signetUrl} in a tab and accept it, ` +
      `then retry.`
  } finally {
    probing.value = false
  }
}

async function onRetry() {
  // The failure is usually fixed outside the app (trust the cert, restart
  // Signet with CORS on). Re-probe instead of forcing a full page reload —
  // metadataService caches only successes, so this really does re-fetch.
  loginError.value = ''
  await checkDiscovery()
}

onMounted(async () => {
  await loadUser()
  await checkDiscovery()
})

async function onLogin() {
  loginError.value = ''
  try {
    await login()
  } catch (err) {
    // signinRedirect() rejects before navigating away (discovery unreachable,
    // or crypto.subtle missing because the page is not a secure context).
    // Without this, the button would silently do nothing.
    loginError.value = err instanceof Error ? err.message : String(err)
  }
}
</script>

<template>
  <section>
    <h1>Sign in with Signet</h1>
    <p>
      Authorization Code + PKCE in the browser — a public client with no
      backend and no client secret.
    </p>

    <div v-if="configMissing" class="error">
      <p>
        <strong>Missing configuration.</strong> Copy <code>.env.example</code> to
        <code>.env</code> and set <code>VITE_SIGNET_URL</code> and
        <code>VITE_CLIENT_ID</code>, then restart the dev server.
      </p>
    </div>

    <div v-else-if="discoveryError" class="error">
      <p><strong>Signet unreachable:</strong> {{ discoveryError }}</p>
    </div>

    <div v-if="loginError" class="error">
      <p><strong>Sign-in failed:</strong> {{ loginError }}</p>
    </div>

    <div class="actions">
      <!-- Left enabled while discovery is failing: the fix is usually applied
           outside the app, and onLogin() surfaces any error on the page. -->
      <button :disabled="configMissing || probing" @click="onLogin">Sign in</button>
      <button v-if="discoveryError" :disabled="probing" @click="onRetry">
        {{ probing ? 'Retrying…' : 'Retry discovery' }}
      </button>
      <!-- A plain button, not a <button> wrapped in <router-link>: the latter
           renders <a><button>, which is invalid nested interactive content. -->
      <button v-if="isAuthenticated" @click="router.push({ name: 'profile' })">
        Go to profile (already signed in)
      </button>
    </div>
  </section>
</template>
