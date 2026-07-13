<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useAuth } from '../auth/useAuth'
import { userManager, signetUrl, clientId } from '../auth/userManager'

const { isAuthenticated, loadUser, login } = useAuth()

const configMissing = !signetUrl || !clientId
const origin = window.location.origin
const discoveryError = ref('')
const loginError = ref('')

onMounted(async () => {
  await loadUser()
  if (configMissing) return

  // Probe discovery up front: if this fails, the most likely cause is CORS
  // being disabled on the Signet side — surface actionable guidance instead
  // of leaving a cryptic error in the browser console. Going through the
  // library's metadataService (rather than a raw fetch) normalizes the URL,
  // applies the configured timeout, and caches the result, so the sign-in
  // below reuses it instead of fetching the document a second time.
  try {
    await userManager.metadataService.getMetadata()
  } catch (err) {
    discoveryError.value =
      `Could not load ${signetUrl}/.well-known/openid-configuration from the browser ` +
      `(${err instanceof Error ? err.message : String(err)}). Make sure Signet is running ` +
      `and started with CORS_ENABLED=true and CORS_ALLOWED_ORIGINS=${origin}.`
  }
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
      <button :disabled="configMissing || !!discoveryError" @click="onLogin">Sign in</button>
      <router-link v-if="isAuthenticated" to="/profile">
        <button>Go to profile (already signed in)</button>
      </router-link>
    </div>
  </section>
</template>
