<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuth } from '../auth/useAuth'
import { callApi } from '../api/client'

const router = useRouter()
const { user, loadUser, refresh, logout } = useAuth()

const busy = ref(false)
const actionError = ref('')
const apiResult = ref('')

const idTokenClaims = computed(() =>
  user.value?.id_token ? decodeJwtPayload(user.value.id_token) : null,
)

const expiresAt = computed(() =>
  user.value?.expires_at ? new Date(user.value.expires_at * 1000).toLocaleString() : '',
)

// Display-only decode of the ID token payload — nothing here is a security
// check. oidc-client-ts does NOT verify the ID token's signature, iss, aud, or
// exp; the token is trusted because it came straight from the token endpoint
// over TLS (OIDC Core 3.1.3.7 clause 8). Decode via TextDecoder, not a bare
// atob(), which would mangle any non-ASCII claim into mojibake.
function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  try {
    const payload = jwt.split('.')[1]!
    const binary = atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return null
  }
}

onMounted(loadUser)

async function run(action: () => Promise<void>) {
  busy.value = true
  actionError.value = ''
  apiResult.value = ''
  try {
    await action()
  } catch (err) {
    actionError.value = err instanceof Error ? err.message : String(err)
  } finally {
    busy.value = false
  }
}

const onRefresh = () => run(async () => void (await refresh()))

const onCallApi = (path: string) =>
  run(async () => {
    apiResult.value = JSON.stringify(await callApi(path), null, 2)
  })

const onLogout = () =>
  run(async () => {
    try {
      await logout()
    } finally {
      // logout() clears the local session even when revocation fails, so leave
      // either way — but let run() surface the revocation error.
      router.replace({ name: 'home' })
    }
  })
</script>

<template>
  <section v-if="user">
    <h1>Profile</h1>

    <p>
      Signed in as <strong>{{ user.profile.email ?? user.profile.sub }}</strong>
      · scopes: <code>{{ user.scopes.join(' ') }}</code>
      · access token expires: <strong>{{ expiresAt }}</strong>
    </p>

    <div class="actions">
      <button :disabled="busy" @click="onRefresh">Refresh token</button>
      <button :disabled="busy" @click="onCallApi('/api/profile')">Call API (/api/profile)</button>
      <button :disabled="busy" @click="onCallApi('/api/data')">Call API (/api/data)</button>
      <button :disabled="busy" @click="onLogout">Sign out</button>
    </div>

    <div v-if="actionError" class="error">
      <p>{{ actionError }}</p>
    </div>

    <template v-if="apiResult">
      <h2>API response</h2>
      <pre>{{ apiResult }}</pre>
    </template>

    <h2>ID token claims</h2>
    <pre>{{ JSON.stringify(idTokenClaims, null, 2) }}</pre>

    <h2>user.profile (ID token claims + userinfo, merged)</h2>
    <pre>{{ JSON.stringify(user.profile, null, 2) }}</pre>
  </section>

  <section v-else>
    <h1>Not signed in</h1>
    <p>The session ended. <router-link to="/">Back to sign-in</router-link>.</p>
  </section>
</template>
