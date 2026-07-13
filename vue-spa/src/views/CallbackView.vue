<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuth } from '../auth/useAuth'
import { settings } from '../auth/userManager'

const router = useRouter()
const { handleCallback } = useAuth()

const error = ref('')

// Only the code exchange can fail on a redirect URI mismatch. A missing state
// means the page was opened directly or reloaded, which needs different advice
// than "go check your client registration".
const staleState = computed(() => /state/i.test(error.value))

onMounted(async () => {
  try {
    await handleCallback()
    router.replace({ name: 'profile' })
  } catch (err) {
    // Shown instead of a blank page: covers provider errors echoed on the
    // redirect (access_denied, invalid_scope, ...), state mismatches, and
    // failed code exchanges.
    error.value = err instanceof Error ? err.message : String(err)
  }
})
</script>

<template>
  <section>
    <h1 v-if="!error">Signing you in…</h1>
    <div v-else class="error">
      <p><strong>Sign-in failed:</strong> {{ error }}</p>
      <p v-if="staleState">
        This page completes a sign-in exactly once — it cannot be reloaded or
        opened directly.
      </p>
      <p v-else>
        Check that <code>{{ settings.redirect_uri }}</code> is registered as a
        redirect URI for client <code>{{ settings.client_id }}</code> in Signet,
        and that the requested scopes are registered for it.
      </p>
      <router-link to="/">Back to sign-in</router-link>
    </div>
  </section>
</template>
