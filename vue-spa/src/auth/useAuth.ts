import { computed, ref } from 'vue'
import type { User } from 'oidc-client-ts'
import { userManager } from './userManager'

// Module-level state so every component sees the same user.
const user = ref<User | null>(null)
// `User.expired` is derived from the wall clock, so a computed over it would
// cache forever and never flip. Track expiry as its own reactive flag, driven
// by the UserManager timer below.
const expired = ref(false)

function setUser(next: User | null): void {
  user.value = next
  // User.expired is undefined when the token carries no expiry — not expired.
  expired.value = next?.expired ?? false
}

// Keep the ref in sync no matter who mutates the session — including a silent
// renew started from api/client.ts. UserManager raises userLoaded on every
// path that stores a user, so the ref is derived state and cannot drift.
userManager.events.addUserLoaded(setUser)
userManager.events.addUserUnloaded(() => setUser(null))
userManager.events.addAccessTokenExpired(() => {
  expired.value = true
})

// Shared definition of "signed in", so the router guard and the UI can't
// disagree about it.
export async function isSignedIn(): Promise<boolean> {
  const current = await userManager.getUser()
  return current !== null && !current.expired
}

// Renewal goes through the refresh token grant. Without a refresh token,
// oidc-client-ts falls back to a hidden-iframe prompt=none flow against
// silent_redirect_uri (which defaults to redirect_uri, i.e. /callback) — a
// page this example does not serve as a silent callback, so it would hang
// until a 10s timeout. Fail loudly with something actionable instead.
let renewal: Promise<User> | null = null

export function renew(): Promise<User> {
  // Single-flight: Signet rotates refresh tokens, so two concurrent grants
  // would replay an already-consumed token.
  renewal ??= (async () => {
    const current = await userManager.getUser()
    // Two distinct failures: there is no session at all, versus there is one
    // but Signet issued no refresh token. Conflating them sends the reader
    // chasing scope configuration when they simply need to sign in.
    if (!current) {
      throw new Error('not signed in — sign in again')
    }
    if (!current.refresh_token) {
      throw new Error(
        'no refresh token in this session — Signet must issue one for this client ' +
          '(register and request the offline_access scope), otherwise renewal is impossible',
      )
    }
    const renewed = await userManager.signinSilent()
    if (!renewed) {
      throw new Error('silent renew returned no user — sign in again')
    }
    return renewed
  })().finally(() => {
    renewal = null
  })
  return renewal
}

export function useAuth() {
  const isAuthenticated = computed(() => user.value !== null && !expired.value)

  async function loadUser(): Promise<User | null> {
    // getUser() does not raise userLoaded, so seed the ref explicitly.
    setUser(await userManager.getUser())
    return user.value
  }

  // Full-page redirect to Signet's /oauth/authorize with PKCE (S256) and
  // state. oidc-client-ts only sends a nonce if we supply one, and only
  // verifies id_token.nonce when it did — so mint one here.
  async function login(): Promise<void> {
    await userManager.signinRedirect({ nonce: crypto.randomUUID() })
  }

  // Completes the flow on /callback: validates state, exchanges the code
  // (with code_verifier) at /oauth/token, checks the nonce, fetches userinfo.
  async function handleCallback(): Promise<User> {
    return await userManager.signinRedirectCallback()
  }

  // grant_type=refresh_token against /oauth/token. Signet rotates refresh
  // tokens; oidc-client-ts stores the rotated one back automatically.
  async function refresh(): Promise<User> {
    return await renew()
  }

  // Signet exposes no end_session_endpoint, so there is no signoutRedirect()
  // to call: revoke both tokens at /oauth/revoke, then drop the local session.
  async function logout(): Promise<void> {
    let revokeError: unknown
    try {
      await userManager.revokeTokens()
    } catch (err) {
      // Still clear the local session, but do not pretend this succeeded —
      // a token we failed to revoke is still live at Signet.
      revokeError = err
    }
    await userManager.removeUser()
    setUser(null)
    if (revokeError) {
      throw new Error(
        `signed out locally, but revoking the tokens at Signet failed — they stay valid until they expire: ${
          revokeError instanceof Error ? revokeError.message : String(revokeError)
        }`,
      )
    }
  }

  return { user, isAuthenticated, loadUser, login, handleCallback, refresh, logout }
}
