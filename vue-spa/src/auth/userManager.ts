import { UserManager, WebStorageStateStore, type UserManagerSettings } from 'oidc-client-ts'

// Trim every env value: a stray space survives a copy-paste into .env and then
// fails deep inside OAuth (an authority that won't resolve, a client_id Signet
// won't match) with an error that points nowhere near the real cause.
const env = (key: string): string => (import.meta.env[key] ?? '').trim()

export const signetUrl: string = env('VITE_SIGNET_URL')
export const clientId: string = env('VITE_CLIENT_ID')

// Requested scopes must be a subset of the scopes registered for the client
// in Signet. Add offline_access here only after registering it on the client.
export const scope = 'openid profile email'

export const settings: UserManagerSettings = {
  authority: signetUrl,
  client_id: clientId,
  // Derived from the live origin unless overridden, so opening the app on
  // 127.0.0.1 sends a 127.0.0.1 redirect_uri rather than a mismatched one.
  redirect_uri: env('VITE_REDIRECT_URI') || `${window.location.origin}/callback`,
  // Requesting the code response type is what makes oidc-client-ts apply
  // PKCE (S256) — Signet rejects public clients that omit it.
  response_type: 'code',
  scope,
  // Both stores must be set. userStore holds the tokens; stateStore holds the
  // in-flight PKCE code_verifier + state + nonce, and defaults to
  // localStorage — which would outlive the tab and be shared across tabs.
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
  // Signet's discovery document has no check_session_iframe — session
  // monitoring would fail, so renewal goes through the refresh token grant.
  monitorSession: false,
  automaticSilentRenew: false,
  // Merge /oauth/userinfo claims into user.profile after sign-in.
  loadUserInfo: true,
  // Order matters: oidc-client-ts revokes these sequentially and stops at the
  // first failure. Revoke the refresh token first — it is the token worth
  // stealing, and a failure on the access token must not leave it alive.
  revokeTokenTypes: ['refresh_token', 'access_token'],
}

export const userManager = new UserManager(settings)
