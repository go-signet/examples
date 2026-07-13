import { beforeEach, describe, expect, it, vi } from 'vitest'

// Mock at the oidc-client-ts boundary so the real userManager.ts module runs:
// the settings it passes to the UserManager constructor are captured for
// assertion, and the returned instance is fully mocked.
const manager = vi.hoisted(() => {
  const handlers = {
    userLoaded: [] as Array<(u: unknown) => void>,
    userUnloaded: [] as Array<() => void>,
    accessTokenExpired: [] as Array<() => void>,
  }
  return {
    handlers,
    settings: undefined as Record<string, unknown> | undefined,
    getUser: vi.fn(),
    signinRedirect: vi.fn(),
    signinRedirectCallback: vi.fn(),
    signinSilent: vi.fn(),
    revokeTokens: vi.fn(),
    removeUser: vi.fn(),
    signoutRedirect: vi.fn(),
    events: {
      addUserLoaded: vi.fn((cb: (u: unknown) => void) => handlers.userLoaded.push(cb)),
      addUserUnloaded: vi.fn((cb: () => void) => handlers.userUnloaded.push(cb)),
      addAccessTokenExpired: vi.fn((cb: () => void) => handlers.accessTokenExpired.push(cb)),
    },
  }
})

vi.mock('oidc-client-ts', () => ({
  UserManager: vi.fn(function (settings: Record<string, unknown>) {
    manager.settings = settings
    return manager
  }),
  WebStorageStateStore: vi.fn(function (args: { store: unknown }) {
    return { store: args.store }
  }),
}))

const sessionStore = { kind: 'session' }
vi.stubGlobal('window', {
  location: { origin: 'http://localhost:5173' },
  sessionStorage: sessionStore,
})
vi.stubGlobal('crypto', { randomUUID: () => 'test-nonce' })

const { settings } = await import('./userManager')
const { useAuth, isSignedIn } = await import('./useAuth')
const { callApi, ApiError } = await import('../api/client')

// A signed-in user with a live access token, as UserManager would return it.
const signedIn = (over: Record<string, unknown> = {}) => ({
  access_token: 'tok-1',
  refresh_token: 'refresh-1',
  expired: false,
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  manager.getUser.mockResolvedValue(null)
  manager.signinSilent.mockReset()
  manager.revokeTokens.mockResolvedValue(undefined)
  manager.removeUser.mockResolvedValue(undefined)
})

describe('settings', () => {
  it('requests the code response type, the registered scopes, and keeps all state in sessionStorage', () => {
    // Requesting the code response type is what makes oidc-client-ts apply
    // PKCE (S256) — required by Signet for public clients.
    expect(settings.response_type).toBe('code')
    expect(settings.scope).toBe('openid profile email')
    expect(settings.redirect_uri).toBe('http://localhost:5173/callback')
    // Signet has no check_session_iframe, so session monitoring must be off.
    expect(settings.monitorSession).toBe(false)
    // stateStore holds the in-flight PKCE code_verifier and defaults to
    // localStorage, which would outlive the tab — it must be set explicitly.
    expect(settings.userStore).toEqual({ store: sessionStore })
    expect(settings.stateStore).toEqual({ store: sessionStore })
    // The refresh token is the one worth stealing: revoke it first, because
    // oidc-client-ts stops at the first failure.
    expect(settings.revokeTokenTypes).toEqual(['refresh_token', 'access_token'])
    expect(manager.settings).toBe(settings)
  })
})

describe('login', () => {
  it('redirects with a nonce, which oidc-client-ts only sends (and verifies) when supplied', async () => {
    await useAuth().login()
    expect(manager.signinRedirect).toHaveBeenCalledExactlyOnceWith({ nonce: 'test-nonce' })
  })
})

describe('logout', () => {
  it('revokes tokens before removing the user, and never calls signoutRedirect', async () => {
    const { logout, loadUser, user } = useAuth()
    manager.getUser.mockResolvedValue(signedIn())
    await loadUser()
    expect(user.value).not.toBeNull() // the ref is populated, so the assert below is real

    await logout()

    expect(manager.revokeTokens).toHaveBeenCalledTimes(1)
    expect(manager.removeUser).toHaveBeenCalledTimes(1)
    expect(manager.revokeTokens.mock.invocationCallOrder[0]!).toBeLessThan(
      manager.removeUser.mock.invocationCallOrder[0]!,
    )
    // Signet publishes no end_session_endpoint — a redirect sign-out would fail.
    expect(manager.signoutRedirect).not.toHaveBeenCalled()
    expect(user.value).toBeNull()
  })

  it('clears the local session but reports failure when revocation fails', async () => {
    manager.revokeTokens.mockRejectedValueOnce(new Error('network down'))

    // A token we failed to revoke is still live at Signet — do not report a
    // clean sign-out.
    await expect(useAuth().logout()).rejects.toThrow(/revoking the tokens at Signet failed/)
    expect(manager.removeUser).toHaveBeenCalledTimes(1)
  })
})

describe('session state', () => {
  it('tracks a renewal started anywhere, including from inside the API client', () => {
    const { user, isAuthenticated } = useAuth()

    // UserManager raises userLoaded on every path that stores a user, so a
    // silent renew triggered by callApi's 401 retry — which never touches
    // useAuth — must still update the shared ref.
    manager.handlers.userLoaded.forEach((cb) => cb(signedIn({ access_token: 'tok-2' })))

    expect(user.value?.access_token).toBe('tok-2')
    expect(isAuthenticated.value).toBe(true)
  })

  it('goes unauthenticated when the access token expires, without a reassignment', () => {
    const { user, isAuthenticated } = useAuth()
    manager.handlers.userLoaded.forEach((cb) => cb(signedIn()))
    expect(isAuthenticated.value).toBe(true)

    // `User.expired` is wall-clock derived, so a computed over it would cache
    // forever. The library's expiry timer is what drives this.
    manager.handlers.accessTokenExpired.forEach((cb) => cb())

    expect(isAuthenticated.value).toBe(false)
    expect(user.value).not.toBeNull() // still there, just not usable
  })
})

describe('isSignedIn', () => {
  it('rejects an expired user, so the route guard agrees with the UI', async () => {
    manager.getUser.mockResolvedValue(signedIn({ expired: true }))
    await expect(isSignedIn()).resolves.toBe(false)

    manager.getUser.mockResolvedValue(signedIn())
    await expect(isSignedIn()).resolves.toBe(true)
  })
})

describe('refresh', () => {
  it('fails with actionable guidance rather than falling back to a hidden iframe', async () => {
    // Without a refresh token, oidc-client-ts would silently try a prompt=none
    // iframe against silent_redirect_uri (defaulted to /callback) and hang.
    manager.getUser.mockResolvedValue(signedIn({ refresh_token: undefined }))

    await expect(useAuth().refresh()).rejects.toThrow(/no refresh token/)
    expect(manager.signinSilent).not.toHaveBeenCalled()
  })

  it('is single-flight, so concurrent callers never replay a rotated refresh token', async () => {
    manager.getUser.mockResolvedValue(signedIn())
    manager.signinSilent.mockResolvedValue(signedIn({ access_token: 'tok-2' }))

    const { refresh } = useAuth()
    await Promise.all([refresh(), refresh(), refresh()])

    // Signet rotates refresh tokens: a second concurrent grant would present
    // an already-consumed token.
    expect(manager.signinSilent).toHaveBeenCalledTimes(1)
  })
})

describe('callApi', () => {
  const okResponse = (body: unknown) => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify(body),
  })
  const unauthorized = {
    ok: false,
    status: 401,
    text: async () => 'invalid or expired token',
  }

  it('sends the Bearer token and returns the JSON body', async () => {
    manager.getUser.mockResolvedValue(signedIn())
    const fetchMock = vi.fn().mockResolvedValue(okResponse({ user_id: 'u1' }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(callApi('/api/profile')).resolves.toEqual({ user_id: 'u1' })
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith('/api/profile', {
      headers: { Authorization: 'Bearer tok-1' },
    })
    expect(manager.signinSilent).not.toHaveBeenCalled()
  })

  it('on 401, silently renews once and retries with the new token', async () => {
    manager.getUser.mockResolvedValue(signedIn({ access_token: 'stale' }))
    manager.signinSilent.mockResolvedValue(signedIn({ access_token: 'fresh' }))
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(unauthorized)
      .mockResolvedValueOnce(okResponse({ message: 'hi' }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(callApi('/api/profile')).resolves.toEqual({ message: 'hi' })
    expect(manager.signinSilent).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock).toHaveBeenLastCalledWith('/api/profile', {
      headers: { Authorization: 'Bearer fresh' },
    })
  })

  it('throws when the retry after renewal is still 401', async () => {
    manager.getUser.mockResolvedValue(signedIn({ access_token: 'stale' }))
    manager.signinSilent.mockResolvedValue(signedIn({ access_token: 'still-bad' }))
    const fetchMock = vi.fn().mockResolvedValue(unauthorized)
    vi.stubGlobal('fetch', fetchMock)

    await expect(callApi('/api/profile')).rejects.toThrow(ApiError)
    // Renewal is attempted exactly once — no retry loop.
    expect(manager.signinSilent).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('reports a non-JSON 200 as an ApiError instead of a raw SyntaxError', async () => {
    // Served without the /api proxy, an SPA history fallback answers 200 with
    // index.html.
    manager.getUser.mockResolvedValue(signedIn())
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, status: 200, text: async () => '<!doctype html>' }),
    )

    await expect(callApi('/api/profile')).rejects.toThrow(/expected JSON/)
  })

  it('throws when no user is signed in', async () => {
    manager.getUser.mockResolvedValue(null)
    await expect(callApi('/api/profile')).rejects.toThrow('not signed in')
  })
})
