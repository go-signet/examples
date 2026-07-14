import { env, userManager } from '../auth/userManager'
import { renew } from '../auth/useAuth'

// Same trimming accessor the OAuth settings use: an untrimmed base would build
// a request URL with a leading space and fail as an opaque fetch error.
const base: string = env('VITE_API_BASE')

export class ApiError extends Error {
  constructor(
    readonly status: number,
    body: string,
  ) {
    super(`API responded ${status}: ${body.trim() || '(empty body)'}`)
    this.name = 'ApiError'
  }
}

function request(path: string, accessToken: string): Promise<Response> {
  return fetch(`${base}${path}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
}

// Calls the resource server with a Bearer token. On 401, renews once via the
// refresh token grant and retries; a second failure is thrown. Renewal goes
// through the shared renew() so the signed-in user stays in sync with the UI
// and concurrent calls don't each burn a rotated refresh token.
export async function callApi(path: string): Promise<unknown> {
  const user = await userManager.getUser()
  if (!user) {
    throw new Error('not signed in')
  }

  let res = await request(path, user.access_token)

  if (res.status === 401) {
    const renewed = await renew()
    res = await request(path, renewed.access_token)
  }

  if (!res.ok) {
    throw new ApiError(res.status, await res.text())
  }

  // A 200 is not necessarily JSON: served without the /api proxy, an SPA
  // history fallback answers with index.html.
  const body = await res.text()
  try {
    return JSON.parse(body)
  } catch {
    throw new ApiError(res.status, `expected JSON, got: ${body.slice(0, 100)}`)
  }
}
