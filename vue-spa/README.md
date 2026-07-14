# Vue SPA — Browser-Only Login (`oidc-client-ts`)

A minimal **Vue 3 + Vite + TypeScript** single-page app that signs in against
Signet directly from the browser — no backend of its own. It is the
**public-client** counterpart to [go-oidc](../go-oidc/): where go-oidc runs
the Authorization Code flow server-side (a confidential client that can hold
a secret), this example holds tokens in the browser and relies on **PKCE**
instead of a secret. Use it as the starting point for integrating Signet as
an SSO provider into any SPA framework.

Package management and script running use [Bun](https://bun.sh).

## OAuth Flow

**Authorization Code + PKCE (S256)**, executed entirely in the browser by
[`oidc-client-ts`](https://github.com/authts/oidc-client-ts):

- **PKCE (S256)** — mandatory: Signet rejects public clients without it
  (`invalid_request: pkce required for public clients`). `oidc-client-ts`
  enables it automatically for `response_type=code`.
- **State** — CSRF protection on the redirect back to `/callback`, generated
  and verified by the library.
- **Nonce** — replay protection tied to the ID token. `oidc-client-ts` only
  sends a `nonce` (and only checks `id_token.nonce` on the way back) **if the
  caller supplies one**, so this example mints one explicitly in
  [`useAuth.ts`](src/auth/useAuth.ts). Calling `signinRedirect()` with no
  arguments — as most tutorials do — silently gets you no nonce protection at
  all.
- **Refresh token grant** — the **Refresh token** button posts
  `grant_type=refresh_token` to `/oauth/token`. Signet **rotates** refresh
  tokens; the rotated token is stored back automatically. Renewal is
  single-flight, because two concurrent grants would replay an
  already-consumed token.
- **Revocation on sign-out** — Signet's discovery document has **no
  `end_session_endpoint`**, so there is no redirect-based logout. Sign-out
  revokes both tokens at `/oauth/revoke` and clears the local session
  (`removeUser()`); the SPA never calls `signoutRedirect()`. It also has no
  `check_session_iframe`, so session monitoring is disabled
  (`monitorSession: false`).

All of this works without a backend because Signet serves `/oauth/*` and
`/.well-known/*` with CORS headers (when enabled — see below).

### ⚠️ The ID token is not fully validated

`oidc-client-ts` **does not verify the ID token's signature**, nor its `iss`,
`aud`, or `exp` claims — its JWT helper is annotated *"doesn't validate the
token"*, and it never fetches the JWKS. It checks only that `sub` is present
and that the `nonce` matches.

Only part of that is sanctioned by the spec.
[OIDC Core §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
clause 6 permits TLS server validation to stand in for **the signature check**
when the ID token came directly from the token endpoint — which it did here.
But clauses 2, 3, and 9 still say the client **MUST** validate `iss`, `aud`,
and `exp`, and TLS is not a substitute for those. `oidc-client-ts` does not do
them, so **this SPA is not a fully conformant OIDC client**. Treat that as a
limitation of the library, not as a design decision this example made.

Practically: **do not use `id_token` claims for anything security-sensitive.**
Use them to render a name and an avatar. Do not use them to decide what a user
is allowed to do — that decision belongs on the server, which must validate the
access token itself (that is exactly what [go-webservice](../go-webservice/)
and [go-jwks](../go-jwks/) demonstrate). And the moment an `id_token` reaches
your app from anywhere other than that direct token-endpoint response, it is
entirely unvalidated input.

If you need real ID token guarantees in the browser, either verify it yourself
against the JWKS (`jwks_uri` is in the discovery document) or move the flow
server-side — [go-oidc](../go-oidc/) does the full check via `verifier.Verify`:
signature against JWKS, plus `iss` / `aud` / `exp`, plus `at_hash`.

## Prerequisites

- Bun 1.2+
- A running Signet server with CORS enabled and a **public** client
  registered (next section)
- Optional: [go-webservice](../go-webservice/) on `:8080` for the
  **Call API** buttons

## Signet Setup

1. **Enable CORS** so the browser may call the token, userinfo, and revoke
   endpoints directly:

   ```bash
   CORS_ENABLED=true
   CORS_ALLOWED_ORIGINS=http://localhost:5173
   ```

   Without this, every request after the redirect back fails in the browser.
   The SPA loads the discovery document on startup and shows this exact
   guidance on the page when it cannot reach Signet.

   **Origins are matched exactly.** `http://localhost:5173` and
   `http://127.0.0.1:5173` are *different* origins to both CORS and OAuth
   redirect-URI matching, even though they reach the same server. Whichever
   one you actually type into the browser is the one to register here — and
   in the client's redirect URI below.

2. **Register a public client** (no client secret). A confidential client's
   credentials cannot be used here — any secret shipped in a JavaScript
   bundle is public by definition, which is why this example must not and
   does not contain one.

3. **Register the redirect URI** `http://localhost:5173/callback` on that
   client.

4. **Scopes**: the requested scopes must be a subset of the client's
   registered scopes. The example requests `openid profile email`. Signet
   accepts `openid`, `profile`, `email`, and `offline_access` — nothing else.
   To make refresh more spec-conventional, register `offline_access` on the
   client and add it to `scope` in
   [`src/auth/userManager.ts`](src/auth/userManager.ts).

## Environment Variables

Vite only exposes variables prefixed with `VITE_` to browser code, so this
example uses `VITE_SIGNET_URL` / `VITE_CLIENT_ID` where the Go and Python
examples use `SIGNET_URL` / `CLIENT_ID`. The prefix is a deliberate guard:
everything it exposes is compiled into the public bundle — which is also why
there is no `VITE_CLIENT_SECRET` and never should be.

| Variable            | Required | Description                                                            |
| ------------------- | -------- | ---------------------------------------------------------------------- |
| `VITE_SIGNET_URL`   | Yes      | Signet issuer URL (discovery: `$VITE_SIGNET_URL/.well-known/openid-configuration`) |
| `VITE_CLIENT_ID`    | Yes      | OAuth 2.0 client identifier of the **public** client                   |
| `VITE_REDIRECT_URI` | No       | Defaults to `<origin>/callback` (`http://localhost:5173/callback` in dev) |
| `VITE_API_BASE`     | No       | Base URL for API calls. Empty (default) = same-origin `/api/...`, proxied by Vite to `http://localhost:8080` |

## Usage

```bash
cd vue-spa
cp .env.example .env   # then set VITE_SIGNET_URL and VITE_CLIENT_ID
bun install
bun run dev
```

Open <http://localhost:5173> and click **Sign in**. After authenticating at
Signet you land on `/profile`, which shows the ID token claims and userinfo
plus buttons for **Refresh token**, **Call API**, and **Sign out**.

To see the API calls succeed, start the resource server in another terminal:

```bash
cd go-webservice
go run main.go   # listens on :8080; Vite proxies /api there
```

`go-webservice` has no CORS of its own — the Vite dev server proxy
(`vite.config.ts`, `/api` → `http://localhost:8080`) makes those requests
same-origin, so the Go example needs no changes.

> [!IMPORTANT]
> **Port collision with Signet.** `go-webservice` hard-codes `:8080` and has no
> `PORT` override. If your Signet is *also* on `:8080` — a common local setup —
> then `go-webservice` cannot bind, and the Vite proxy's plaintext request
> reaches Signet's listener instead. If Signet is serving TLS there, the
> **Call API** buttons fail with:
>
> ```
> API responded 400: Client sent an HTTP request to an HTTPS server.
> ```
>
> That error means you are talking to Signet, not to the resource server. Run
> Signet on a different port (and update `VITE_SIGNET_URL` to match), which
> frees `:8080` for `go-webservice` and leaves the proxy config as shipped.

Other scripts:

```bash
bun run test        # Vitest unit tests (note: `bun test` cannot run these —
                    # Bun's built-in runner does not implement vi.mock)
bun run typecheck   # vue-tsc
bun run build       # typecheck + production bundle in dist/
bun run preview     # serve the production bundle, also on :5173
```

`preview` is pinned to port 5173 (Vite's default is 4173) so the production
bundle uses the same origin and redirect URI you already registered.

## Routes

| Route       | Description                                                              |
| ----------- | ------------------------------------------------------------------------ |
| `/`         | Sign-in page; loads discovery and shows CORS/config guidance on failure  |
| `/callback` | Completes the code exchange (PKCE verifier), then redirects to `/profile`; renders a readable error instead of a blank page on failure |
| `/profile`  | ID token claims + userinfo; Refresh token / Call API / Sign out buttons. Guarded — unauthenticated visits go back to `/` |

## How It Works

1. `src/auth/userManager.ts` configures a single `UserManager`:
   `response_type: 'code'` (PKCE S256 implied), scope
   `openid profile email`, **both** the token store and the state store in
   `sessionStorage`, `monitorSession: false`, `loadUserInfo: true`.
2. **Sign in** calls `signinRedirect({ nonce })`: `oidc-client-ts` loads the
   discovery document, generates the PKCE verifier and state, stashes them
   with the nonce in `sessionStorage`, and redirects to `/oauth/authorize`.
3. On `/callback`, `signinRedirectCallback()` validates `state`, exchanges
   the code (with `code_verifier`) at `/oauth/token`, checks the ID token's
   `nonce` and `sub`, and fetches `/oauth/userinfo` — all as CORS requests
   from the browser.
4. **Refresh token** uses the refresh token grant. The example checks for a
   refresh token first and fails with a clear message if there isn't one:
   without that guard, `signinSilent()` quietly falls back to a hidden
   `prompt=none` iframe aimed at `silent_redirect_uri` — which
   **defaults to `redirect_uri`**, i.e. `/callback`, a page this SPA does not
   serve as a silent callback — and hangs until a 10-second timeout.
5. **Call API** (`src/api/client.ts`) sends `Authorization: Bearer <access
   token>` to `/api/profile` or `/api/data`. On a 401 it renews once and
   retries; a second failure is surfaced to the page. `/api/data` requires the
   `read` scope, which Signet does not offer — so it returns 403
   `insufficient_scope`, shown verbatim. That is the point: it proves the
   token really was sent and that scope enforcement works.
6. **Sign out** revokes the refresh token and then the access token at
   `/oauth/revoke` (in that order — the library stops at the first failure, and
   the refresh token is the one worth stealing), then removes the user from
   `sessionStorage`.

The signed-in user is derived from `UserManager`'s own `userLoaded` /
`userUnloaded` / `accessTokenExpired` events rather than assigned by hand at
each call site, so the UI cannot drift out of sync with the stored session —
including when a renewal is triggered from inside the API client.

### Seeing the SSO effect

Sign in once, then open <http://localhost:5173> in a **new tab** and click
**Sign in** again: the Signet session cookie is still valid, so you return
authenticated without re-entering credentials. That round trip — app-local
tokens per tab, one shared login session at Signet — is the SSO behavior
this example demonstrates.

## Security Notes

> **⚠️ Tokens live in `sessionStorage`.** This keeps the example
> self-contained (survives a reload, dies with the tab) but means **any XSS
> vulnerability hands the attacker your tokens — including the refresh
> token, which is effectively account takeover** for its lifetime. This is
> the standard trade-off of every backend-less SPA.
>
> For production systems that need stronger guarantees, put a small backend
> in front (the **BFF pattern**): keep tokens server-side and give the
> browser only an httpOnly, SameSite session cookie. [go-oidc](../go-oidc/)
> is the server-side flow to start from.

- **No client secret, anywhere.** The bundle is public; the client must be
  registered as public and authenticates the code exchange with PKCE alone.
- **Set `stateStore`, not just `userStore`.** `oidc-client-ts` keeps the
  in-flight PKCE `code_verifier`, `state`, and `nonce` in a *separate* store
  that **defaults to `localStorage`** — which outlives the tab and is shared
  across tabs. This example points both stores at `sessionStorage`; if you
  configure only `userStore` (the common mistake), your tokens are in
  `sessionStorage` but your `code_verifier` is not.
- **Ship a Content-Security-Policy.** This example does not set one, because
  the `connect-src` it needs depends on your issuer URL. Given that XSS here
  means token theft, a real deployment should send something like
  `default-src 'self'; connect-src 'self' https://auth.example.com;
  object-src 'none'; base-uri 'none'` — `base-uri` matters, since a `<base>`
  tag injection would otherwise redirect the API client's relative fetches.
- Sign-out is **local + revocation**: the Signet browser session itself
  stays alive (no `end_session_endpoint`), so a subsequent sign-in from the
  same browser succeeds without a password prompt. Revoked tokens, however,
  are dead immediately — replaying the old access token against
  `/api/profile` returns 401.

## Choosing Between This and go-oidc

| | vue-spa (this) | [go-oidc](../go-oidc/) |
| --- | --- | --- |
| Client type | Public (PKCE only) | Confidential (secret) or public |
| Where tokens live | Browser `sessionStorage` | Server memory/session |
| Backend required | No (Vite proxy for the demo API only) | Yes (Go web app) |
| ID token validation | **None beyond `sub` + `nonce`** — no signature, `iss`, `aud`, or `exp` | Full: JWKS signature + `iss`/`aud`/`exp` + `at_hash` |
| XSS blast radius | Tokens exposed | Tokens unreachable from JS |
| Use when | Pure SPA / static hosting, SSO demo | Existing server-rendered app, higher security bar |
