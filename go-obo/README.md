# Go On-behalf-of: Web, CLI, API A and API B

[繁體中文](README.zh-TW.md)

Run a complete user-delegated orders flow with Go 1.26+ and
[`sdk-go v1.2.0`](https://github.com/go-signet/sdk-go/tree/v1.2.0).
A Go Web frontend or public Go CLI signs a user in. API A exchanges that user's
access token for an OBO token addressed to API B. B verifies the user, actor,
audience and scope, checks current token validity online, and returns fictional
orders owned by that user.

The runnable path requires Signet with OBO token exchange and combined consent
support. Complete the database migrations and configure RS256/ES256 signing
with a publicly accessible JWKS endpoint before running this example.

## What runs where

| Command              | Role                        | Local address             | Credential                           |
| -------------------- | --------------------------- | ------------------------- | ------------------------------------ |
| `go run ./cmd/web`   | F-Web: Go HTML frontend/BFF | `127.0.0.1:8090`          | Web client ID + secret               |
| `go run ./cmd/cli`   | F-CLI: public PKCE client   | callback `127.0.0.1:8093` | CLI client ID only                   |
| `go run ./cmd/api-a` | A: middle API, OBO actor    | `127.0.0.1:8091`          | A client ID + secret                 |
| `go run ./cmd/api-b` | B: orders resource server   | `127.0.0.1:8092`          | Separate B introspection ID + secret |

No Node, Bun, database or browser JavaScript is needed by this example. The Web
frontend uses `html/template` embedded in Go. All tokens stay in process memory;
the browser only receives random HttpOnly session cookies. The CLI has no A/B
secret and no persistent token cache.

```mermaid
sequenceDiagram
    actor U as User / browser
    participant F as Go Web or CLI
    participant S as Signet
    participant A as API A
    participant B as API B
    F->>U: Open authorize URL (PKCE, nonce, state, resource A)
    U->>S: Sign in and approve F→A plus A→B
    S-->>F: F's authorization code
    F->>S: Exchange code with PKCE verifier
    S-->>F: User access token, aud=A
    F->>A: GET /api/orders, Bearer source token
    A->>A: Verify source signature, audience, user, type and scope
    A->>S: OBO: A credentials + assertion + B resource + scope
    S-->>A: OBO token, aud=B, sub=user, actor=A
    A->>B: GET /api/orders, Bearer OBO token
    B->>B: Verify JWT and expected user/actor/scope
    B->>S: Introspect with B's own credentials
    S-->>B: active=true (metadata may be omitted)
    B-->>A: User's fictional orders and verified identity
    A-->>F: Orders with source/downstream identity summaries
    F-->>U: HTML or terminal JSON; no raw tokens
```

| Property          | Source token                               | OBO token                             |
| ----------------- | ------------------------------------------ | ------------------------------------- |
| `sub` / `user_id` | Signed-in user                             | Same user                             |
| `client_id`       | F-Web or F-CLI                             | A                                     |
| `aud`             | Exactly A resource URI                     | Exactly B resource URI                |
| Scope             | `orders.delegate.read` (plus login scopes) | `orders.read`                         |
| `act.sub`         | Absent                                     | `client:<A_CLIENT_ID>`                |
| Issuer            | Signet                                     | Same Signet                           |
| Renewal           | Sign in again in this example              | Exchange the still-valid source again |

OBO is for a service acting with a user's permission. Client Credentials is for
an application acting as itself. Never forward the source token directly to B,
replace a denied OBO request with an application token, or use an ID token as an
API credential. This is single-hop Signet OBO, not Entra/MSAL, Agent OBO or RFC
8693 token-exchange wire format.

## 1. Configure the Signet test instance

Use a test deployment and complete the upstream migrations before starting it.
The example does not migrate Signet or create remote clients/policies for you.
Set these on **Signet**, not merely in this example's `.env`:

```dotenv
OBO_ENABLED=true
OBO_POLICY_SOURCE=database
OBO_POLICIES_FILE=
OBO_COMBINED_CONSENT_ENABLED=true
LOGIN_SESSION_TRACKING_ENABLED=true
OBO_TOKEN_EXPIRATION=5m
INTROSPECTION_REQUIRE_OWNERSHIP=true
```

Keep settings consistent across Signet replicas. If you were already logged in
before enabling login-session tracking, sign out of Signet and sign in again.

Create four active, non-CIMD clients in Signet's client administration:

| Client          | Type / grants                     | Registered scopes                          | Allowed resources                         | Redirect URI                            |
| --------------- | --------------------------------- | ------------------------------------------ | ----------------------------------------- | --------------------------------------- |
| F-Web           | Confidential, Authorization Code  | `openid orders.delegate.read`              | `https://api-a.example.com`               | `http://127.0.0.1:8090/callback`        |
| F-CLI           | Public, Authorization Code + PKCE | `openid orders.delegate.read`              | `https://api-a.example.com`               | `http://127.0.0.1:8093/callback`        |
| A               | Confidential, active              | `orders.read`                              | `https://api-b.example.com`               | No callback needed for combined consent |
| B introspection | Confidential, active              | No delegated scope required for this query | No token resource required for this query | No callback used                        |

If the client creation UI requires an ordinary grant configuration, keep its
valid settings; OBO itself does not require enabling Client Credentials on A.
Initially leave SkipConsent off on the frontends. Record the actual generated
client IDs and secrets, rather than entering the table's F/A/B role names.

The B **resource** does not require an OAuth client owner. We create a separate
confidential client because this example's B calls introspection. Never share
A's secret with B or a frontend to obtain more introspection metadata.

As a Signet administrator:

1. Open `/admin/api-resources`. Create A with URI `https://api-a.example.com`,
   a descriptive name, **Owner/Actor Client ID = A's actual client ID**, and
   **Enabled checked**. Create B with URI `https://api-b.example.com`, owner
   empty, and Enabled checked.
2. Under A, create enabled scope `orders.delegate.read`; under B, create enabled
   scope `orders.read`. Do not register `openid` as a delegated API scope.
3. Open `/admin/clients/<A_CLIENT_ID>/delegations`. Create enabled policy
   `orders-a-to-b`, inbound A, target B, with this mapping:

   ```text
   orders.read=orders.delegate.read
   ```

4. Open `/admin/clients/<WEB_CLIENT_ID>/consent-bundles`, select inbound A,
   check Enabled, and configure:

   ```text
   orders-a-to-b=orders.read
   ```

5. Repeat step 4 for `/admin/clients/<CLI_CLIENT_ID>/consent-bundles`.

Mapping direction is **output scope = required input scopes**; all inputs on a
line are required. Registry policy never broadens client scopes or resource
allowlists and never substitutes for user consent. New resources/scopes/forms
must explicitly be enabled.

Both frontends use normal authorization-code requests with one `resource=A`.
The bundle is chosen by administrator configuration, not an OAuth parameter.
The Signet consent page should display frontend access F→A and access on your
behalf A→B. Approval creates independent grants and issues only F's code/token.
A needs no consent callback. Device Flow does not invoke this combined screen,
so the CLI deliberately does not auto-fallback to Device Flow.

## 2. Configure and run the Go programs

```bash
cd go-obo
cp .env.example .env
chmod 600 .env
# Edit .env with your issuer and four registered client identities.
```

Environment variables take precedence over `.env`. Each process validates only
its own required credentials. The single file is convenient for local demos;
in separate deployments supply only each process's required secrets.

| Setting                                  | Used by           | Default / meaning                                        |
| ---------------------------------------- | ----------------- | -------------------------------------------------------- |
| `SIGNET_URL`                             | All               | Required exact issuer URL                                |
| `WEB_CLIENT_ID`, `WEB_CLIENT_SECRET`     | Web               | Required confidential frontend credentials               |
| `CLI_CLIENT_ID`                          | CLI               | Required public frontend ID; no secret                   |
| `API_A_CLIENT_ID`                        | A, B              | A credentials / B's expected actor                       |
| `API_A_CLIENT_SECRET`                    | A                 | Required OBO secret                                      |
| `API_B_CLIENT_ID`, `API_B_CLIENT_SECRET` | B                 | Required introspection credentials                       |
| `API_A_AUDIENCE`, `API_B_AUDIENCE`       | All               | `https://api-a.example.com`, `https://api-b.example.com` |
| `API_A_URL`                              | Web, CLI          | `http://127.0.0.1:8091`                                  |
| `API_B_URL`                              | A                 | `http://127.0.0.1:8092`                                  |
| `WEB_ADDR`, `API_A_ADDR`, `API_B_ADDR`   | Respective server | `127.0.0.1:8090`, `:8091`, `:8092`                       |
| `WEB_REDIRECT_URL`                       | Web               | `http://127.0.0.1:8090/callback`                         |
| `CLI_CALLBACK_ADDR`                      | CLI               | `127.0.0.1:8093`, fixed loopback port; path `/callback`  |

Audience identifiers are **not network destinations**: no example.com DNS or
API deployment is needed. URI comparison is exact; do not change trailing
slashes independently. This demo rejects query/fragment-bearing configured
URLs to keep configuration unambiguous. All discovered endpoints must use the
issuer's origin. HTTPS is required except for loopback HTTP development.

In separate terminals, each with `go-obo` as the working directory:

```bash
# Terminal 1
go run ./cmd/api-b
```

```bash
# Terminal 2
go run ./cmd/api-a
```

```bash
# Terminal 3
go run ./cmd/web
```

Visit **http://127.0.0.1:8090/** (use this host consistently, not `localhost`).
Click **Sign in with Signet**, approve both groups, then **Read my orders**. To try the CLI against the same A/B services:

```bash
# Terminal 4
go run ./cmd/cli
```

Open its printed URL in a browser on the same computer. The callback listener
is started before the URL is printed. The CLI prints the result and exits;
Ctrl+C cancels, and login expires after five minutes. Remote/headless sessions
without a reachable local browser callback are not supported in this example.

Check API reachability without tokens:

```bash
curl http://127.0.0.1:8091/healthz
curl http://127.0.0.1:8092/healthz
```

Both return `{"status":"ok"}`. An unauthenticated `/api/orders` returns 401.

Example successful response (IDs and times vary):

```json
{
  "source": {
    "sub": "user-alice",
    "client_id": "YOUR_FRONTEND_CLIENT_ID",
    "aud": ["https://api-a.example.com"],
    "scope": "openid orders.delegate.read",
    "expires_at": "2026-09-12T16:10:00Z"
  },
  "downstream": {
    "sub": "user-alice",
    "client_id": "YOUR_API_A_CLIENT_ID",
    "actor": "client:YOUR_API_A_CLIENT_ID",
    "aud": ["https://api-b.example.com"],
    "scope": "orders.read",
    "expires_at": "2026-09-12T16:05:00Z"
  },
  "orders": [
    {
      "id": "demo-<subject-hash>",
      "owner": "user-alice",
      "item": "Example notebook"
    }
  ],
  "demo": true
}
```

## 3. Follow the Go code

| File                      | Responsibility                                                                   |
| ------------------------- | -------------------------------------------------------------------------------- |
| `cmd/*/main.go`           | Load role settings, cancellation and server startup                              |
| `internal/demo/login.go`  | Discovery, PKCE/state/nonce/issuer binding, verified login, bounded memory store |
| `internal/demo/web.go`    | Server-side sessions, CSRF-protected orders/logout, template rendering           |
| `internal/demo/cli.go`    | Single-use loopback callback, timeout and cancellation                           |
| `internal/demo/api.go`    | Source/downstream validation, SDK OBO/introspection and subject-owned orders     |
| `internal/demo/http.go`   | Origin-pinned HTTP clients, response limits, no redirects, safe errors           |
| `internal/demo/config.go` | Per-role configuration and URL validation                                        |

The exchange in API A uses the SDK directly:

```go
token, err := a.oauth.ExchangeOnBehalfOf(r.Context(), oauth.OnBehalfOfRequest{
    Assertion: raw,                 // F's validated user access token, aud=A
    Resource:  a.config.AudienceB,   // trusted server configuration
    Scopes:    []string{OutputScope}, // orders.read
})
```

`a.oauth` is constructed with A's client ID/secret. The SDK sends credentials in
the form body (not combined with Basic auth). The corresponding wire request is:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
&requested_token_use=on_behalf_of
&assertion=USER_ACCESS_TOKEN_FOR_A
&resource=https%3A%2F%2Fapi-b.example.com
&scope=orders.read
&client_id=API_A_CLIENT_ID
&client_secret=API_A_CLIENT_SECRET
```

Line breaks are for readability; the SDK uses a form encoder. The response has
`access_token`, `token_type`, `scope` and `expires_in`, with no ID or refresh
token. Expiry is bounded by the source, A's profile and the configured maximum
(at most five minutes). The example does not cache OBO tokens: each operation
exchanges the still-valid source again. Expired frontend sessions require login
again; no refresh token is retained.

`jwksauth.Verify` verifies signature/issuer/audience/expiry. The example adds
`type=access`, exactly one audience, matching non-machine `sub`/`user_id`, scope
and actor policy. A requires no actor on the source; B requires both
`client_id=A` and `act.sub=client:A`. Arbitrary claims are never used for access.

B then calls `Introspect` with **B's own** credentials on every request. With
ownership enforcement a valid cross-client response is only `{"active":true}`.
Claims must still come from the verified JWT. Inactive, timeout, rate limit,
upstream error or malformed JSON all deny data; positive verdicts are not cached.
JWKS public keys may be cached. Pure offline JWT validation cannot enforce live
policy/consent revocation before token expiry.

Orders are deterministic fictional records selected from the verified subject,
not from request query parameters. A real orders service must enforce its own
record ownership using that subject. OAuth consent alone does not grant access
to another user's data.

## 4. Verification and failure cases

Automated tests use an in-process issuer fixture with actual RSA-signed tokens,
discovery/JWKS HTTP endpoints and real SDK calls. They exercise the example's
handlers, Web login/session flow and CLI callback. They do **not** certify
Signet's registry transactions or actual browser consent UI.

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/...
```

Three reproducible contract checks:

```bash
# User preserved through A -> B; source reuse; simulated revocation rejects
# both new exchanges and previously issued, unexpired downstream tokens.
go test ./internal/demo -run '^TestOBOEndToEnd$' -v

# Correctly signed wrong-audience/actor/type/scope tokens cannot read orders.
go test ./internal/demo -run '^TestAPIBRejectsInvalidClaims$' -v

# Inactive/unavailable introspection cannot be bypassed; authorization
# endpoint error text and credentials are not exposed.
go test ./internal/demo -run 'TestIntrospectionFailuresDenyData|TestOAuthErrorsAreSanitized' -v
```

Other tests cover state/nonce/issuer/PKCE errors, transaction replay/expiry,
CSRF, two users, local logout, CLI cancellation, no redirects and body limits.

For **live Signet acceptance**, record the Signet commit, configuration and
PASS/FAIL/NOT RUN separately:

1. Use a fresh test user for Web and CLI. Confirm two consent groups, then
   matching source/downstream subjects, B audience, A actor and own orders.
2. Reject consent with a fresh user: no local session/orders should appear.
   Repeat with a disabled or incorrectly mapped policy; no successful OBO.
3. Obtain a source token for A using a trusted OAuth test client (register its
   F client and bundle as above). In that client's secure in-memory request
   console, send it directly as Bearer to B's `/api/orders`: expect 401. Do not
   copy raw tokens into logs, URLs or issue reports. The provided Web/CLI do not
   export tokens; the automated audience test requires no external client.
4. In the same trusted test harness, exchange the source using A's credentials
   and retain the resulting B token in memory. Verify B returns 200. On Signet's
   `/account/authorizations`, revoke A→B, then reuse that **same unexpired B
   token**: expect 401. New OBO requests must fail. In a separate run disable
   the policy and repeat; reenabling it must not revive the old B token.
5. Retry Web/CLI after revocation: they cannot read orders until the user
   completes fresh consent. Revoking A→B affects both frontends for the same
   user because this grant belongs to user + A + B. Re-consent does not revive
   an older delegated token. Run as a second user to confirm isolated results.

Live Signet/browser consent and policy revoke/re-enable acceptance has **not
been executed as part of this implementation**; no test deployment credentials
were supplied. Automated revocation is a simulated inactive verdict, not proof
of Signet's database policy behavior.

## Troubleshooting and limits

| Error                                | What to check                                                                            |
| ------------------------------------ | ---------------------------------------------------------------------------------------- |
| `unsupported_grant_type`             | OBO enabled on every Signet replica; correct version                                     |
| `invalid_client`                     | A/B credentials, active confidential clients; this is a server setup problem             |
| `unauthorized_client`                | A is non-CIMD confidential and has matching enabled delegation policy                    |
| `invalid_grant`                      | Source expiry/state, user/client status, both consent grants; not always missing consent |
| `invalid_scope`                      | Output-to-input mapping, client scopes and downstream consent                            |
| `invalid_target`                     | Exact B resource URI, enabled resource and A allowlist                                   |
| `invalid_token` / `invalid_actor`    | JWT issuer/type/expiry/audience, user subject and A actor                                |
| `insufficient_scope`                 | Required scope absent from an otherwise verified token                                   |
| `invalid_state` / `invalid_id_token` | Start login again; callback cookie, PKCE, nonce and issuer bindings                      |
| `login_required`                     | Local session absent/expired; sign in again                                              |
| `introspection_unavailable`          | Signet reachable, B credentials valid, no timeout/rate limit                             |

The API maps invalid credentials/tokens to 401, insufficient permission and OBO
grant/policy denial to 403, configuration/upstream response errors to 502, and
unavailable upstream services to 503. OAuth error codes retain their meaning:
for example A's `invalid_client` is surfaced as 502, not a request for the user
to reauthenticate. Error descriptions/raw upstream bodies are never exposed.
Automatic OAuth retries are disabled.

Local Web sign-out only destroys the example session. It does not log out of
Signet or revoke its consent records. Signet's next login can reuse its SSO
session. Use the account authorizations page to demonstrate revocation.

Servers listen on loopback by default and do not terminate TLS. Nonlocal use
requires HTTPS termination, trusted configured origins and per-process secret
injection. Web memory sessions (maximum 1,000 sessions and 1,000 pending logins,
minute cleanup) are single-process demonstration storage, not shared production
sessions. No claims about production capacity or deployment are made.

## Appendix: File-based delegation policies

[`testdata/obo-policies.example.json`](testdata/obo-policies.example.json)
contains the equivalent file-mode delegation policy. Replace A's client ID and
mount it on Signet, then set on Signet:

```dotenv
OBO_ENABLED=true
OBO_POLICY_SOURCE=file
OBO_POLICIES_FILE=/etc/signet/obo-policies.json
OBO_COMBINED_CONSENT_ENABLED=false
```

File/database sources are mutually exclusive; file policies load at startup.
This is a configuration reference, **not** an automatic compatibility switch:
without combined consent, the same user must separately consent to F→A and
A→B. This example's A has no independent authorization-code consent callback.
Implement and complete that separate interactive consent flow before using
the exchange. An administrator policy or SQL-created data cannot
replace actual user consent. Never use a setup token addressed to B as the A
assertion, and do not mix policy modes across replicas.
