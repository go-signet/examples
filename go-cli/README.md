# Go CLI — Interactive Authentication

Authenticate a human user via browser or device code with automatic environment detection.

## OAuth Flow

- **Local machine** (browser available): Authorization Code + PKCE
- **SSH / headless session**: Device Code flow (RFC 8628)

The SDK auto-detects the environment and selects the appropriate flow.

## Prerequisites

- Go 1.26+
- An Signet server with a configured OAuth client

## Environment Variables

| Variable       | Required | Description                 |
| -------------- | -------- | --------------------------- |
| `SIGNET_URL` | Yes      | Signet server URL         |
| `CLIENT_ID`    | Yes      | OAuth 2.0 client identifier |
| `RESOURCES` | No | Space-separated resource identifiers; unset omits `resource` |

## Usage

```bash
export SIGNET_URL=https://auth.example.com
export CLIENT_ID=your-client-id
go run main.go
```

Alternatively, create a `.env` file in the `go-cli/` directory:

```bash
SIGNET_URL=https://auth.example.com
CLIENT_ID=your-client-id
```

Then simply run:

```bash
go run main.go
```

Environment variables take precedence over `.env` values. The `.env` file is optional — the program works without it.

## Request a token for an API (resources)

sdk-go v1.2.0 supports RFC 8707 resource indicators. A **resource** identifies the
intended API/audience; a **scope** describes the requested permissions. Configure
the client to allow the resource in Signet before requesting it. An empty resource
allowlist rejects explicit resources with `invalid_target`.

```bash
export RESOURCES='https://api.example.com'
go run main.go
```

The example passes these values to the SDK:

```go
signet.WithResources(strings.Fields(os.Getenv("RESOURCES"))...)
```

This covers Authorization Code + PKCE, Device Code, and subsequent refreshes.
The SDK separates cached tokens by client ID and resource set, so switching
resources does not reuse the token cached for a different resource set.
Leave `RESOURCES` unset for the original behavior. Multiple resources use spaces,
not commas: `RESOURCES='https://api.example.com https://other.example.com'`.
Every requested resource must be permitted by the issuer.

`TokenInfo Audience` shows the audience returned by the server (an array even
when the server encodes a single string). `[]` means the response omitted it;
it is not proof that an API will accept the token. UserInfo is best-effort and
may fail for an API-targeted token; tokeninfo is still attempted. Tokens remain
masked in terminal output.

For a runnable client-to-API example and audience enforcement, see
[Go M2M resources](../go-m2m/README.md#request-a-token-for-an-api-resources).

## How It Works

1. Calls `signet.New()` which performs OIDC discovery and starts the appropriate OAuth flow
2. Requests `profile` and `email` scopes and any configured `RESOURCES`
3. Stores the token in the OS keyring (falls back to file-based storage if keyring is unavailable)
4. Fetches user info via the `/oauth/userinfo` endpoint
5. Validates the token via `/oauth/tokeninfo` and prints detailed metadata

On subsequent runs, the cached token is reused automatically. If expired, it is refreshed transparently.

## Example Output

```
User: Jane Doe (jane@example.com)
Subject: user-uuid-1234
Access Token: eyJhbGci...
Refresh Token: dGhpcyBp...
Token Type: Bearer
Expires In: 3600
Expires At: 2025-01-01T12:00:00Z
Scope: profile email
ID Token: eyJ0eXAi...
TokenInfo Active: true
TokenInfo UserID: user-uuid-1234
TokenInfo ClientID: your-client-id
TokenInfo Scope: profile email
TokenInfo SubjectType: user
TokenInfo Issuer: https://auth.example.com
TokenInfo Exp: 1735732800
TokenInfo Audience: []
```

## Token Storage

Tokens are persisted in the OS keyring:

| Platform | Backend                    |
| -------- | -------------------------- |
| macOS    | Keychain                   |
| Linux    | Secret Service (D-Bus)     |
| Windows  | Windows Credential Manager |

If the keyring is unavailable, tokens fall back to a file-based cache.
