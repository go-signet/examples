# Go M2M — Machine-to-Machine Authentication

Service-to-service authentication using the OAuth 2.0 Client Credentials grant. No user interaction required.

## OAuth Flow

Uses the **Client Credentials** grant. The service authenticates with its own `CLIENT_ID` and `CLIENT_SECRET` to obtain an access token.

## Prerequisites

- Go 1.26+
- An Signet server with a configured OAuth client (with client secret)

## Environment Variables

| Variable        | Required | Description                 |
| --------------- | -------- | --------------------------- |
| `SIGNET_URL`  | Yes      | Signet server URL         |
| `CLIENT_ID`     | Yes      | OAuth 2.0 client identifier |
| `CLIENT_SECRET` | Yes      | OAuth 2.0 client secret     |
| `RESOURCES` | No | Space-separated resource identifiers; unset omits `resource` |
| `API_URL` | When `RESOURCES` is set | Exact API endpoint to call; otherwise defaults to discovery userinfo |

## Usage

```bash
export SIGNET_URL=https://auth.example.com
export CLIENT_ID=your-client-id
export CLIENT_SECRET=your-client-secret
go run main.go
```

Alternatively, create a `.env` file in the `go-m2m/` directory:

```bash
SIGNET_URL=https://auth.example.com
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
```

Then simply run:

```bash
go run main.go
```

Environment variables take precedence over `.env` values. The `.env` file is optional — the program works without it.

## Request a token for an API (resources)

A resource indicator (RFC 8707) requests a token intended for a specific API.
It is distinct from a scope: this example continues to request `profile email`
permissions. In Signet, configure the client to allow these scopes and add
`https://api.example.com` to its allowed resources. An empty resource allowlist
rejects explicit resources with `invalid_target`.

Start the existing JWKS resource server in a separate terminal:

```bash
cd go-jwks
export ISSUER_URL=https://auth.example.com
export EXPECTED_AUDIENCE=https://api.example.com
unset SKIP_AUDIENCE_CHECK
go run main.go
# Wait for "Listening on :8088".
```

From the repository root in another terminal:

```bash
cd go-m2m
export SIGNET_URL=https://auth.example.com
export CLIENT_ID=your-client-id
export CLIENT_SECRET=your-client-secret
export RESOURCES='https://api.example.com'
export API_URL=http://localhost:8088/api/data
go run main.go
```

Expected: `Status: 200` and the API response. The issuer must issue signed JWT
access tokens discoverable by `go-jwks`; its issuer must match `ISSUER_URL`.
The `/api/data` route requires `email`, which this client requests.

The example uses:

```go
clientcreds.NewTokenSource(client,
    clientcreds.WithScopes("profile", "email"),
    clientcreds.WithResources(strings.Fields(os.Getenv("RESOURCES"))...),
)
```

`RESOURCES` determines the requested audience; `API_URL` determines where to send
the HTTP request. They need not be identical: an audience can identify an API
while `API_URL` includes a route such as `/api/data`. Set `API_URL` explicitly
when requesting resources so the token is sent to its intended API instead of
the issuer's userinfo endpoint.

Multiple resources use spaces, not commas:
`RESOURCES='https://api.example.com https://other.example.com'`. The SDK sends a
separate `resource` form value for each; all must be allowed by the issuer.
The token source preserves resources when obtaining replacement tokens before
expiry. Client Credentials obtains new tokens rather than using a refresh token.

To run the original userinfo example, unset both variables:

```bash
unset RESOURCES API_URL
go run main.go
```

### Verify failure cases

- Request a resource absent from the client's allowlist: expect an
  `invalid_target` error and no API call.
- Restart `go-jwks` with `EXPECTED_AUDIENCE=https://other.example.com`, keeping
  the M2M resource unchanged: expect `Status: 401` and a nonzero client exit.
- Point `API_URL` at `/api/admin` without the required domain/service-account/
  project claims: expect `Status: 401` and a nonzero exit.

Non-2xx API responses print their status/body and fail the command. Redirects
are not followed, since the SDK transport would attach a token to each new
request. The command has a 30-second timeout and limits output bodies to 1 MB.
Stop the local resource server with Ctrl-C and unset `RESOURCES API_URL` after
trying the example. No tokens are persisted by the M2M client.

### Automated verification

```bash
# From go-m2m/
go test ./...
go build ./...
go vet ./...
```

Tests use local HTTP fixtures to verify resource form values, bearer forwarding,
default userinfo behavior, missing API configuration, issuer rejection, API
rejection, and redirects. Live Signet setup is only needed for the manual steps
above.

## How It Works

1. Auto-discovers OIDC endpoints via `/.well-known/openid-configuration`
2. Creates an OAuth client with the client secret
3. Creates an auto-refreshing `TokenSource` with `profile` and `email` scopes and a 30-second expiry delta (refreshes token 30 seconds before it expires)
4. Obtains a pre-authenticated `http.Client` from the token source
5. Makes an authenticated GET request to `API_URL`, or the `userinfo_endpoint` advertised in discovery when no resources are requested
6. Prints the response status and body (limited to 1 MB)

The token source automatically handles token acquisition and renewal — no manual refresh logic needed.

## Example Output

```txt
Status: 200
Body: {"sub":"service-uuid","client_id":"your-client-id",...}
```

## Use Cases

- Backend services calling protected APIs
- Cron jobs and scheduled tasks
- Microservice-to-microservice communication
- CI/CD pipeline authentication
