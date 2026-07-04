# Signet Examples

[![Trivy Security Scan](https://github.com/go-signet/examples/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/go-signet/examples/actions/workflows/security.yml)
[![Goreleaser](https://github.com/go-signet/examples/actions/workflows/goreleaser.yml/badge.svg?branch=main)](https://github.com/go-signet/examples/actions/workflows/goreleaser.yml)
[![CodeQL](https://github.com/go-signet/examples/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/go-signet/examples/actions/workflows/codeql.yml)

Multi-language usage examples for Signet authentication (Go, Python, Bash).

## Quick Reference

| Example                         | Use Case                 | OAuth Flow                   | Language | Prerequisites    |
| ------------------------------- | ------------------------ | ---------------------------- | -------- | ---------------- |
| [go-cli](go-cli/)               | CLI login                | Auth Code+PKCE / Device Code | Go       | Go 1.25+         |
| [python-cli](python-cli/)       | CLI login                | Auth Code+PKCE / Device Code | Python   | Python 3.10+, uv |
| [bash-cli](bash-cli/)           | CLI login (headless)     | Device Code (RFC 8628)       | Bash     | curl, jq         |
| [go-m2m](go-m2m/)               | Service-to-service       | Client Credentials           | Go       | Go 1.25+         |
| [python-m2m](python-m2m/)       | Service-to-service       | Client Credentials           | Python   | Python 3.10+, uv |
| [go-webservice](go-webservice/) | API protection           | Bearer validation            | Go       | Go 1.25+         |
| [go-jwks](go-jwks/)             | API protection (offline) | JWKS public-key validation   | Go       | Go 1.25+         |
| [go-jwks-multi](go-jwks-multi/) | API protection (N iss)   | JWKS validation (multi)      | Go       | Go 1.25+         |
| [go-oidc](go-oidc/)             | Web login (no SDK)       | Auth Code (coreos/go-oidc)   | Go       | Go 1.25+         |
| [kong-mcp](kong-mcp/)           | MCP gateway (Kong)       | PKCE entry + JWKS validation | Go       | Go 1.25+, Kong   |

## Environment Setup

All examples except [kong-mcp](kong-mcp/) require `SIGNET_URL` and `CLIENT_ID`. M2M examples additionally require `CLIENT_SECRET`. The kong-mcp gateway reads no environment variables — configure it via the plugin block in [`kong-mcp/kong.yml`](kong-mcp/kong.yml) (`issuer`, `gateway_origin`, `jwks_uri`, ...).

Set via environment variables:

```bash
export SIGNET_URL=https://auth.example.com
export CLIENT_ID=your-client-id
export CLIENT_SECRET=your-client-secret  # M2M only
```

Or use a `.env` file in the example directory:

```bash
SIGNET_URL=https://auth.example.com
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret  # M2M only
```

All env-configured examples automatically load `.env` if present (kong-mcp does not read `.env`). Environment variables take precedence over `.env` values.

## Interactive CLI Authentication

These examples authenticate a human user via browser or device code. Auto-detects browser availability: uses Auth Code + PKCE on local machines, falls back to Device Code in SSH/headless sessions. Tokens are cached for reuse.

### Go CLI

Uses the Signet Go SDK. Tokens are stored in the OS keyring.

```bash
cd go-cli
go run main.go
```

### Python CLI

Uses the Signet Python SDK. Tokens are stored in the OS keyring when available, with a fallback cache file at `~/.signet-tokens.json`.

```bash
cd python-cli
uv run python main.py
```

### Bash CLI

Pure shell implementation using only `curl` and `jq` — no SDK or runtime required. Uses the Device Authorization Grant (RFC 8628) exclusively. Tokens are cached to `~/.signet-tokens.json`.

Features: OIDC discovery, token caching/refresh, expiry handling, cross-platform support (GNU/BSD), and security hardening (symlink protection, stdin-based secret passing to avoid process-list leaks).

```bash
cd bash-cli
bash main.sh
```

## Machine-to-Machine (M2M) Authentication

These examples use the Client Credentials grant for service-to-service authentication. No user interaction needed — requires `CLIENT_SECRET`.

### Go M2M

Uses the Signet Go SDK with auto-caching and a pre-authenticated HTTP client.

```bash
cd go-m2m
go run main.go
```

### Python M2M

Uses the Signet Python SDK with auto-refreshing `BearerAuth` for httpx.

```bash
cd python-m2m
uv run python main.py
```

## Web Service — API Token Validation

Protects HTTP endpoints with Bearer token middleware and scope-based access control. Works with any Go HTTP framework.

```bash
cd go-webservice
go run main.go

# Test
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/profile
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/data
```

## Offline JWKS Validation (no SDK, no introspection)

Alternative resource-server pattern: validates JWT access tokens locally using the provider's public keys (`jwks_uri`), with no per-request callback to Signet. Ideal for latency-sensitive or multi-region deployments. Trade-off vs. [go-webservice](go-webservice/): revoked tokens stay valid until their `exp`, so keep access-token TTLs short.

```bash
cd go-jwks
go run main.go
```

## Multi-Issuer Offline JWKS Validation

Same offline JWKS pattern as [go-jwks](go-jwks/), but the resource server accepts tokens signed by **any of N trusted Signets**. Per-token routing by `iss` claim, one cached JWKS per issuer. Use for multi-region deployments, multi-tenant SaaS where each tenant has its own Signet, Signet-to-Signet migrations (both trusted during cutover), or B2B federation.

```bash
cd go-jwks-multi
go run main.go
```

## OIDC Web Login (no SDK)

Browser-based Authorization Code flow against any OpenID Connect provider using the standard [`github.com/coreos/go-oidc/v3`](https://github.com/coreos/go-oidc) library and `golang.org/x/oauth2`. Demonstrates discovery, state + nonce CSRF protection, ID token verification, and the UserInfo endpoint — handy when integrating Signet into an existing Go web app without the SDK.

```bash
cd go-oidc
go run main.go
# then open http://localhost:8080/
```

## MCP OAuth Gateway (Kong)

A Kong [go-pdk](https://github.com/Kong/go-pdk) plugin that puts one OAuth front
door in front of every MCP server. Internal MCP services stop accepting
hand-written PATs and instead require an Signet-issued access token. Kong does
not run the OAuth flow — it only advertises the entry point (`401` +
`WWW-Authenticate` → RFC 9728 Protected Resource Metadata) and validates the
returned token offline with **RS256 + JWKS** (alg-confusion blocked), then
forwards it to the MCP backend. The MCP client runs Auth Code + PKCE against
Signet itself. One plugin config covers all MCP servers.

```bash
cd kong-mcp
go mod tidy && go build -o mcp-signet .   # build the plugin
docker compose up --build                   # demo stack: Kong + stub MCP upstreams
```

## OAuth 2.0 Flows

- **Authorization Code + PKCE** — Browser-based login, most secure for CLI tools on machines with a browser. The client opens a browser, the user authenticates, and a code is exchanged for tokens.
- **Device Code ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628))** — For headless/SSH environments. The user authenticates on a separate device by visiting a URL and entering a code.
- **Client Credentials** — Service-to-service auth with a shared secret. No user involved.
- **Bearer Token Validation** — Server-side introspection of access tokens sent by clients in the `Authorization` header.

## Troubleshooting

- **"Cannot connect to SIGNET_URL"** — Verify the URL is correct and the Signet server is running.
- **"Device code expired"** — Restart the flow; the default timeout is 300 seconds.
- **Token cache location** — `~/.signet-tokens.json` is shared by bash-cli and Python examples. Go CLI examples use the OS keyring.
- **OS keyring unavailable** — Go and Python CLI examples fall back to file-based cache automatically.
