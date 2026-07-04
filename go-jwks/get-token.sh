#!/usr/bin/env bash
# Fetches a test access token from Signet using the OAuth 2.0
# Client Credentials grant (RFC 6749 §4.4), for use against the
# go-jwks resource server.
#
# Prerequisites: curl, jq

set -euo pipefail

usage() {
  cat <<'EOF'
Fetch an access token from Signet via the Client Credentials grant.

Usage:
  bash get-token.sh                    # print access_token
  bash get-token.sh --raw              # print full token response JSON
  bash get-token.sh --decode           # print decoded JWT header + payload
  bash get-token.sh --debug            # echo raw server response to stderr
  bash get-token.sh --scope "read"     # request specific scopes
  INSECURE=1 bash get-token.sh         # skip TLS verification (self-signed issuer)

Env vars (loaded from the script's own directory .env if not already set):
  ISSUER_URL      required — Signet issuer, e.g. https://auth.example.com
  CLIENT_ID       required — OAuth client ID
  CLIENT_SECRET   required — OAuth client secret (M2M)
  SCOPE           optional — space-separated; default "email profile"
  INSECURE        optional — "1" to pass -k to curl (dev only)

Smoke test:
  TOKEN=$(bash get-token.sh)
  curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/api/profile
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

# Pretty-print a JWT's header + payload as a single JSON object. We decode in
# jq (already a hard dependency) rather than `base64 -d`, whose decode flag is
# -d on GNU but -D on older macOS. jq's @base64d only accepts the standard
# base64 alphabet, so b64urld first maps the JWT base64url alphabet (-_ -> +/)
# and restores the stripped '=' padding. A segment that isn't valid
# base64url-encoded JSON makes `fromjson` fail, which we surface as a clean
# error instead of a raw jq trace.
decode_jwt() {
  local jwt="$1"
  local -a parts
  IFS='.' read -r -a parts <<<"$jwt"
  [[ ${#parts[@]} -eq 3 && -n "${parts[0]}" && -n "${parts[1]}" && -n "${parts[2]}" ]] \
    || die "not a JWT (expected exactly three dot-separated segments)"
  jq -rn --arg h "${parts[0]}" --arg p "${parts[1]}" '
    def b64urld: gsub("-";"+") | gsub("_";"/")
      | . + ("=" * ((4 - (length % 4)) % 4)) | @base64d;
    {header: ($h | b64urld | fromjson), payload: ($p | b64urld | fromjson)}
  ' 2>/dev/null \
    || die "failed to decode JWT (a segment is not valid base64url-encoded JSON)"
}

load_dotenv() {
  local file="$1" line key value line_no=0
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    line="${line#"${line%%[![:space:]]*}"}"   # trim leading whitespace
    line="${line%"${line##*[![:space:]]}"}"   # trim trailing whitespace
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    if [[ ! "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      printf 'Warning: %s:%d: skipping malformed entry (content redacted)\n' \
        "$file" "$line_no" >&2
      continue
    fi
    key="${line%%=*}"
    value="${line#*=}"
    if [[ -z "${!key+x}" ]]; then
      if ! export "$key=$value"; then
        printf 'Warning: %s:%d: failed to export %s (value redacted)\n' \
          "$file" "$line_no" "$key" >&2
      fi
    fi
  done < "$file"
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
load_dotenv "$script_dir/.env"

RAW=0
DECODE=0
DEBUG=0
SCOPE="${SCOPE:-email profile}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --raw)    RAW=1; shift ;;
    --decode) DECODE=1; shift ;;
    --debug)  DEBUG=1; shift ;;
    --scope)
      [[ $# -ge 2 && "$2" != -* ]] || die 'missing value for --scope (try --scope "read")'
      SCOPE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1 (try --help)" ;;
  esac
done

command -v curl >/dev/null || die "curl not found"
command -v jq   >/dev/null || die "jq not found"

: "${ISSUER_URL:?set ISSUER_URL (or add it to .env)}"
: "${CLIENT_ID:?set CLIENT_ID}"
: "${CLIENT_SECRET:?set CLIENT_SECRET}"

curl_opts=(-sS --connect-timeout 10 --max-time 30)
[[ "${INSECURE:-0}" == "1" ]] && curl_opts+=(-k)

discovery="${ISSUER_URL%/}/.well-known/openid-configuration"
meta=$(curl "${curl_opts[@]}" "$discovery") || die "discovery failed: $discovery"
# Pull issuer + token_endpoint in one parse. jq fails if the body isn't JSON,
# so a proxy HTML error page produces a clean message instead of a raw trace.
# Fields are joined with ASCII RS (0x1e) so `read` preserves empty fields.
fields=$(jq -r '[.issuer // "", .token_endpoint // ""] | join("\u001e")' <<<"$meta" 2>/dev/null) \
  || die "discovery returned invalid JSON: $discovery"
IFS=$'\x1e' read -r disc_issuer token_url <<<"$fields"
[[ -n "$token_url" ]] || die "discovery response missing token_endpoint: $discovery"
# OIDC Discovery / RFC 8414 require the document's `issuer` to equal the
# issuer it was fetched for; the Go SDK's discovery client enforces this and
# so do we. It rejects a doc fetched for one issuer that claims to be another
# (issuer-confusion / mix-up) before we POST the client secret anywhere.
[[ "${disc_issuer%/}" == "${ISSUER_URL%/}" ]] \
  || die "discovery issuer mismatch: doc says ${disc_issuer:-<empty>}, expected ${ISSUER_URL%/}"

# Build the form body with each value URL-encoded separately.
# Secrets flow through jq's env (not argv) and curl's stdin (not argv) so
# they don't appear in /proc/<pid>/cmdline or `ps` output.
form=$(CID="$CLIENT_ID" SEC="$CLIENT_SECRET" SCP="$SCOPE" jq -rn '
  "grant_type=client_credentials"
  + "&client_id="     + (env.CID | @uri)
  + "&client_secret=" + (env.SEC | @uri)
  + "&scope="         + (env.SCP | @uri)')

response=$(printf '%s' "$form" | curl "${curl_opts[@]}" \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Accept: application/json' \
  --data-binary @- \
  -- "$token_url") || die "token request failed"

if [[ "$DEBUG" == "1" ]]; then
  printf -- '--- raw response from %s ---\n%s\n--- end ---\n' "$token_url" "$response" >&2
fi

# Parse once. Non-JSON responses (e.g. HTML error pages from a proxy) are
# reported explicitly instead of falling through to a confusing jq error.
# Fields are joined with ASCII RS (0x1e) — a non-whitespace separator so
# bash's `read` preserves empty fields (unlike tab, which `read` treats as
# IFS whitespace and collapses, turning "\t\tTOKEN" into a single field).
parsed=$(jq -r '[.error // "", .error_description // "", .access_token // ""] | join("\u001e")' \
  <<<"$response" 2>/dev/null) \
  || die "token endpoint returned non-JSON response (rerun with --debug to inspect the raw body)"
IFS=$'\x1e' read -r err desc token <<<"$parsed"
[[ -z "$err" ]] || die "token endpoint returned $err: $desc"
# Don't echo $response here: if parsing breaks on a valid 200 we'd leak
# the access_token to stderr / shell history. Use --debug to see the body.
[[ -n "$token" ]] || die "access_token missing from response (rerun with --debug to inspect the raw body)"

if [[ "$RAW" == "1" ]]; then
  jq . <<<"$response"
elif [[ "$DECODE" == "1" ]]; then
  decode_jwt "$token"
else
  printf '%s\n' "$token"
fi
