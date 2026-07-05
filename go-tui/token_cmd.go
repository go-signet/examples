package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"github.com/go-signet/sdk-go/credstore"
	"github.com/spf13/cobra"
)

type tokenGetOutput struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	Expired     bool      `json:"expired"`
	ClientID    string    `json:"client_id"`
	// RefreshToken is intentionally omitted — it is a long-lived secret
	// that should not be casually printed to stdout or captured in logs.
}

func buildTokenCmd() *cobra.Command {
	tokenCmd := &cobra.Command{
		Use:   "token",
		Short: "Manage stored tokens",
	}
	tokenCmd.AddCommand(buildTokenGetCmd())
	tokenCmd.AddCommand(buildTokenDeleteCmd())
	tokenCmd.AddCommand(buildTokenInspectCmd())
	tokenCmd.AddCommand(buildTokenDecodeCmd())
	return tokenCmd
}

func buildTokenInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect the stored access token via /oauth/tokeninfo",
		Long: `Send the stored access token to the OAuth server's /oauth/tokeninfo
endpoint and print the response as pretty-printed JSON.

This shows what the server records for the token (e.g. scopes, expiry,
subject, client_id) — useful for debugging when the local token state
disagrees with the server.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			resolveEndpoints(cmd.Context(), cfg)
			if code := runTokenInspect(
				cmd.Context(),
				cfg,
				cmd.OutOrStdout(),
				cmd.ErrOrStderr(),
			); code != 0 {
				return exitCodeError(code)
			}
			return nil
		},
	}
	return cmd
}

func buildTokenGetCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Print the stored access token",
		Long: `Print the stored access token.

When the token is within the refresh threshold of expiry (default 5m,
configurable via --refresh-threshold / REFRESH_THRESHOLD), it is proactively
refreshed using the stored refresh token so scripts stay logged in. If the
refresh fails but the existing token is still valid, the old token is printed
with a warning on stderr (exit 0); if the token is already expired and the
refresh token is no longer valid, the command exits non-zero.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load only the store + client ID + refresh threshold up front so a
			// far-from-expiry read stays fully offline. The network-capable
			// config (SIGNET_URL validation, retry client, endpoints) is built
			// lazily via loadConfig, only when a refresh is actually required.
			cfg := loadStoreConfig()
			if code := runTokenGet(
				cmd.Context(),
				cfg,
				loadConfig,
				jsonOutput,
				cmd.OutOrStdout(),
				cmd.ErrOrStderr(),
			); code != 0 {
				return exitCodeError(code)
			}
			return nil
		},
	}
	cmd.Flags().
		BoolVar(&jsonOutput, "json", false, "Output token details as JSON (access_token, token_type, expires_at, expired, client_id)")
	return cmd
}

func buildTokenDeleteCmd() *cobra.Command {
	var localOnly bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete the stored token",
		Long: `Delete the stored token.

By default, the token is first revoked on the OAuth server before being
deleted locally. If the server is unreachable, the local token is still
deleted (graceful degradation).

Use --local-only to skip server revocation and only delete the local token.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var cfg *AppConfig
			if localOnly {
				cfg = loadStoreConfig()
			} else {
				cfg = loadConfig()
				resolveEndpoints(cmd.Context(), cfg)
			}
			if code := runTokenDelete(
				cmd.Context(),
				cfg,
				localOnly,
				cmd.OutOrStdout(),
				cmd.ErrOrStderr(),
			); code != 0 {
				return exitCodeError(code)
			}
			return nil
		},
	}
	cmd.Flags().
		BoolVar(&localOnly, "local-only", false, "Skip server-side token revocation; only delete the local token")
	return cmd
}

// loadTokenOrFail loads the token for id and writes user-facing diagnostics
// to stderr on failure. Returns the token and 0, or a zero token and a
// non-zero exit code.
func loadTokenOrFail(
	store credstore.Store[credstore.Token],
	id string,
	stderr io.Writer,
) (credstore.Token, int) {
	tok, err := store.Load(id)
	if err != nil {
		if errors.Is(err, credstore.ErrNotFound) {
			fmt.Fprintf(stderr, "Error: no stored token for client-id %q\n", id)
			fmt.Fprintf(stderr, "Hint: run 'signet-cli' first to authenticate.\n")
			return tok, 1
		}
		fmt.Fprintf(stderr, "Error: failed to load token: %v\n", err)
		return tok, 1
	}
	return tok, 0
}

// runTokenDelete is the testable core of `token delete`.
func runTokenDelete(
	ctx context.Context,
	cfg *AppConfig,
	localOnly bool,
	stdout io.Writer,
	stderr io.Writer,
) int {
	// Check existence first — Delete is idempotent and silently succeeds
	// even when the key is absent.
	tok, code := loadTokenOrFail(cfg.Store, cfg.ClientID, stderr)
	if code != 0 {
		return code
	}

	if !localOnly {
		if err := revokeTokenOnServer(ctx, cfg, tok, stderr); err != nil {
			fmt.Fprintf(stderr, "Warning: server-side revocation failed: %v\n", err)
			fmt.Fprintln(stderr, "Proceeding with local token deletion.")
		} else {
			fmt.Fprintln(stdout, "Token revoked on server.")
		}
	}

	if err := cfg.Store.Delete(cfg.ClientID); err != nil {
		fmt.Fprintf(stderr, "Error: failed to delete token: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Token for client-id %q deleted.\n", cfg.ClientID)
	return 0
}

// revokeTokenOnServer attempts to revoke tokens on the OAuth server (RFC 7009).
// It revokes the refresh and access tokens concurrently.
func revokeTokenOnServer(
	ctx context.Context,
	cfg *AppConfig,
	tok credstore.Token,
	stderr io.Writer,
) error {
	revokeURL := cfg.Endpoints.RevocationURL
	timeout := cfg.RevocationTimeout

	var (
		mu         sync.Mutex
		refreshErr error
		accessErr  error
		wg         sync.WaitGroup
	)

	if tok.RefreshToken != "" {
		wg.Go(func() {
			if err := doRevoke(
				ctx,
				cfg,
				revokeURL,
				tok.RefreshToken,
				"refresh_token",
				timeout,
			); err != nil {
				mu.Lock()
				refreshErr = err
				mu.Unlock()
			}
		})
	}

	if tok.AccessToken != "" {
		wg.Go(func() {
			if err := doRevoke(
				ctx,
				cfg,
				revokeURL,
				tok.AccessToken,
				"access_token",
				timeout,
			); err != nil {
				mu.Lock()
				accessErr = err
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	switch {
	case accessErr != nil && refreshErr != nil:
		fmt.Fprintf(stderr, "Warning: failed to revoke refresh token: %v\n", refreshErr)
		return fmt.Errorf("access token revocation: %w", accessErr)
	case accessErr != nil:
		return fmt.Errorf("access token revocation: %w", accessErr)
	case refreshErr != nil:
		return fmt.Errorf("refresh token revocation: %w", refreshErr)
	default:
		return nil
	}
}

// doRevoke posts a single token to the revocation endpoint (RFC 7009).
// It includes client_id (and client_secret for confidential clients) as
// required by most OAuth servers for client authentication.
func doRevoke(
	ctx context.Context,
	cfg *AppConfig,
	revokeURL string,
	token string,
	tokenTypeHint string,
	timeout time.Duration,
) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	data := url.Values{
		"token":     {token},
		"client_id": {cfg.ClientID},
	}
	if tokenTypeHint != "" {
		data.Set("token_type_hint", tokenTypeHint)
	}
	cfg.setClientSecret(data)
	resp, err := cfg.RetryClient.Post(ctx, revokeURL,
		retry.WithBody(
			"application/x-www-form-urlencoded",
			strings.NewReader(data.Encode()),
		),
	)
	if err != nil {
		return fmt.Errorf("revoke request: %w", err)
	}
	defer resp.Body.Close()

	// Drain a bounded amount of the body for proper HTTP connection reuse.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("revoke returned status %d", resp.StatusCode)
	}
	return nil
}

// runTokenGet is the testable core of `token get`. It loads the stored token,
// proactively refreshes it when near expiry (see ensureFreshToken), and prints
// the resulting access token.
func runTokenGet(
	ctx context.Context,
	cfg *AppConfig,
	loadFull func() *AppConfig,
	jsonOut bool,
	stdout io.Writer,
	stderr io.Writer,
) int {
	tok, _, err := ensureFreshToken(ctx, cfg, loadFull, stderr)
	if err != nil {
		switch {
		case errors.Is(err, credstore.ErrNotFound):
			fmt.Fprintf(stderr, "Error: no stored token for client-id %q\n", cfg.ClientID)
			fmt.Fprintf(stderr, "Hint: run 'signet-cli' first to authenticate.\n")
		case errors.Is(err, ErrRefreshTokenExpired), errors.Is(err, ErrNoRefreshToken):
			fmt.Fprintf(
				stderr,
				"Error: stored token can no longer be refreshed: %v\n",
				err,
			)
			fmt.Fprintf(stderr, "Hint: run 'signet-cli' to re-authenticate.\n")
		default:
			// Covers both load failures and refresh/exchange errors (e.g. a
			// network failure while refreshing an expired token), so keep the
			// wording neutral rather than implying the load step failed.
			fmt.Fprintf(stderr, "Error: failed to obtain a valid token: %v\n", err)
		}
		return 1
	}
	if jsonOut {
		out := tokenGetOutput{
			AccessToken: tok.AccessToken,
			TokenType:   tok.TokenType,
			ExpiresAt:   tok.ExpiresAt,
			Expired:     !time.Now().Before(tok.ExpiresAt),
			ClientID:    tok.ClientID,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "Error: failed to write output: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, tok.AccessToken)
	return 0
}

func buildTokenDecodeCmd() *cobra.Command {
	var field string
	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Decode the stored access token's claims locally (JWT only)",
		Long: `Decode the stored access token's claims by base64-decoding its
JWT payload locally, without contacting the OAuth server.

The signature is NOT verified. Use 'token inspect' to query the
server for token validity. Useful when the access token is a JWT
(e.g. contains aud, sub, project_id). If the token is opaque (not
a JWT), this command fails with an error.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadStoreConfig()
			if code := runTokenDecode(
				cfg.Store,
				cfg.ClientID,
				field,
				cmd.OutOrStdout(),
				cmd.ErrOrStderr(),
			); code != 0 {
				return exitCodeError(code)
			}
			return nil
		},
	}
	cmd.Flags().
		StringVarP(&field, "field", "f", "", "Print only the named top-level claim (e.g. aud, sub, project_id)")
	return cmd
}

// errNotJWT signals that a token is not in JWT format (wrong segment count).
// Distinct from base64/JSON failures so callers can tailor the error message.
var errNotJWT = errors.New("not a JWT-formatted token")

// parseJWTPayload decodes a JWT's payload (claims) without verifying the
// signature. Use only for local inspection — claims must not drive
// authorization; use the server's introspection endpoint for that.
func parseJWTPayload(token string) (map[string]any, error) {
	// SplitN with cap 4 bounds allocation when fed a malformed token with
	// many separators; we still reject anything that isn't exactly 3 parts.
	// Count separators directly so the diagnostic reports the true segment
	// count rather than the capped slice length.
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 3 {
		return nil, fmt.Errorf(
			"%w (expected 3 dot-separated parts, got %d)",
			errNotJWT,
			strings.Count(token, ".")+1,
		)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	// UseNumber preserves integer claims (e.g. exp, iat, custom IDs) exactly;
	// the default would coerce them to float64 and lose precision past 2^53.
	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}
	// A payload of the JSON literal `null` unmarshals into a nil map with no
	// error; reject it so a malformed token isn't reported as an empty-but-valid
	// claim set.
	if claims == nil {
		return nil, errors.New("parse claims: payload is not a JSON object")
	}
	// Reject trailing bytes (or a second concatenated value) so a malformed
	// payload can't masquerade as valid by hiding extra data after the object.
	var sink struct{}
	if err := dec.Decode(&sink); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("parse claims: trailing data after JSON object")
		}
		return nil, fmt.Errorf("parse claims: trailing data: %w", err)
	}
	return claims, nil
}

// runTokenDecode is the testable core of `token decode`. It locally parses
// the stored access token as a JWT and prints either the full claims map or
// a single named claim.
func runTokenDecode(
	store credstore.Store[credstore.Token],
	id string,
	field string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	tok, code := loadTokenOrFail(store, id, stderr)
	if code != 0 {
		return code
	}
	claims, err := parseJWTPayload(tok.AccessToken)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to decode access token: %v\n", err)
		// Only suggest "token inspect" when the token looks like it could be
		// opaque (fewer dots than a real JWT). Tokens with 4+ segments are
		// just malformed JWTs, not opaque, so the hint would mislead.
		if errors.Is(err, errNotJWT) && strings.Count(tok.AccessToken, ".") < 2 {
			fmt.Fprintln(
				stderr,
				"Hint: if the token is opaque, use 'signet-cli token inspect' to query the server.",
			)
		}
		return 1
	}
	if field != "" {
		return printClaimField(claims, field, stdout, stderr)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(claims); err != nil {
		fmt.Fprintf(stderr, "Error: failed to write output: %v\n", err)
		return 1
	}
	return 0
}

// printClaimField writes a single claim to stdout. String values are printed
// raw (like `jq -r`) so they're shell-friendly; other types stay JSON-encoded
// so arrays/objects/numbers remain machine-readable.
func printClaimField(
	claims map[string]any,
	field string,
	stdout io.Writer,
	stderr io.Writer,
) int {
	v, ok := claims[field]
	if !ok {
		fmt.Fprintf(stderr, "Error: claim %q not found in token\n", field)
		return 1
	}
	if s, isStr := v.(string); isStr {
		fmt.Fprintln(stdout, s)
		return 0
	}
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to encode claim: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(b))
	return 0
}

// runTokenInspect is the testable core of `token inspect`. It calls the
// OAuth server's /oauth/tokeninfo endpoint with the stored access token and
// prints the response as pretty-printed JSON. If the body is not valid JSON,
// it is printed verbatim so the user still sees what the server returned.
func runTokenInspect(
	ctx context.Context,
	cfg *AppConfig,
	stdout io.Writer,
	stderr io.Writer,
) int {
	tok, code := loadTokenOrFail(cfg.Store, cfg.ClientID, stderr)
	if code != 0 {
		return code
	}
	body, err := verifyToken(ctx, cfg, tok.AccessToken)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to inspect token: %v\n", err)
		return 1
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, []byte(body), "", "  "); err == nil {
		fmt.Fprintln(stdout, pretty.String())
	} else {
		fmt.Fprintln(stdout, body)
	}
	return 0
}
