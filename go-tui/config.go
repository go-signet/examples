package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-signet/sdk-go/credstore"
	"github.com/go-signet/sdk-go/discovery"
	"github.com/go-signet/sdk-go/oauth"

	retry "github.com/appleboy/go-httpretry"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=...".
var version string

// Flag variables — Cobra binding targets, read once in loadConfig/loadStoreConfig.
var (
	flagServerURL    string
	flagClientID     string
	flagClientSecret string
	flagRedirectURI  string
	flagCallbackPort int
	flagScope        string
	flagTokenFile    string
	flagTokenStore   string
	flagDevice       bool

	flagTokenExchangeTimeout     string
	flagTokenVerificationTimeout string
	flagRefreshTokenTimeout      string
	flagDeviceCodeRequestTimeout string
	flagCallbackTimeout          string
	flagUserInfoTimeout          string
	flagDiscoveryTimeout         string
	flagRevocationTimeout        string
	flagMaxResponseBodySize      string
	flagRefreshThreshold         string

	flagExtraClaims     []string
	flagExtraClaimsFile string
)

const (
	defaultTokenExchangeTimeout     = 10 * time.Second
	defaultTokenVerificationTimeout = 10 * time.Second
	defaultRefreshTokenTimeout      = 10 * time.Second
	defaultDeviceCodeRequestTimeout = 10 * time.Second
	defaultCallbackTimeout          = 2 * time.Minute
	defaultUserInfoTimeout          = 10 * time.Second
	defaultDiscoveryTimeout         = 10 * time.Second
	defaultRevocationTimeout        = 10 * time.Second
	defaultMaxResponseBodySize      = 1 * 1024 * 1024 // 1 MB — guards against oversized server responses
	defaultKeyringService           = "signet-cli"

	// defaultRefreshThreshold is the window before expiry within which a stored
	// access token is proactively refreshed so users stay logged in.
	defaultRefreshThreshold = 5 * time.Minute

	// maxDurationConfig caps user-supplied timeout values to prevent the CLI
	// from hanging indefinitely on misconfiguration.
	maxDurationConfig = 10 * time.Minute

	// maxResponseBodySizeCap prevents users from setting an excessively large
	// response body limit that could cause OOM via io.ReadAll.
	maxResponseBodySizeCap int64 = 100 * 1024 * 1024 // 100 MB

	// extraClaimsFormKey is the form parameter name defined by the Signet
	// server's caller-supplied extra-claims feature.
	extraClaimsFormKey = "extra_claims"

	// maxExtraClaimsFileSize bounds godotenv reads so a malicious file can't
	// OOM the CLI before the server's much smaller raw-payload limit fires.
	maxExtraClaimsFileSize int64 = 64 * 1024 // 64 KiB
)

// AppConfig holds all resolved configuration for the CLI application.
type AppConfig struct {
	ServerURL      string
	ClientID       string
	ClientSecret   string
	RedirectURI    string
	CallbackPort   int
	Scope          string
	ForceDevice    bool
	TokenStoreMode string // "auto", "file", or "keyring"
	RetryClient    *retry.Client
	Store          credstore.Store[credstore.Token]

	// Endpoints holds the resolved OAuth endpoint URLs.
	// Populated by resolveEndpoints after loadConfig.
	Endpoints oauth.Endpoints

	// Timeout configuration (resolved from flag → env → default).
	// Only populated by loadConfig; zero in loadStoreConfig paths.
	TokenExchangeTimeout     time.Duration
	TokenVerificationTimeout time.Duration
	RefreshTokenTimeout      time.Duration
	DeviceCodeRequestTimeout time.Duration
	CallbackTimeout          time.Duration
	UserInfoTimeout          time.Duration
	DiscoveryTimeout         time.Duration
	RevocationTimeout        time.Duration
	MaxResponseBodySize      int64

	// RefreshThreshold is the window before expiry within which the stored
	// access token is proactively refreshed. Resolved by loadStoreConfig so it
	// is available on the offline `token get` path too, not just loadConfig.
	RefreshThreshold time.Duration

	// ExtraClaims is a compact JSON object string sent verbatim as the
	// `extra_claims` form parameter on every token request. Server validates
	// reserved keys and size limits; CLI only re-encodes for normalization.
	ExtraClaims string
}

// IsPublicClient returns true when no client secret is configured —
// i.e., this is a public client that must use PKCE.
func (c *AppConfig) IsPublicClient() bool {
	return c.ClientSecret == ""
}

func registerFlags(cmd *cobra.Command) {
	_ = godotenv.Load()
	cmd.PersistentFlags().
		StringVar(&flagServerURL, "server-url", "", "OAuth server URL (default: http://localhost:8080 or SIGNET_URL env)")
	cmd.PersistentFlags().
		StringVar(&flagClientID, "client-id", "", "OAuth client ID (required, or set CLIENT_ID env)")
	cmd.PersistentFlags().
		StringVar(&flagClientSecret, "client-secret", "", "OAuth client secret (confidential clients only; omit for public/PKCE clients)")
	cmd.PersistentFlags().
		StringVar(&flagRedirectURI, "redirect-uri", "", "Redirect URI registered with the OAuth server (default: http://localhost:PORT/callback)")
	cmd.PersistentFlags().
		IntVar(&flagCallbackPort, "port", 0, "Local callback port for browser flow (default: 8888 or CALLBACK_PORT env)")
	cmd.PersistentFlags().
		StringVar(&flagScope, "scope", "", "Space-separated OAuth scopes (default: \"email profile\")")
	cmd.PersistentFlags().
		StringVar(&flagTokenFile, "token-file", "", "Token storage file (default: .signet-tokens.json or TOKEN_FILE env)")
	cmd.PersistentFlags().
		StringVar(&flagTokenStore, "token-store", "", "Token storage backend: auto, file, keyring (default: auto or TOKEN_STORE env)")
	cmd.PersistentFlags().
		BoolVar(&flagDevice, "device", false, "Force Device Code Flow (skip browser detection)")
	cmd.PersistentFlags().
		StringVar(&flagTokenExchangeTimeout, "token-exchange-timeout", "", "Timeout for token exchange requests (e.g. 10s, 1m)")
	cmd.PersistentFlags().
		StringVar(&flagTokenVerificationTimeout, "token-verification-timeout", "", "Timeout for token verification requests (e.g. 10s, 1m)")
	cmd.PersistentFlags().
		StringVar(&flagRefreshTokenTimeout, "refresh-token-timeout", "", "Timeout for token refresh requests (e.g. 10s, 1m)")
	cmd.PersistentFlags().
		StringVar(&flagDeviceCodeRequestTimeout, "device-code-request-timeout", "", "Timeout for device code requests (e.g. 10s, 1m)")
	cmd.PersistentFlags().
		StringVar(&flagCallbackTimeout, "callback-timeout", "", "Timeout waiting for browser callback (e.g. 2m, 5m)")
	cmd.PersistentFlags().
		StringVar(&flagUserInfoTimeout, "userinfo-timeout", "", "Timeout for UserInfo requests (e.g. 10s, 1m)")
	cmd.PersistentFlags().
		StringVar(&flagDiscoveryTimeout, "discovery-timeout", "", "Timeout for OIDC Discovery requests (e.g. 10s, 30s)")
	cmd.PersistentFlags().
		StringVar(&flagRevocationTimeout, "revocation-timeout", "", "Timeout for token revocation requests (e.g. 10s, 1m)")
	cmd.PersistentFlags().
		StringVar(&flagMaxResponseBodySize, "max-response-body-size", "", "Maximum response body size in bytes (e.g. 1048576)")
	cmd.PersistentFlags().
		StringVar(&flagRefreshThreshold, "refresh-threshold", "", "Proactively refresh the access token when it expires within this window (e.g. 5m, 30s)")
	cmd.PersistentFlags().
		StringArrayVar(&flagExtraClaims, "extra-claims", nil, "Caller-supplied JWT claim as key=value (repeatable; values that parse as JSON keep their type, e.g. count=42, enabled=true, tags=[\"a\"])")
	cmd.PersistentFlags().
		StringVar(&flagExtraClaimsFile, "extra-claims-file", "", "Path to a .env-style file (key=value lines) supplying extra_claims; merged before --extra-claims so flags override file entries")
}

// loadStoreConfig initialises only the token store, client ID, and refresh
// threshold — the minimal offline config. Commands like `token get` start from
// this and load the full network-capable config lazily (via loadConfig) only
// when a refresh is actually required, so a far-from-expiry read stays offline.
func loadStoreConfig() *AppConfig {
	cfg := &AppConfig{}

	cfg.ClientID = getConfig(flagClientID, "CLIENT_ID", "")
	cfg.TokenStoreMode = getConfig(flagTokenStore, "TOKEN_STORE", "auto")
	tokenFile := getConfig(flagTokenFile, "TOKEN_FILE", ".signet-tokens.json")

	// Resolved here (not loadConfig) so the offline `token get` path can decide
	// whether a refresh is due without building the full network config.
	cfg.RefreshThreshold = getRefreshThresholdConfig(flagRefreshThreshold)

	if cfg.ClientID == "" {
		fmt.Fprintln(os.Stderr, "Error: CLIENT_ID not set. Please provide it via:")
		fmt.Fprintln(os.Stderr, "  1. Command-line flag: --client-id=<your-client-id>")
		fmt.Fprintln(os.Stderr, "  2. Environment variable: CLIENT_ID=<your-client-id>")
		fmt.Fprintln(os.Stderr, "  3. .env file: CLIENT_ID=<your-client-id>")
		fmt.Fprintln(os.Stderr, "\nYou can find the client_id in the server startup logs.")
		os.Exit(1)
	}

	var storeErr error
	cfg.Store, storeErr = newTokenStore(cfg.TokenStoreMode, tokenFile, defaultKeyringService)
	if storeErr != nil {
		fmt.Fprintln(os.Stderr, storeErr)
		os.Exit(1)
	}

	return cfg
}

// loadConfig resolves all configuration from flags, environment, and defaults.
func loadConfig() *AppConfig {
	cfg := loadStoreConfig()

	cfg.ForceDevice = flagDevice
	cfg.ServerURL = getConfig(flagServerURL, "SIGNET_URL", "http://localhost:8080")
	cfg.ClientSecret = getConfig(flagClientSecret, "CLIENT_SECRET", "")
	cfg.Scope = getConfig(flagScope, "SCOPE", "email profile")

	// Resolve callback port (int flag needs special handling).
	portStr := ""
	if flagCallbackPort != 0 {
		portStr = strconv.Itoa(flagCallbackPort)
	}
	portStr = getConfig(portStr, "CALLBACK_PORT", "8888")
	if port, err := strconv.Atoi(portStr); err != nil || port <= 0 || port > 65535 {
		cfg.CallbackPort = 8888
	} else {
		cfg.CallbackPort = port
	}

	// Resolve redirect URI (depends on port, so compute after port is known).
	defaultRedirectURI := fmt.Sprintf("http://localhost:%d/callback", cfg.CallbackPort)
	cfg.RedirectURI = getConfig(flagRedirectURI, "REDIRECT_URI", defaultRedirectURI)

	if err := validateServerURL(cfg.ServerURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid SIGNET_URL: %v\n", err)
		os.Exit(1)
	}

	// Drop trailing slashes so the fallback default endpoints (used when OIDC
	// Discovery is unavailable) don't double the separator, e.g.
	// "https://host/" + "/oauth/token" → "https://host//oauth/token".
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")

	if strings.HasPrefix(strings.ToLower(cfg.ServerURL), "http://") {
		fmt.Fprintln(
			os.Stderr,
			"WARNING: Using HTTP instead of HTTPS. Tokens will be transmitted in plaintext!",
		)
		fmt.Fprintln(
			os.Stderr,
			"WARNING: This is only safe for local development. Use HTTPS in production.",
		)
		fmt.Fprintln(os.Stderr)
	}

	if _, err := uuid.Parse(cfg.ClientID); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"WARNING: CLIENT_ID doesn't appear to be a valid UUID: %s\n",
			cfg.ClientID,
		)
		fmt.Fprintln(os.Stderr)
	}

	baseHTTPClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	var err error
	cfg.RetryClient, err = retry.NewBackgroundClient(retry.WithHTTPClient(baseHTTPClient))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create retry HTTP client: %v\n", err)
		os.Exit(1)
	}

	// Resolve timeout configuration.
	cfg.TokenExchangeTimeout = getDurationConfig(
		flagTokenExchangeTimeout, "TOKEN_EXCHANGE_TIMEOUT", defaultTokenExchangeTimeout)
	cfg.TokenVerificationTimeout = getDurationConfig(
		flagTokenVerificationTimeout, "TOKEN_VERIFICATION_TIMEOUT", defaultTokenVerificationTimeout)
	cfg.RefreshTokenTimeout = getDurationConfig(
		flagRefreshTokenTimeout, "REFRESH_TOKEN_TIMEOUT", defaultRefreshTokenTimeout)
	cfg.DeviceCodeRequestTimeout = getDurationConfig(
		flagDeviceCodeRequestTimeout,
		"DEVICE_CODE_REQUEST_TIMEOUT",
		defaultDeviceCodeRequestTimeout,
	)
	cfg.CallbackTimeout = getDurationConfig(
		flagCallbackTimeout, "CALLBACK_TIMEOUT", defaultCallbackTimeout)
	cfg.UserInfoTimeout = getDurationConfig(
		flagUserInfoTimeout, "USERINFO_TIMEOUT", defaultUserInfoTimeout)
	cfg.DiscoveryTimeout = getDurationConfig(
		flagDiscoveryTimeout, "DISCOVERY_TIMEOUT", defaultDiscoveryTimeout)
	cfg.RevocationTimeout = getDurationConfig(
		flagRevocationTimeout, "REVOCATION_TIMEOUT", defaultRevocationTimeout)
	cfg.MaxResponseBodySize = getInt64Config(
		flagMaxResponseBodySize, "MAX_RESPONSE_BODY_SIZE", defaultMaxResponseBodySize)
	if cfg.MaxResponseBodySize > maxResponseBodySizeCap {
		fmt.Fprintf(os.Stderr,
			"WARNING: MAX_RESPONSE_BODY_SIZE exceeds %d, capping\n", maxResponseBodySizeCap)
		cfg.MaxResponseBodySize = maxResponseBodySizeCap
	}

	if cfg.TokenStoreMode == "auto" {
		if ss, ok := cfg.Store.(*credstore.SecureStore[credstore.Token]); ok && !ss.UseKeyring() {
			fmt.Fprintln(
				os.Stderr,
				"WARNING: OS keyring unavailable, falling back to file-based token storage",
			)
		}
	}

	extra, err := resolveExtraClaims(flagExtraClaims, flagExtraClaimsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid extra_claims: %v\n", err)
		os.Exit(1)
	}
	cfg.ExtraClaims = extra

	return cfg
}

// resolveExtraClaims merges caller-supplied JWT claims from the flag and the
// optional .env-style file, then returns a compact JSON object string ready
// to send as the `extra_claims` form parameter. File entries are applied
// first; flag entries override on conflicting keys. Returns "" when the
// merged map is empty so the caller can omit the parameter entirely.
//
// Validation is intentionally minimal — the server enforces reserved keys
// and size limits and returns descriptive `invalid_request` errors which
// the CLI surfaces as-is.
func resolveExtraClaims(flagPairs []string, filePath string) (string, error) {
	merged := map[string]any{}

	if filePath != "" {
		fileClaims, err := loadExtraClaimsFile(filePath)
		if err != nil {
			return "", fmt.Errorf("--extra-claims-file %q: %w", filePath, err)
		}
		maps.Copy(merged, fileClaims)
	}

	// Error messages reference the pair by index rather than echoing the raw
	// pair, so a value the user accidentally typed (e.g. a secret) doesn't
	// land in stderr or CI logs.
	for i, pair := range flagPairs {
		k, v, err := parseExtraClaimPair(pair)
		if err != nil {
			return "", fmt.Errorf("--extra-claims #%d: %w", i+1, err)
		}
		merged[k] = v
	}

	if len(merged) == 0 {
		return "", nil
	}

	encoded, err := json.Marshal(merged)
	if err != nil {
		return "", fmt.Errorf("encode %s: %w", extraClaimsFormKey, err)
	}
	return string(encoded), nil
}

func loadExtraClaimsFile(path string) (map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read limit+1 so an oversized file is detected explicitly rather than
	// truncated silently by io.LimitReader (which would partially apply
	// claims with no error).
	data, err := io.ReadAll(io.LimitReader(f, maxExtraClaimsFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxExtraClaimsFileSize {
		return nil, fmt.Errorf("file too large: limit is %d bytes", maxExtraClaimsFileSize)
	}

	parsed, err := godotenv.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(parsed))
	for k, v := range parsed {
		out[k] = parseClaimValue(v)
	}
	return out, nil
}

func parseExtraClaimPair(pair string) (string, any, error) {
	rawKey, rawVal, ok := strings.Cut(pair, "=")
	if !ok {
		return "", nil, errors.New("must be key=value with a non-empty key")
	}
	// Trim the key so a flag like "name =v" matches the godotenv-trimmed keys
	// from --extra-claims-file, preserving the documented "flags override file
	// entries" contract on conflicting keys.
	key := strings.TrimSpace(rawKey)
	if key == "" {
		return "", nil, errors.New("must be key=value with a non-empty key")
	}
	return key, parseClaimValue(rawVal), nil
}

// parseClaimValue tries to decode raw as JSON so users can write count=42
// or tags=["a","b"] without thinking in JSON terms, falling back to a plain
// string. UseNumber preserves integer claims exactly (mirrors token_cmd.go's
// JWT decoder) — without it, IDs above 2^53 silently round. Inputs with
// trailing non-whitespace data fall back to the raw string so e.g.
// "42 not-a-number" stays a string instead of decoding as 42.
func parseClaimValue(raw string) any {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return raw
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	var sink any
	if err := dec.Decode(&sink); !errors.Is(err, io.EOF) {
		return raw
	}
	return v
}

// newTokenStore creates a token store backend based on the given mode.
//
// "keyring" mode keeps only the 32-byte master key in the OS keyring and
// AES-256-GCM-encrypts the token to tokenFilePath+".enc", so large tokens (e.g.
// with groups claims) don't hit keyring blob size limits. The ".enc" path
// matches "auto" mode and stays distinct from "file" mode's plaintext file.
func newTokenStore(
	mode, tokenFilePath, keyringService string,
) (credstore.Store[credstore.Token], error) {
	switch mode {
	case "file":
		return credstore.NewTokenFileStore(tokenFilePath), nil
	case "keyring":
		return credstore.NewTokenEncryptedFileStore(keyringService, tokenFilePath+".enc"), nil
	case "auto":
		return credstore.DefaultTokenSecureStore(keyringService, tokenFilePath), nil
	default:
		return nil, fmt.Errorf("invalid token store mode: %q (valid: auto, file, keyring)", mode)
	}
}

func getConfig(flagValue, envKey, defaultValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return getEnv(envKey, defaultValue)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func validateServerURL(rawURL string) error {
	if rawURL == "" {
		return errors.New("server URL cannot be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got: %s", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("URL must include a host")
	}
	return nil
}

// defaultEndpoints returns hardcoded endpoint paths appended to serverURL.
// Used as fallback when OIDC Discovery is unavailable.
func defaultEndpoints(serverURL string) oauth.Endpoints {
	return oauth.Endpoints{
		AuthorizeURL:           serverURL + "/oauth/authorize",
		TokenURL:               serverURL + "/oauth/token",
		DeviceAuthorizationURL: serverURL + "/oauth/device/code",
		TokenInfoURL:           serverURL + "/oauth/tokeninfo",
		UserinfoURL:            serverURL + "/oauth/userinfo",
		RevocationURL:          serverURL + "/oauth/revoke",
	}
}

// resolveEndpoints attempts OIDC Discovery and falls back to hardcoded paths.
func resolveEndpoints(ctx context.Context, cfg *AppConfig) {
	disco, err := discovery.NewClient(
		cfg.ServerURL,
		discovery.WithHTTPClient(cfg.RetryClient),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"WARNING: OIDC Discovery init failed: %v (using default endpoints)\n", err)
		cfg.Endpoints = defaultEndpoints(cfg.ServerURL)
		return
	}

	fetchCtx, cancel := context.WithTimeout(ctx, cfg.DiscoveryTimeout)
	defer cancel()

	meta, err := disco.Fetch(fetchCtx)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"WARNING: OIDC Discovery fetch failed: %v (using default endpoints)\n", err)
		cfg.Endpoints = defaultEndpoints(cfg.ServerURL)
		return
	}

	cfg.Endpoints = meta.Endpoints()
}

// getDurationConfig resolves a time.Duration from flag → env → default, capped
// at maxDurationConfig. The value is parsed with time.ParseDuration (e.g. "10s",
// "2m", "1m30s"). On parse error or non-positive value, it falls back to the
// default and prints a warning.
func getDurationConfig(flagValue, envKey string, defaultValue time.Duration) time.Duration {
	return parseDurationConfig(flagValue, envKey, defaultValue, maxDurationConfig)
}

// getRefreshThresholdConfig resolves the proactive-refresh threshold from
// flag → REFRESH_THRESHOLD env → defaultRefreshThreshold. Like getDurationConfig
// it rejects invalid or non-positive values, but unlike timeouts it is
// intentionally NOT capped at maxDurationConfig: a large threshold only makes
// the CLI refresh sooner (it can't cause a hang), so users may legitimately
// want 30m, 1h, etc.
func getRefreshThresholdConfig(flagValue string) time.Duration {
	return parseDurationConfig(flagValue, "REFRESH_THRESHOLD", defaultRefreshThreshold, 0)
}

// parseDurationConfig is the shared flag → env → default duration resolver. A
// maxValue of 0 means "no upper cap"; any positive maxValue caps the result and
// warns. On parse error or non-positive value it returns defaultValue.
func parseDurationConfig(
	flagValue, envKey string,
	defaultValue, maxValue time.Duration,
) time.Duration {
	raw := getConfig(flagValue, envKey, "")
	if raw == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: invalid duration %q for %s, using default %s\n",
			raw, envKey, defaultValue)
		return defaultValue
	}
	if d <= 0 {
		fmt.Fprintf(os.Stderr, "WARNING: %s must be positive, got %s, using default %s\n",
			envKey, d, defaultValue)
		return defaultValue
	}
	if maxValue > 0 && d > maxValue {
		fmt.Fprintf(os.Stderr, "WARNING: %s exceeds maximum %s, capping at %s\n",
			envKey, maxValue, maxValue)
		return maxValue
	}
	return d
}

// getInt64Config resolves an int64 from flag → env → default.
// On parse error or non-positive value, it falls back to the default and prints a warning.
func getInt64Config(flagValue, envKey string, defaultValue int64) int64 {
	raw := getConfig(flagValue, envKey, "")
	if raw == "" {
		return defaultValue
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		fmt.Fprintf(os.Stderr, "WARNING: invalid value %q for %s, using default %d\n",
			raw, envKey, defaultValue)
		return defaultValue
	}
	return v
}

// getVersion returns the build version, preferring the ldflags-injected value
// and falling back to debug.ReadBuildInfo().
func getVersion() string {
	if version != "" {
		return version
	}
	if build, ok := debug.ReadBuildInfo(); ok &&
		build.Main.Version != "" &&
		build.Main.Version != "(devel)" {
		return build.Main.Version
	}
	return "unknown version"
}
