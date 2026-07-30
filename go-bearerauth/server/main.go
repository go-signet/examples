// Command server runs a small resource server that accepts either a Signet
// JWT access token or a complete Signet Personal API Key on the same endpoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-signet/sdk-go/bearerauth"
	"github.com/joho/godotenv"
)

const (
	defaultServerAddr = ":8080"

	verifierStartupTimeout = 30 * time.Second
	shutdownTimeout        = 10 * time.Second
)

// credentialVerifier is deliberately narrower than *bearerauth.Verifier. The
// HTTP adapter depends only on this contract, which keeps it independent of a
// framework and makes its behavior testable without a live Signet issuer.
type credentialVerifier interface {
	Verify(context.Context, string) (*bearerauth.Identity, error)
}

type serverConfig struct {
	signetURL                 string
	clientID                  string
	expectedAudience          string
	skipAudienceCheck         bool
	requiredScopes            []string
	introspectionClientID     string
	introspectionClientSecret string
	serverAddr                string
}

func main() {
	// A missing .env is expected in deployments that inject environment
	// variables directly.
	_ = godotenv.Load()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		logger.Printf("startup failed category=invalid_configuration: %v", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := run(ctx, cfg, logger); err != nil {
		logger.Printf("server stopped category=error: %v", err)
		os.Exit(1)
	}
}

func loadConfig(getenv func(string) string) (serverConfig, error) {
	cfg := serverConfig{
		signetURL:                 strings.TrimSpace(getenv("SIGNET_URL")),
		clientID:                  strings.TrimSpace(getenv("CLIENT_ID")),
		expectedAudience:          strings.TrimSpace(getenv("EXPECTED_AUDIENCE")),
		requiredScopes:            strings.Fields(getenv("REQUIRED_SCOPES")),
		introspectionClientID:     strings.TrimSpace(getenv("INTROSPECTION_CLIENT_ID")),
		introspectionClientSecret: getenv("INTROSPECTION_CLIENT_SECRET"),
		serverAddr:                strings.TrimSpace(getenv("SERVER_ADDR")),
	}
	if cfg.serverAddr == "" {
		cfg.serverAddr = defaultServerAddr
	}

	switch strings.TrimSpace(getenv("SKIP_AUDIENCE_CHECK")) {
	case "", "0":
		cfg.skipAudienceCheck = false
	case "1":
		cfg.skipAudienceCheck = true
	default:
		return serverConfig{}, errors.New(
			"SKIP_AUDIENCE_CHECK must be empty, 0, or 1",
		)
	}

	switch {
	case cfg.signetURL == "":
		return serverConfig{}, errors.New("SIGNET_URL is required")
	case cfg.clientID == "":
		return serverConfig{}, errors.New("CLIENT_ID is required")
	case cfg.expectedAudience == "" && !cfg.skipAudienceCheck:
		return serverConfig{}, errors.New(
			"EXPECTED_AUDIENCE is required unless SKIP_AUDIENCE_CHECK=1",
		)
	case cfg.expectedAudience != "" && cfg.skipAudienceCheck:
		return serverConfig{}, errors.New(
			"EXPECTED_AUDIENCE and SKIP_AUDIENCE_CHECK=1 are mutually exclusive",
		)
	}

	hasIntrospectionID := cfg.introspectionClientID != ""
	hasIntrospectionSecret := cfg.introspectionClientSecret != ""
	if hasIntrospectionID != hasIntrospectionSecret {
		return serverConfig{}, errors.New(
			"INTROSPECTION_CLIENT_ID and INTROSPECTION_CLIENT_SECRET must be set together",
		)
	}
	if hasIntrospectionSecret &&
		strings.TrimSpace(cfg.introspectionClientSecret) == "" {
		return serverConfig{}, errors.New(
			"INTROSPECTION_CLIENT_SECRET must not be blank",
		)
	}

	return cfg, nil
}

func (c serverConfig) bearerAuthConfig() bearerauth.Config {
	return bearerauth.Config{
		Audience:                  c.expectedAudience,
		SkipAudience:              c.skipAudienceCheck,
		ClientID:                  c.clientID,
		RequiredScopes:            c.requiredScopes,
		IntrospectionClientID:     c.introspectionClientID,
		IntrospectionClientSecret: c.introspectionClientSecret,
	}
}

func (c serverConfig) personalAPIKeyMode() string {
	if c.introspectionClientID != "" {
		return "introspection"
	}
	return "tokeninfo"
}

func run(ctx context.Context, cfg serverConfig, logger *log.Logger) error {
	startupCtx, cancel := context.WithTimeout(ctx, verifierStartupTimeout)
	defer cancel()

	// Construct the immutable, concurrency-safe verifier once at startup and
	// share it across all requests. New performs OIDC discovery and builds the
	// JWT and Personal API Key verification paths.
	verifier, err := bearerauth.New(
		startupCtx,
		cfg.signetURL,
		cfg.bearerAuthConfig(),
	)
	if err != nil {
		return fmt.Errorf("initialize bearer verifier: %w", err)
	}

	handler := newHandler(verifier, logger)
	server := newHTTPServer(cfg.serverAddr, handler)
	return serve(ctx, server, cfg.personalAPIKeyMode(), logger)
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func serve(
	ctx context.Context,
	server *http.Server,
	personalAPIKeyMode string,
	logger *log.Logger,
) error {
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	logger.Printf(
		"server listening addr=%s personal_api_key_verification=%s",
		listener.Addr(),
		personalAPIKeyMode,
	)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)

	case <-ctx.Done():
		logger.Print("server shutting down")

		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			shutdownTimeout,
		)
		defer cancel()

		shutdownErr := server.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			// Ensure Serve unblocks even if a handler outlives the graceful
			// shutdown window.
			_ = server.Close()
		}

		err := <-serveErr
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve during shutdown: %w", err)
		}
		if shutdownErr != nil {
			return fmt.Errorf("graceful shutdown: %w", shutdownErr)
		}

		logger.Print("server stopped")
		return nil
	}
}

func newHandler(verifier credentialVerifier, logger *log.Logger) http.Handler {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.Handle(
		"GET /api/whoami",
		requireBearer(verifier, logger)(http.HandlerFunc(whoamiHandler)),
	)
	return mux
}

type identityContextKey struct{}

func requireBearer(
	verifier credentialVerifier,
	logger *log.Logger,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			values := r.Header.Values("Authorization")
			if len(values) != 1 {
				logger.Printf(
					"authentication failed category=missing_or_malformed_authorization status=%d",
					http.StatusUnauthorized,
				)
				writeAuthError(w, http.StatusUnauthorized, "Bearer")
				return
			}

			credential, ok := bearerCredential(values[0])
			if !ok {
				logger.Printf(
					"authentication failed category=missing_or_malformed_authorization status=%d",
					http.StatusUnauthorized,
				)
				writeAuthError(w, http.StatusUnauthorized, "Bearer")
				return
			}

			identity, err := verifier.Verify(r.Context(), credential)
			if err != nil {
				status, challenge, category := mapVerificationError(err)
				logger.Printf(
					"authentication failed category=%s status=%d",
					category,
					status,
				)
				writeAuthError(w, status, challenge)
				return
			}
			if identity == nil {
				logger.Printf(
					"authentication failed category=invalid_verifier_result status=%d",
					http.StatusInternalServerError,
				)
				writeAuthError(w, http.StatusInternalServerError, "")
				return
			}

			ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerCredential parses the RFC 6750 Authorization scheme
// case-insensitively. Fields permits ordinary leading/trailing whitespace and
// multiple spaces after the scheme while rejecting embedded whitespace in the
// credential itself.
func bearerCredential(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}
	return fields[1], fields[1] != ""
}

func mapVerificationError(err error) (status int, challenge, category string) {
	switch {
	case errors.Is(err, bearerauth.ErrInsufficientScope):
		var scopeErr *bearerauth.InsufficientScopeError
		if !errors.As(err, &scopeErr) || scopeErr == nil ||
			scopeErr.MissingScope == "" {
			return http.StatusInternalServerError, "", "unexpected_error"
		}
		return http.StatusForbidden,
			`Bearer error="insufficient_scope", scope=` +
				strconv.Quote(scopeErr.MissingScope),
			"insufficient_scope"

	case errors.Is(err, bearerauth.ErrInvalidCredential):
		return http.StatusUnauthorized,
			`Bearer error="invalid_token"`,
			"invalid_credential"

	case errors.Is(err, bearerauth.ErrUntrustedIssuer):
		return http.StatusUnauthorized,
			`Bearer error="invalid_token"`,
			"untrusted_issuer"

	case errors.Is(err, bearerauth.ErrClientAppNotAllowed):
		return http.StatusUnauthorized,
			`Bearer error="invalid_token"`,
			"client_app_not_allowed"

	case errors.Is(err, bearerauth.ErrVerifierUnavailable):
		return http.StatusServiceUnavailable, "", "verifier_unavailable"

	default:
		return http.StatusInternalServerError, "", "unexpected_error"
	}
}

func identityFromContext(ctx context.Context) (*bearerauth.Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(*bearerauth.Identity)
	return identity, ok && identity != nil
}

type identityResponse struct {
	Subject        string                    `json:"subject"`
	SubjectType    bearerauth.SubjectType    `json:"subject_type"`
	Issuer         string                    `json:"issuer"`
	ClientID       string                    `json:"client_id"`
	Scopes         []string                  `json:"scopes"`
	ExpiresAt      time.Time                 `json:"expires_at"`
	CredentialType bearerauth.CredentialType `json:"credential_type"`
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func whoamiHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := identityFromContext(r.Context())
	if !ok {
		writeAuthError(w, http.StatusInternalServerError, "")
		return
	}

	// Identity contains only the SDK's normalized fields. It deliberately has
	// no raw credential or claim map, so neither credential kind can be echoed
	// in the response.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, identityResponse{
		Subject:        identity.Subject,
		SubjectType:    identity.SubjectType,
		Issuer:         identity.Issuer,
		ClientID:       identity.ClientID,
		Scopes:         identity.Scopes,
		ExpiresAt:      identity.ExpiresAt,
		CredentialType: identity.CredentialType,
	})
}

func writeAuthError(w http.ResponseWriter, status int, challenge string) {
	w.Header().Set("Cache-Control", "no-store")
	if challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}

	message := "internal_server_error"
	switch status {
	case http.StatusUnauthorized:
		message = "unauthorized"
	case http.StatusForbidden:
		message = "forbidden"
	case http.StatusServiceUnavailable:
		message = "service_unavailable"
		w.Header().Set("Retry-After", "1")
	}
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
