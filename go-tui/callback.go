package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-signet/examples/go-tui/tui"
	"github.com/go-signet/sdk-go/credstore"
)

// browserErrorMessages overrides the TUI messages with shorter, browser-safe versions.
// Only codes that need different wording for the browser are listed here.
var browserErrorMessages = map[string]string{
	"access_denied":           "Authorization was denied. You may close this window.",
	"invalid_request":         "Invalid request. Please contact support.",
	"unauthorized_client":     "Client is not authorized.",
	"server_error":            "Server error. Please try again later.",
	"temporarily_unavailable": "Service is temporarily unavailable. Please try again later.",
}

// sanitizeOAuthError maps standard OAuth error codes to user-friendly messages
// that are safe to display in the browser. This prevents information disclosure
// while maintaining a good user experience.
// The errorDescription parameter is intentionally ignored to prevent leaking details.
func sanitizeOAuthError(errorCode, _ string) string {
	// Check browser-specific overrides first
	if msg, ok := browserErrorMessages[errorCode]; ok {
		return msg
	}
	// Fall back to the shared TUI error map
	if msg, ok := tui.OAuthErrorMessage(errorCode); ok {
		return msg
	}
	return "Authentication failed. Please check your terminal for details."
}

// sanitizeTokenExchangeError sanitizes backend token exchange errors to prevent
// leaking sensitive implementation details such as service names, internal error
// codes, or validation mechanisms.
// The err parameter is intentionally ignored to prevent leaking any details.
func sanitizeTokenExchangeError(_ error) string {
	// Always return a generic message to prevent information disclosure.
	// The full error is still logged to the terminal for debugging.
	return "Token exchange failed. Please try again."
}

// ErrCallbackTimeout is returned when no browser callback is received within the callback timeout.
// Callers can use errors.Is to distinguish a timeout from other authorization errors
// and decide whether to fall back to Device Code Flow.
var ErrCallbackTimeout = errors.New("browser authorization timed out")

// callbackResult holds the outcome of the local callback round-trip.
type callbackResult struct {
	Storage      *credstore.Token
	Error        string
	Desc         string // Detailed description (for terminal only)
	SanitizedMsg string // User-friendly message (for browser only)
}

// startCallbackServer starts a local HTTP server on the given port and waits
// for the OAuth callback. It validates the returned state against expectedState,
// calls exchangeFn to exchange the code for tokens, and returns the resulting
// token (or an error).
//
// The server shuts itself down after the first request.
func startCallbackServer(ctx context.Context, port int, expectedState string,
	cbTimeout time.Duration,
	exchangeFn func(context.Context, string) (*credstore.Token, error),
) (*credstore.Token, error) {
	resultCh := make(chan callbackResult, 1)

	var once sync.Once
	sendResult := func(r callbackResult) {
		once.Do(func() { resultCh <- r })
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()

		if oauthErr := q.Get("error"); oauthErr != "" {
			desc := q.Get("error_description")
			sanitized := sanitizeOAuthError(oauthErr, desc)
			writeCallbackPage(w, false, sanitized)
			sendResult(callbackResult{Error: oauthErr, Desc: desc, SanitizedMsg: sanitized})
			return
		}

		state := q.Get("state")
		if subtle.ConstantTimeCompare([]byte(state), []byte(expectedState)) == 0 {
			sanitized := "Authorization failed. Possible security issue detected."
			writeCallbackPage(w, false, sanitized)
			sendResult(callbackResult{
				Error:        "state_mismatch",
				Desc:         "State parameter does not match. Possible CSRF attack.",
				SanitizedMsg: sanitized,
			})
			return
		}

		code := q.Get("code")
		if code == "" {
			sanitized := "Authorization failed. Missing authorization code."
			writeCallbackPage(w, false, sanitized)
			sendResult(callbackResult{
				Error:        "missing_code",
				Desc:         "code parameter missing",
				SanitizedMsg: sanitized,
			})
			return
		}

		storage, exchangeErr := exchangeFn(r.Context(), code)
		if exchangeErr != nil {
			sanitized := sanitizeTokenExchangeError(exchangeErr)
			writeCallbackPage(w, false, sanitized)
			sendResult(callbackResult{
				Error:        "token_exchange_failed",
				Desc:         exchangeErr.Error(),
				SanitizedMsg: sanitized,
			})
			return
		}
		writeCallbackPage(w, true, "")
		sendResult(callbackResult{Storage: storage})
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", srv.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server on port %d: %w", port, err)
	}

	go func() {
		_ = srv.Serve(ln)
	}()

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	timer := time.NewTimer(cbTimeout)
	defer timer.Stop()

	select {
	case result := <-resultCh:
		if result.Error != "" {
			if result.Desc != "" {
				return nil, fmt.Errorf("%s: %s", result.Error, result.Desc)
			}
			return nil, errors.New(result.Error)
		}
		return result.Storage, nil

	case <-timer.C:
		return nil, fmt.Errorf("%w after %s", ErrCallbackTimeout, cbTimeout)

	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// writeCallbackPage writes a minimal HTML response to the browser tab.
// The message parameter should be pre-sanitized for security.
func writeCallbackPage(w http.ResponseWriter, success bool, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if success {
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Authorization Successful</title></head>
<body style="font-family:sans-serif;text-align:center;padding:4rem">
  <h1 style="color:#2ea44f">&#10003; Authorization Successful</h1>
  <p>You have been successfully authorized.</p>
  <p>You can close this tab and return to your terminal.</p>
</body>
</html>`)
		return
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Authorization Failed</title></head>
<body style="font-family:sans-serif;text-align:center;padding:4rem">
  <h1 style="color:#cb2431">&#10007; Authorization Failed</h1>
  <p>%s</p>
  <p>You can close this tab and check your terminal for details.</p>
</body>
</html>`, html.EscapeString(message))
}
