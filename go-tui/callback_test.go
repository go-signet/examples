package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/credstore"
)

func TestSanitizeOAuthError(t *testing.T) {
	tests := []struct {
		name             string
		errorCode        string
		errorDescription string
		wantContains     string
		wantNotContains  string
	}{
		{
			name:             "access_denied",
			errorCode:        "access_denied",
			errorDescription: "User denied the request",
			wantContains:     "Authorization was denied",
			wantNotContains:  "User denied",
		},
		{
			name:             "invalid_request",
			errorCode:        "invalid_request",
			errorDescription: "Missing required parameter: redirect_uri",
			wantContains:     "Invalid request",
			wantNotContains:  "redirect_uri",
		},
		{
			name:             "unauthorized_client",
			errorCode:        "unauthorized_client",
			errorDescription: "Client authentication failed",
			wantContains:     "Client is not authorized",
			wantNotContains:  "authentication failed",
		},
		{
			name:             "server_error",
			errorCode:        "server_error",
			errorDescription: "Internal database connection failed",
			wantContains:     "Server error",
			wantNotContains:  "database",
		},
		{
			name:             "temporarily_unavailable",
			errorCode:        "temporarily_unavailable",
			errorDescription: "Service overloaded",
			wantContains:     "temporarily unavailable",
			wantNotContains:  "overloaded",
		},
		{
			name:             "unknown_error",
			errorCode:        "custom_error_code",
			errorDescription: "Some internal error details",
			wantContains:     "Authentication failed",
			wantNotContains:  "internal",
		},
		{
			name:             "empty_description",
			errorCode:        "access_denied",
			errorDescription: "",
			wantContains:     "Authorization was denied",
			wantNotContains:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeOAuthError(tt.errorCode, tt.errorDescription)

			if tt.wantContains != "" && !strings.Contains(got, tt.wantContains) {
				t.Errorf("sanitizeOAuthError() = %q, want to contain %q", got, tt.wantContains)
			}

			if tt.wantNotContains != "" && strings.Contains(got, tt.wantNotContains) {
				t.Errorf(
					"sanitizeOAuthError() = %q, should not contain %q",
					got,
					tt.wantNotContains,
				)
			}
		})
	}
}

func TestSanitizeTokenExchangeError(t *testing.T) {
	tests := []struct {
		name            string
		err             error
		wantContains    string
		wantNotContains []string
	}{
		{
			name:            "generic_error",
			err:             errors.New("unauthorized_client: client authentication failed"),
			wantContains:    "Token exchange failed",
			wantNotContains: []string{"unauthorized_client", "authentication"},
		},
		{
			name:            "backend_service_error",
			err:             errors.New("backend service error: database connection failed"),
			wantContains:    "Token exchange failed",
			wantNotContains: []string{"backend", "database", "service"},
		},
		{
			name:            "internal_error",
			err:             errors.New("internal error: validation failed for user account"),
			wantContains:    "Token exchange failed",
			wantNotContains: []string{"internal", "validation", "account"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeTokenExchangeError(tt.err)

			if !strings.Contains(got, tt.wantContains) {
				t.Errorf(
					"sanitizeTokenExchangeError() = %q, want to contain %q",
					got,
					tt.wantContains,
				)
			}

			for _, notWant := range tt.wantNotContains {
				if strings.Contains(strings.ToLower(got), strings.ToLower(notWant)) {
					t.Errorf(
						"sanitizeTokenExchangeError() = %q, should not contain %q",
						got,
						notWant,
					)
				}
			}
		})
	}
}

type callbackServerResult struct {
	storage *credstore.Token
	err     error
}

// startCallbackServerAsync starts the callback server in a goroutine and
// returns a channel that will receive the result (storage or error).
func startCallbackServerAsync(
	t *testing.T, ctx context.Context, //nolint:revive // t before ctx in test helpers
	port int, state string,
	exchangeFn func(context.Context, string) (*credstore.Token, error),
) chan callbackServerResult {
	t.Helper()
	ch := make(chan callbackServerResult, 1)
	go func() {
		storage, err := startCallbackServer(ctx, port, state, defaultCallbackTimeout, exchangeFn)
		ch <- callbackServerResult{storage, err}
	}()
	// Give the server a moment to bind.
	time.Sleep(50 * time.Millisecond)
	return ch
}

// noExchangeFn returns an exchange function that fails the test if called.
func noExchangeFn(t *testing.T) func(context.Context, string) (*credstore.Token, error) {
	t.Helper()
	return func(_ context.Context, _ string) (*credstore.Token, error) {
		t.Error("exchangeFn should not be called")
		return nil, errors.New("should not be called")
	}
}

// stubExchangeFn returns an exchange function that validates the received code
// and returns a minimal token on success.
func stubExchangeFn(wantCode string) func(context.Context, string) (*credstore.Token, error) {
	return func(_ context.Context, gotCode string) (*credstore.Token, error) {
		if gotCode != wantCode {
			return nil, fmt.Errorf("unexpected code: got %q, want %q", gotCode, wantCode)
		}
		return &credstore.Token{AccessToken: "test-token"}, nil
	}
}

func TestCallbackServer_Success(t *testing.T) {
	const port = 19101
	state := "test-state-success"

	ch := startCallbackServerAsync(
		t,
		context.Background(),
		port,
		state,
		stubExchangeFn("mycode123"),
	)

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode123&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec // test-only HTTP call to local server
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Authorization Successful") {
		t.Errorf("expected success page, got: %s", string(body))
	}

	select {
	case result := <-ch:
		if result.err != nil {
			t.Errorf("expected success, got error: %v", result.err)
		}
		if result.storage == nil {
			t.Error("expected non-nil storage")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_StateMismatch(t *testing.T) {
	const port = 19102
	state := "expected-state"

	ch := startCallbackServerAsync(t, context.Background(), port, state, noExchangeFn(t))

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode&state=wrong-state",
		port,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec // test-only HTTP call to local server
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify browser shows sanitized message
	if !strings.Contains(bodyStr, "Authorization Failed") {
		t.Errorf("expected failure page for state mismatch, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "security issue") {
		t.Errorf("expected sanitized security message in browser, got: %s", bodyStr)
	}

	// Verify browser does NOT show CSRF attack details
	if strings.Contains(bodyStr, "CSRF") {
		t.Errorf("browser should not mention CSRF attack details, got: %s", bodyStr)
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected error for state mismatch, got nil")
		}
		// Terminal error should contain state_mismatch
		if !strings.Contains(result.err.Error(), "state_mismatch") {
			t.Errorf("expected terminal error to mention state_mismatch, got: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_OAuthError(t *testing.T) {
	const port = 19103
	state := "state-for-error"

	ch := startCallbackServerAsync(t, context.Background(), port, state, noExchangeFn(t))

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?error=access_denied&error_description=User+denied&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec // test-only HTTP call to local server
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify browser shows sanitized message
	if !strings.Contains(bodyStr, "Authorization Failed") {
		t.Errorf("expected failure page for access_denied, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Authorization was denied") {
		t.Errorf("expected sanitized message in browser, got: %s", bodyStr)
	}

	// Verify browser does NOT show detailed description
	if strings.Contains(bodyStr, "User denied") {
		t.Errorf("browser should not contain detailed error description, got: %s", bodyStr)
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected error for access_denied, got nil")
		}
		// Verify terminal error still contains full details
		if !strings.Contains(result.err.Error(), "access_denied") {
			t.Errorf("expected terminal error to mention access_denied, got: %v", result.err)
		}
		if !strings.Contains(result.err.Error(), "User denied") {
			t.Errorf("expected terminal error to contain detailed description, got: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_ExchangeFailure(t *testing.T) {
	const port = 19106
	state := "state-for-exchange-failure"

	ch := startCallbackServerAsync(t, context.Background(), port, state,
		func(_ context.Context, _ string) (*credstore.Token, error) {
			return nil, errors.New("unauthorized_client: backend service authentication failed")
		})

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode&state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec // test-only HTTP call to local server
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Verify browser shows generic message
	if !strings.Contains(bodyStr, "Authorization Failed") {
		t.Errorf("expected failure page for exchange error, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "Token exchange failed") {
		t.Errorf("expected sanitized message in browser, got: %s", bodyStr)
	}

	// Verify browser does NOT show backend error details
	if strings.Contains(bodyStr, "unauthorized_client") {
		t.Errorf("browser should not contain backend error code, got: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "backend service") {
		t.Errorf("browser should not contain backend error details, got: %s", bodyStr)
	}

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected error for exchange failure, got nil")
		}
		// Verify terminal error still contains full backend error
		if !strings.Contains(result.err.Error(), "unauthorized_client") {
			t.Errorf("expected terminal error to mention unauthorized_client, got: %v", result.err)
		}
		if !strings.Contains(result.err.Error(), "backend service") {
			t.Errorf("expected terminal error to contain full details, got: %v", result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_DoubleCallback(t *testing.T) {
	const port = 19105
	state := "test-state-double"

	ch := startCallbackServerAsync(t, context.Background(), port, state, stubExchangeFn("mycode"))

	url := fmt.Sprintf("http://127.0.0.1:%d/callback?code=mycode&state=%s", port, state)

	done := make(chan error, 2)
	for range 2 {
		go func() {
			resp, err := http.Get(url) //nolint:noctx,gosec // test-only HTTP call to local server
			if err == nil {
				resp.Body.Close()
			}
			done <- err
		}()
	}

	for range 2 {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("a callback handler goroutine hung on channel send")
		}
	}

	select {
	case result := <-ch:
		if result.err != nil {
			t.Errorf("expected success, got error: %v", result.err)
		}
		if result.storage == nil {
			t.Error("expected non-nil storage")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_MissingCode(t *testing.T) {
	const port = 19104
	state := "state-for-missing-code"

	ch := startCallbackServerAsync(t, context.Background(), port, state, noExchangeFn(t))

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?state=%s",
		port, state,
	)
	resp, err := http.Get(callbackURL) //nolint:noctx,gosec // test-only HTTP call to local server
	if err != nil {
		t.Fatalf("GET callback failed: %v", err)
	}
	defer resp.Body.Close()

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected error for missing code, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestCallbackServer_RejectsNonGetMethod(t *testing.T) {
	const port = 19107
	state := "test-state-method"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := startCallbackServerAsync(t, ctx, port, state, noExchangeFn(t))

	callbackURL := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?code=mycode&state=%s",
		port, state,
	)
	resp, err := http.Post(
		callbackURL,
		"",
		nil,
	) //nolint:noctx,gosec // test-only HTTP call to local server
	if err != nil {
		t.Fatalf("POST callback failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", resp.StatusCode)
	}

	cancel()

	select {
	case result := <-ch:
		if result.err == nil {
			t.Error("expected context cancellation error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for callback result")
	}
}

func TestWriteCallbackPage_SecurityHeaders(t *testing.T) {
	tests := []struct {
		name    string
		success bool
		message string
	}{
		{"success_page", true, ""},
		{"failure_page", false, "Something went wrong"},
	}

	wantHeaders := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeCallbackPage(w, tt.success, tt.message)
			resp := w.Result()
			defer resp.Body.Close()

			for name, want := range wantHeaders {
				if got := resp.Header.Get(name); got != want {
					t.Errorf("header %s = %q, want %q", name, got, want)
				}
			}
		})
	}
}
