package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-signet/examples/go-tui/tui"
	"golang.org/x/oauth2"
)

const testAccessToken = "test-access-token"

// drainUpdates consumes FlowUpdate messages in the background so the producer
// never blocks. It signals the goroutine to stop via a done channel on
// cleanup, without closing the producer-owned updates channel.
func drainUpdates(t *testing.T, ch <-chan tui.FlowUpdate) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-ch:
			case <-done:
				return
			}
		}
	}()
}

func TestPollForToken_AuthorizationPending(t *testing.T) {
	attempts := atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)

		if attempts.Load() < 3 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error":             "authorization_pending",
				"error_description": "User has not yet authorized",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  testAccessToken,
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := testConfig(t)

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	updates := make(chan tui.FlowUpdate, 100)
	drainUpdates(t, updates)

	token, err := pollForTokenWithUpdates(ctx, cfg, config, deviceAuth, updates)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if token.AccessToken != testAccessToken {
		t.Errorf("access token = %q, want %q", token.AccessToken, testAccessToken)
	}
	if attempts.Load() < 3 {
		t.Errorf("expected at least 3 attempts, got %d", attempts.Load())
	}
}

func TestPollForToken_SlowDown(t *testing.T) {
	attempts := atomic.Int32{}
	slowDownCount := atomic.Int32{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)

		if attempts.Load() <= 2 {
			slowDownCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error":             "slow_down",
				"error_description": "Polling too frequently",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		if attempts.Load() < 5 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{
				"error":             "authorization_pending",
				"error_description": "User has not yet authorized",
			}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  testAccessToken,
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := testConfig(t)

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	updates := make(chan tui.FlowUpdate, 100)
	drainUpdates(t, updates)

	token, err := pollForTokenWithUpdates(ctx, cfg, config, deviceAuth, updates)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if token.AccessToken != testAccessToken {
		t.Errorf("access token = %q, want %q", token.AccessToken, testAccessToken)
	}
	if slowDownCount.Load() < 2 {
		t.Errorf("expected at least 2 slow_down responses, got %d", slowDownCount.Load())
	}
}

// pollForTokenErrorTest is a shared helper for tests that expect pollForTokenWithUpdates
// to return a specific error when the server responds with a terminal OAuth error code.
func pollForTokenErrorTest(t *testing.T, errCode, errDesc, expectedMsg string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"error":             errCode,
			"error_description": errDesc,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := testConfig(t)

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	updates := make(chan tui.FlowUpdate, 100)
	drainUpdates(t, updates)

	_, err := pollForTokenWithUpdates(ctx, cfg, config, deviceAuth, updates)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != expectedMsg {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPollForToken_ExpiredToken(t *testing.T) {
	pollForTokenErrorTest(t,
		"expired_token",
		"Device code has expired",
		"device code expired, please restart the flow",
	)
}

func TestPollForToken_AccessDenied(t *testing.T) {
	pollForTokenErrorTest(t,
		"access_denied",
		"User denied the authorization request",
		"user denied authorization",
	)
}

func TestPollForToken_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"error":             "authorization_pending",
			"error_description": "User has not yet authorized",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := testConfig(t)

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	updates := make(chan tui.FlowUpdate, 100)
	drainUpdates(t, updates)

	_, err := pollForTokenWithUpdates(ctx, cfg, config, deviceAuth, updates)
	if err == nil {
		t.Fatal("expected context timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded in error chain, got: %v", err)
	}
}

func TestPollForToken_NegativeInterval(t *testing.T) {
	// A malicious or buggy server may return a negative poll interval. It must
	// be clamped to the default rather than reaching time.NewTicker (which
	// panics on a non-positive duration and would crash the whole CLI).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"error":             "authorization_pending",
			"error_description": "User has not yet authorized",
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := testConfig(t)

	config := &oauth2.Config{
		ClientID: "test-client",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}
	deviceAuth := &oauth2.DeviceAuthResponse{
		DeviceCode: "test-device-code",
		Interval:   -1, // negative — must be clamped, not passed to NewTicker
	}

	// Short context: with the interval clamped to the 5s default, the first poll
	// never fires before this deadline, so the call returns via ctx instead of
	// waiting. The assertion is simply that it returns rather than panicking.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	updates := make(chan tui.FlowUpdate, 100)
	drainUpdates(t, updates)

	_, err := pollForTokenWithUpdates(ctx, cfg, config, deviceAuth, updates)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}

func TestExchangeDeviceCode_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse form: %v", err)
		}
		if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("unexpected grant_type: %s", r.FormValue("grant_type"))
		}
		if r.FormValue("device_code") != "test-device-code" {
			t.Errorf("unexpected device_code: %s", r.FormValue("device_code"))
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token":  testAccessToken,
			"refresh_token": "test-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := testConfig(t)

	ctx := context.Background()
	token, err := exchangeDeviceCode(ctx, cfg, server.URL, "test-client", "test-device-code")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if token.AccessToken != testAccessToken {
		t.Errorf("access token = %q, want %q", token.AccessToken, testAccessToken)
	}
	if token.RefreshToken != "test-refresh-token" {
		t.Errorf("refresh token = %q, want %q", token.RefreshToken, "test-refresh-token")
	}
}
