package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"github.com/go-signet/sdk-go/credstore"
)

// testConfig returns an *AppConfig with test defaults (no global state needed).
func testConfig(t *testing.T) *AppConfig {
	t.Helper()
	rc, err := retry.NewClient()
	if err != nil {
		t.Fatalf("failed to create retry client: %v", err)
	}
	serverURL := "http://localhost:8080"
	return &AppConfig{
		ServerURL:   serverURL,
		ClientID:    "test-client",
		Scope:       "email profile",
		RetryClient: rc,
		Store: credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		),
		Endpoints:                defaultEndpoints(serverURL),
		TokenExchangeTimeout:     defaultTokenExchangeTimeout,
		TokenVerificationTimeout: defaultTokenVerificationTimeout,
		RefreshTokenTimeout:      defaultRefreshTokenTimeout,
		DeviceCodeRequestTimeout: defaultDeviceCodeRequestTimeout,
		CallbackTimeout:          defaultCallbackTimeout,
		UserInfoTimeout:          defaultUserInfoTimeout,
		DiscoveryTimeout:         defaultDiscoveryTimeout,
		RevocationTimeout:        defaultRevocationTimeout,
		MaxResponseBodySize:      defaultMaxResponseBodySize,
	}
}

// -----------------------------------------------------------------------
// Config helpers
// -----------------------------------------------------------------------

func TestValidateServerURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid http", "http://localhost:8080", false},
		{"valid https", "https://auth.example.com", false},
		{"empty", "", true},
		{"no scheme", "localhost:8080", true},
		{"bad scheme", "ftp://example.com", true},
		{"no host", "http://", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServerURL(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateServerURL(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestGetConfig_Priority(t *testing.T) {
	t.Setenv("MYKEY", "from-env")

	if got := getConfig("from-flag", "MYKEY", "default"); got != "from-flag" {
		t.Errorf("expected flag value, got %q", got)
	}
	if got := getConfig("", "MYKEY", "default"); got != "from-env" {
		t.Errorf("expected env value, got %q", got)
	}

	t.Setenv("MYKEY", "")
	if got := getConfig("", "MYKEY", "default"); got != "default" {
		t.Errorf("expected default, got %q", got)
	}
}

func TestIsPublicClient(t *testing.T) {
	cfg := &AppConfig{ClientSecret: ""}
	if !cfg.IsPublicClient() {
		t.Error("expected public client when secret is empty")
	}
	cfg.ClientSecret = "secret"
	if cfg.IsPublicClient() {
		t.Error("expected confidential client when secret is set")
	}
}

// -----------------------------------------------------------------------
// Token response validation
// -----------------------------------------------------------------------

func TestValidateTokenResponse(t *testing.T) {
	tests := []struct {
		name        string
		accessToken string
		tokenType   string
		expiresIn   int
		wantErr     bool
	}{
		{"valid bearer", "a-long-enough-token", "Bearer", 3600, false},
		{"valid empty type", "a-long-enough-token", "", 3600, false},
		{"empty access token", "", "Bearer", 3600, true},
		{"too short token", "short", "Bearer", 3600, true},
		{"zero expires_in", "a-long-enough-token", "Bearer", 0, true},
		{"negative expires_in", "a-long-enough-token", "Bearer", -1, true},
		{"wrong token type", "a-long-enough-token", "MAC", 3600, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenResponse(tc.accessToken, tc.tokenType, tc.expiresIn)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTokenResponse() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Token storage
// -----------------------------------------------------------------------

func TestSaveAndLoadTokens(t *testing.T) {
	store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))
	clientID := "test-client-id"

	storage := credstore.Token{
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		ClientID:     clientID,
	}

	if err := store.Save(clientID, storage); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	loaded, err := store.Load(clientID)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.AccessToken != storage.AccessToken {
		t.Errorf("AccessToken mismatch: got %q, want %q", loaded.AccessToken, storage.AccessToken)
	}
	if loaded.RefreshToken != storage.RefreshToken {
		t.Errorf(
			"RefreshToken mismatch: got %q, want %q",
			loaded.RefreshToken,
			storage.RefreshToken,
		)
	}
}

func TestSaveTokens_MultipleClients(t *testing.T) {
	store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))

	for _, id := range []string{"client-a", "client-b"} {
		if err := store.Save(id, credstore.Token{
			AccessToken:  "token-" + id,
			RefreshToken: "refresh-" + id,
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
			ClientID:     id,
		}); err != nil {
			t.Fatalf("Save(%s) error: %v", id, err)
		}
	}

	for _, id := range []string{"client-a", "client-b"} {
		loaded, err := store.Load(id)
		if err != nil {
			t.Fatalf("Load(%s) error: %v", id, err)
		}
		if loaded.AccessToken != "token-"+id {
			t.Errorf("Load(%s): AccessToken = %q, want %q", id, loaded.AccessToken, "token-"+id)
		}
	}
}

func TestSaveTokens_ConcurrentWrites(t *testing.T) {
	store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			cid := fmt.Sprintf("client-%d", id)
			if err := store.Save(cid, credstore.Token{
				AccessToken:  fmt.Sprintf("access-token-%d", id),
				RefreshToken: fmt.Sprintf("refresh-token-%d", id),
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(time.Hour),
				ClientID:     cid,
			}); err != nil {
				t.Errorf("goroutine %d: Save() error: %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		id := fmt.Sprintf("client-%d", i)
		if _, err := store.Load(id); err != nil {
			t.Errorf("Load(%s) error: %v", id, err)
		}
	}
}

// -----------------------------------------------------------------------
// Authorization URL construction
// -----------------------------------------------------------------------

func TestBuildAuthURL_ContainsRequiredParams(t *testing.T) {
	cfg := &AppConfig{
		ServerURL:   "http://localhost:8080",
		ClientID:    "my-client-id",
		RedirectURI: "http://localhost:8888/callback",
		Scope:       "email profile",
		Endpoints:   defaultEndpoints("http://localhost:8080"),
	}

	pkce := &PKCEParams{
		Verifier:  "test-verifier",
		Challenge: "test-challenge",
		Method:    "S256",
	}
	state := "random-state"

	u := buildAuthURL(cfg, state, pkce)

	for _, want := range []string{
		"client_id=my-client-id",
		"redirect_uri=",
		"response_type=code",
		"scope=",
		"state=random-state",
		"code_challenge=test-challenge",
		"code_challenge_method=S256",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("auth URL missing %q\nURL: %s", want, u)
		}
	}
}

// -----------------------------------------------------------------------
// Refresh token: rotation vs fixed mode
// -----------------------------------------------------------------------

func TestRefreshAccessToken_RotationMode(t *testing.T) {
	tests := []struct {
		name                 string
		oldRefreshToken      string
		responseRefreshToken string
		expectedRefreshToken string
	}{
		{
			name:                 "rotation mode - server returns new refresh token",
			oldRefreshToken:      "old-refresh-token",
			responseRefreshToken: "new-refresh-token",
			expectedRefreshToken: "new-refresh-token",
		},
		{
			name:                 "fixed mode - server doesn't return refresh token",
			oldRefreshToken:      "old-refresh-token",
			responseRefreshToken: "",
			expectedRefreshToken: "old-refresh-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if err := r.ParseForm(); err != nil {
						http.Error(w, "bad form", http.StatusBadRequest)
						return
					}
					resp := map[string]any{
						"access_token": "new-access-token",
						"token_type":   "Bearer",
						"expires_in":   3600,
					}
					if tt.responseRefreshToken != "" {
						resp["refresh_token"] = tt.responseRefreshToken
					}
					w.Header().Set("Content-Type", "application/json")
					if err := json.NewEncoder(w).Encode(resp); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
					}
				}),
			)
			defer srv.Close()

			cfg := testConfig(t)
			cfg.ServerURL = srv.URL
			cfg.Endpoints = defaultEndpoints(srv.URL)
			cfg.ClientID = "test-client-rotation"

			storage, err := refreshAccessToken(context.Background(), cfg, tt.oldRefreshToken)
			if err != nil {
				t.Fatalf("refreshAccessToken() error: %v", err)
			}
			if storage.RefreshToken != tt.expectedRefreshToken {
				t.Errorf(
					"RefreshToken = %q, want %q",
					storage.RefreshToken,
					tt.expectedRefreshToken,
				)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Device code request with retry
// -----------------------------------------------------------------------

func TestRequestDeviceCode_WithRetry(t *testing.T) {
	var attemptCount atomic.Int32
	var testServer *httptest.Server

	testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := attemptCount.Add(1)
		if count < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"device_code":               "test-device-code",
			"user_code":                 "TEST-CODE",
			"verification_uri":          testServer.URL + "/device",
			"verification_uri_complete": testServer.URL + "/device?user_code=TEST-CODE",
			"expires_in":                600,
			"interval":                  5,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	defer testServer.Close()

	cfg := testConfig(t)
	cfg.ServerURL = testServer.URL
	cfg.Endpoints = defaultEndpoints(testServer.URL)

	resp, err := requestDeviceCode(context.Background(), cfg)
	if err != nil {
		t.Fatalf("requestDeviceCode() error: %v", err)
	}
	if resp.DeviceCode != "test-device-code" {
		t.Errorf("DeviceCode = %q, want %q", resp.DeviceCode, "test-device-code")
	}
	if attemptCount.Load() != 2 {
		t.Errorf("expected 2 attempts (1 retry), got %d", attemptCount.Load())
	}
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
