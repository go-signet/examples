package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/go-signet/sdk-go/oauth"
)

func TestRunTokenDelete(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(credstore.Store[credstore.Token])
		wantCode  int
		checkOut  func(t *testing.T, out string)
		checkErr  func(t *testing.T, errOut string)
		postCheck func(t *testing.T, store credstore.Store[credstore.Token])
	}{
		{
			name: "token exists delete succeeds",
			setup: func(s credstore.Store[credstore.Token]) {
				if err := s.Save("test-id", credstore.Token{
					AccessToken: "my-access-token",
					ExpiresAt:   time.Now().Add(time.Hour),
					ClientID:    "test-id",
				}); err != nil {
					t.Fatalf("setup: failed to save token: %v", err)
				}
			},
			wantCode: 0,
			checkOut: func(t *testing.T, out string) {
				if !strings.Contains(out, "deleted") {
					t.Errorf("expected 'deleted' in stdout, got: %q", out)
				}
			},
		},
		{
			name:     "no token stored",
			setup:    func(s credstore.Store[credstore.Token]) {},
			wantCode: 1,
			checkErr: func(t *testing.T, errOut string) {
				if !strings.Contains(errOut, "no stored token") {
					t.Errorf("expected 'no stored token' in stderr, got: %q", errOut)
				}
			},
		},
		{
			name: "delete then load returns not found",
			setup: func(s credstore.Store[credstore.Token]) {
				if err := s.Save("test-id", credstore.Token{
					AccessToken: "my-access-token",
					ExpiresAt:   time.Now().Add(time.Hour),
					ClientID:    "test-id",
				}); err != nil {
					t.Fatalf("setup: failed to save token: %v", err)
				}
			},
			wantCode: 0,
			postCheck: func(t *testing.T, store credstore.Store[credstore.Token]) {
				_, err := store.Load("test-id")
				if !errors.Is(err, credstore.ErrNotFound) {
					t.Errorf("expected ErrNotFound after delete, got: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := credstore.NewTokenFileStore(
				filepath.Join(t.TempDir(), "tokens.json"),
			)
			tc.setup(store)
			cfg := &AppConfig{ClientID: "test-id", Store: store}
			var stdout, stderr bytes.Buffer
			code := runTokenDelete(
				context.Background(), cfg, true, &stdout, &stderr,
			)
			if code != tc.wantCode {
				t.Errorf("exit code: got %d, want %d", code, tc.wantCode)
			}
			if tc.checkOut != nil {
				tc.checkOut(t, stdout.String())
			}
			if tc.checkErr != nil {
				tc.checkErr(t, stderr.String())
			}
			if tc.postCheck != nil {
				tc.postCheck(t, store)
			}
		})
	}
}

func TestRunTokenDelete_ServerRevocation(t *testing.T) {
	t.Run("successful revocation and local delete", func(t *testing.T) {
		type revokeCall struct {
			token         string
			tokenTypeHint string
		}
		var revokeCalls []revokeCall
		var mu sync.Mutex
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					http.Error(w, "bad form", http.StatusBadRequest)
					return
				}
				mu.Lock()
				revokeCalls = append(revokeCalls, revokeCall{
					token:         r.FormValue("token"),
					tokenTypeHint: r.FormValue("token_type_hint"),
				})
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken:  "access-123",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(time.Hour),
			ClientID:     "test-id",
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &AppConfig{
			ClientID:          "test-id",
			ServerURL:         srv.URL,
			Endpoints:         oauth.Endpoints{RevocationURL: srv.URL + "/oauth/revoke"},
			RevocationTimeout: defaultRevocationTimeout,
			RetryClient:       rc,
			Store:             store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenDelete(
			context.Background(), cfg, false, &stdout, &stderr,
		)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "revoked on server") {
			t.Errorf("expected 'revoked on server' in stdout, got: %q", stdout.String())
		}
		if !strings.Contains(stdout.String(), "deleted") {
			t.Errorf("expected 'deleted' in stdout, got: %q", stdout.String())
		}

		mu.Lock()
		defer mu.Unlock()
		if len(revokeCalls) != 2 {
			t.Fatalf("expected 2 revoke calls, got %d", len(revokeCalls))
		}
		// Revocations run concurrently, so order is non-deterministic.
		// Build a map from token to its type hint for assertion.
		hintByToken := make(map[string]string, len(revokeCalls))
		for _, c := range revokeCalls {
			hintByToken[c.token] = c.tokenTypeHint
		}
		if hint, ok := hintByToken["refresh-456"]; !ok {
			t.Errorf("expected refresh token to be revoked, got %v", revokeCalls)
		} else if hint != "refresh_token" {
			t.Errorf("refresh token_type_hint: got %q, want %q", hint, "refresh_token")
		}
		if hint, ok := hintByToken["access-123"]; !ok {
			t.Errorf("expected access token to be revoked, got %v", revokeCalls)
		} else if hint != "access_token" {
			t.Errorf("access token_type_hint: got %q, want %q", hint, "access_token")
		}
	})

	t.Run("server error graceful degradation", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "access-123",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &AppConfig{
			ClientID:          "test-id",
			ServerURL:         srv.URL,
			Endpoints:         oauth.Endpoints{RevocationURL: srv.URL + "/oauth/revoke"},
			RevocationTimeout: defaultRevocationTimeout,
			RetryClient:       rc,
			Store:             store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenDelete(
			context.Background(), cfg, false, &stdout, &stderr,
		)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0", code)
		}
		if !strings.Contains(stderr.String(), "Warning") {
			t.Errorf("expected warning in stderr, got: %q", stderr.String())
		}
		if !strings.Contains(stdout.String(), "deleted") {
			t.Errorf("token should still be deleted locally, got: %q", stdout.String())
		}
	})

	t.Run("local-only skips server call", func(t *testing.T) {
		var serverCalled atomic.Bool
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				serverCalled.Store(true)
				w.WriteHeader(http.StatusOK)
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "access-123",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &AppConfig{
			ClientID:          "test-id",
			Endpoints:         oauth.Endpoints{RevocationURL: srv.URL + "/oauth/revoke"},
			RevocationTimeout: defaultRevocationTimeout,
			RetryClient:       rc,
			Store:             store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenDelete(
			context.Background(), cfg, true, &stdout, &stderr,
		)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0", code)
		}
		if serverCalled.Load() {
			t.Error("server should not have been called with --local-only")
		}
	})

	t.Run("only access token no refresh token", func(t *testing.T) {
		var (
			callCount        int
			gotToken         string
			gotTokenTypeHint string
			mu               sync.Mutex
		)
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					http.Error(w, "bad form", http.StatusBadRequest)
					return
				}
				mu.Lock()
				callCount++
				gotToken = r.FormValue("token")
				gotTokenTypeHint = r.FormValue("token_type_hint")
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "access-only",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &AppConfig{
			ClientID:          "test-id",
			ServerURL:         srv.URL,
			Endpoints:         oauth.Endpoints{RevocationURL: srv.URL + "/oauth/revoke"},
			RevocationTimeout: defaultRevocationTimeout,
			RetryClient:       rc,
			Store:             store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenDelete(
			context.Background(), cfg, false, &stdout, &stderr,
		)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0", code)
		}

		mu.Lock()
		defer mu.Unlock()
		if callCount != 1 {
			t.Fatalf("expected 1 revoke call (access only), got %d", callCount)
		}
		if gotToken != "access-only" {
			t.Errorf("token: got %q, want %q", gotToken, "access-only")
		}
		if gotTokenTypeHint != "access_token" {
			t.Errorf("token_type_hint: got %q, want %q", gotTokenTypeHint, "access_token")
		}
	})
}

func TestRunTokenGet(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(credstore.Store[credstore.Token])
		jsonOut  bool
		wantCode int
		checkOut func(t *testing.T, out string)
		checkErr func(t *testing.T, errOut string)
	}{
		{
			name: "token found plain output",
			setup: func(s credstore.Store[credstore.Token]) {
				if err := s.Save("test-id", credstore.Token{
					AccessToken: "my-access-token",
					ExpiresAt:   time.Now().Add(time.Hour),
					ClientID:    "test-id",
				}); err != nil {
					t.Fatalf("setup: failed to save token: %v", err)
				}
			},
			jsonOut:  false,
			wantCode: 0,
			checkOut: func(t *testing.T, out string) {
				if out != "my-access-token\n" {
					t.Errorf("got %q, want %q", out, "my-access-token\n")
				}
			},
		},
		{
			name: "token found json output",
			setup: func(s credstore.Store[credstore.Token]) {
				if err := s.Save("test-id", credstore.Token{
					AccessToken: "my-access-token",
					ExpiresAt:   time.Now().Add(time.Hour),
					ClientID:    "test-id",
				}); err != nil {
					t.Fatalf("setup: failed to save token: %v", err)
				}
			},
			jsonOut:  true,
			wantCode: 0,
			checkOut: func(t *testing.T, out string) {
				var result tokenGetOutput
				if err := json.Unmarshal([]byte(out), &result); err != nil {
					t.Fatalf("invalid JSON: %v", err)
				}
				if result.AccessToken != "my-access-token" {
					t.Errorf("access_token: got %q", result.AccessToken)
				}
				if result.Expired {
					t.Error("expected expired=false")
				}
			},
		},
		{
			name:     "no token stored",
			setup:    func(s credstore.Store[credstore.Token]) {},
			jsonOut:  false,
			wantCode: 1,
			checkErr: func(t *testing.T, errOut string) {
				if !strings.Contains(errOut, "no stored token") {
					t.Errorf("expected 'no stored token' in stderr, got: %q", errOut)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := credstore.NewTokenFileStore(
				filepath.Join(t.TempDir(), "tokens.json"),
			)
			tc.setup(store)
			cfg := &AppConfig{
				ClientID:         "test-id",
				Store:            store,
				RefreshThreshold: defaultRefreshThreshold,
			}
			var stdout, stderr bytes.Buffer
			code := runTokenGet(context.Background(), cfg, nil, tc.jsonOut, &stdout, &stderr)
			if code != tc.wantCode {
				t.Errorf("exit code: got %d, want %d", code, tc.wantCode)
			}
			if tc.checkOut != nil {
				tc.checkOut(t, stdout.String())
			}
			if tc.checkErr != nil {
				tc.checkErr(t, stderr.String())
			}
		})
	}
}

// tokenGetRefreshConfig builds an *AppConfig wired to tokenURL with a token
// store seeded with tok, suitable for exercising `token get`'s proactive
// refresh. RefreshThreshold defaults to 5m.
func tokenGetRefreshConfig(t *testing.T, tokenURL string, tok credstore.Token) *AppConfig {
	t.Helper()
	rc, err := retry.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	store := credstore.NewTokenFileStore(
		filepath.Join(t.TempDir(), "tokens.json"),
	)
	if err := store.Save("test-id", tok); err != nil {
		t.Fatal(err)
	}
	return &AppConfig{
		ClientID:            "test-id",
		Endpoints:           oauth.Endpoints{TokenURL: tokenURL},
		RefreshTokenTimeout: defaultRefreshTokenTimeout,
		MaxResponseBodySize: defaultMaxResponseBodySize,
		RefreshThreshold:    defaultRefreshThreshold,
		RetryClient:         rc,
		Store:               store,
	}
}

func TestRunTokenGet_ProactiveRefresh(t *testing.T) {
	t.Run("happy path refreshes token near expiry", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					http.Error(w, "bad form", http.StatusBadRequest)
					return
				}
				if got := r.FormValue("grant_type"); got != "refresh_token" {
					t.Errorf("grant_type: got %q, want refresh_token", got)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(
					`{"access_token":"new-access-token-value","token_type":"Bearer","expires_in":3600}`,
				))
			}),
		)
		defer srv.Close()

		// Token expires in 2 minutes — inside the default 5m threshold.
		cfg := tokenGetRefreshConfig(t, srv.URL+"/oauth/token", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(2 * time.Minute),
			ClientID:     "test-id",
		})

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, nil, false, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if strings.TrimSpace(stdout.String()) != "new-access-token-value" {
			t.Errorf("stdout: got %q, want the refreshed token", stdout.String())
		}
		// Store must hold the refreshed token with a future expiry.
		saved, err := cfg.Store.Load("test-id")
		if err != nil {
			t.Fatal(err)
		}
		if saved.AccessToken != "new-access-token-value" {
			t.Errorf("stored access token: got %q, want refreshed value", saved.AccessToken)
		}
		if !saved.ExpiresAt.After(time.Now()) {
			t.Errorf("stored ExpiresAt %v should be in the future", saved.ExpiresAt)
		}
	})

	t.Run("json output reflects refreshed expiry", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(
					`{"access_token":"new-access-token-value","token_type":"Bearer","expires_in":3600}`,
				))
			}),
		)
		defer srv.Close()

		cfg := tokenGetRefreshConfig(t, srv.URL+"/oauth/token", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(2 * time.Minute),
			ClientID:     "test-id",
		})

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, nil, true, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		var result tokenGetOutput
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if result.AccessToken != "new-access-token-value" {
			t.Errorf("access_token: got %q, want refreshed value", result.AccessToken)
		}
		if result.Expired {
			t.Error("expected expired=false after refresh")
		}
	})

	t.Run("refresh failure with valid token degrades gracefully", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}),
		)
		defer srv.Close()

		// Token expires in 4 minutes — inside the threshold but still valid.
		cfg := tokenGetRefreshConfig(t, srv.URL+"/oauth/token", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(4 * time.Minute),
			ClientID:     "test-id",
		})

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, nil, false, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0 (graceful); stderr: %s", code, stderr.String())
		}
		if strings.TrimSpace(stdout.String()) != "old-access-token" {
			t.Errorf("stdout: got %q, want the existing token", stdout.String())
		}
		if !strings.Contains(stderr.String(), "refresh failed") {
			t.Errorf("expected refresh-failure warning in stderr, got: %q", stderr.String())
		}
		if strings.Contains(stderr.String(), "refresh-456") {
			t.Errorf("refresh token must not appear in output, got: %q", stderr.String())
		}
	})

	t.Run("expired token with invalid refresh token fails", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(
					`{"error":"invalid_grant","error_description":"refresh token expired"}`,
				))
			}),
		)
		defer srv.Close()

		// Token already expired.
		cfg := tokenGetRefreshConfig(t, srv.URL+"/oauth/token", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(-1 * time.Minute),
			ClientID:     "test-id",
		})

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, nil, false, &stdout, &stderr)
		if code == 0 {
			t.Fatalf("exit code: got 0, want non-zero; stdout: %s", stdout.String())
		}
		if !strings.Contains(stderr.String(), "re-authenticate") {
			t.Errorf("expected re-authentication hint in stderr, got: %q", stderr.String())
		}
		if strings.Contains(stderr.String(), "refresh-456") {
			t.Errorf("refresh token must not appear in output, got: %q", stderr.String())
		}
	})

	t.Run("token far from expiry makes no network request", func(t *testing.T) {
		var called atomic.Bool
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called.Store(true)
				w.WriteHeader(http.StatusOK)
			}),
		)
		defer srv.Close()

		// Token expires in 1 hour — well beyond the 5m threshold.
		cfg := tokenGetRefreshConfig(t, srv.URL+"/oauth/token", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(time.Hour),
			ClientID:     "test-id",
		})

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, nil, false, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if called.Load() {
			t.Error("no network request expected when token is far from expiry")
		}
		if strings.TrimSpace(stdout.String()) != "old-access-token" {
			t.Errorf("stdout: got %q, want the cached token", stdout.String())
		}
	})
}

func TestRunTokenGet_DefersDiscoveryUntilRefresh(t *testing.T) {
	t.Run("far from expiry makes no request including discovery", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))
		if err := store.Save("test-id", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(time.Hour),
			ClientID:     "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		// Endpoints intentionally left empty: if the command resolved discovery
		// eagerly it would hit srv (via ServerURL). It must not, because the
		// token is far from expiry.
		cfg := &AppConfig{
			ClientID:            "test-id",
			ServerURL:           srv.URL,
			RefreshThreshold:    defaultRefreshThreshold,
			RefreshTokenTimeout: defaultRefreshTokenTimeout,
			DiscoveryTimeout:    defaultDiscoveryTimeout,
			MaxResponseBodySize: defaultMaxResponseBodySize,
			RetryClient:         rc,
			Store:               store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, nil, false, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if hits.Load() != 0 {
			t.Errorf("expected zero network requests (incl. discovery), got %d", hits.Load())
		}
		if strings.TrimSpace(stdout.String()) != "old-access-token" {
			t.Errorf("stdout: got %q, want the cached token", stdout.String())
		}
	})

	t.Run("near expiry resolves discovery then refreshes", func(t *testing.T) {
		var discoveryHit, tokenHit atomic.Bool
		var srvURL string
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					discoveryHit.Store(true)
					meta := map[string]any{
						"issuer":                                srvURL,
						"authorization_endpoint":                srvURL + "/auth",
						"token_endpoint":                        srvURL + "/token",
						"device_authorization_endpoint":         srvURL + "/device",
						"userinfo_endpoint":                     srvURL + "/userinfo",
						"revocation_endpoint":                   srvURL + "/revoke",
						"response_types_supported":              []string{"code"},
						"subject_types_supported":               []string{"public"},
						"id_token_signing_alg_values_supported": []string{"RS256"},
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(meta)
				case "/token":
					tokenHit.Store(true)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(
						`{"access_token":"new-access-token-value","token_type":"Bearer","expires_in":3600}`,
					))
				default:
					http.NotFound(w, r)
				}
			}),
		)
		defer srv.Close()
		srvURL = srv.URL

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))
		if err := store.Save("test-id", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(2 * time.Minute),
			ClientID:     "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		cfg := &AppConfig{
			ClientID:            "test-id",
			ServerURL:           srv.URL,
			RefreshThreshold:    defaultRefreshThreshold,
			RefreshTokenTimeout: defaultRefreshTokenTimeout,
			DiscoveryTimeout:    defaultDiscoveryTimeout,
			MaxResponseBodySize: defaultMaxResponseBodySize,
			RetryClient:         rc,
			Store:               store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, nil, false, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if !discoveryHit.Load() {
			t.Error("expected discovery to be resolved when a refresh is needed")
		}
		if !tokenHit.Load() {
			t.Error("expected the token endpoint to be called for the refresh")
		}
		if strings.TrimSpace(stdout.String()) != "new-access-token-value" {
			t.Errorf("stdout: got %q, want the refreshed token", stdout.String())
		}
	})

	t.Run("empty refresh token skips network and reuses valid token", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))
		// Near expiry (inside threshold) but no refresh token available.
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "old-access-token",
			ExpiresAt:   time.Now().Add(2 * time.Minute),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		cfg := &AppConfig{
			ClientID:            "test-id",
			ServerURL:           srv.URL,
			RefreshThreshold:    defaultRefreshThreshold,
			RefreshTokenTimeout: defaultRefreshTokenTimeout,
			DiscoveryTimeout:    defaultDiscoveryTimeout,
			MaxResponseBodySize: defaultMaxResponseBodySize,
			RetryClient:         rc,
			Store:               store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, nil, false, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0 (graceful); stderr: %s", code, stderr.String())
		}
		if hits.Load() != 0 {
			t.Errorf("expected no network request without a refresh token, got %d", hits.Load())
		}
		if strings.TrimSpace(stdout.String()) != "old-access-token" {
			t.Errorf("stdout: got %q, want the existing token", stdout.String())
		}
	})
}

func TestRunTokenGet_LazyFullConfig(t *testing.T) {
	t.Run("far from expiry never builds full config", func(t *testing.T) {
		store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))
		if err := store.Save("test-id", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(time.Hour),
			ClientID:     "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		cfg := &AppConfig{
			ClientID:         "test-id",
			Store:            store,
			RefreshThreshold: defaultRefreshThreshold,
		}

		var loadFullCalls int
		loadFull := func() *AppConfig {
			loadFullCalls++
			return cfg
		}

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), cfg, loadFull, false, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if loadFullCalls != 0 {
			t.Errorf("loadFull called %d times, want 0 (offline path)", loadFullCalls)
		}
		if strings.TrimSpace(stdout.String()) != "old-access-token" {
			t.Errorf("stdout: got %q, want cached token", stdout.String())
		}
	})

	t.Run("near expiry builds full config once and refreshes", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(
					`{"access_token":"new-access-token-value","token_type":"Bearer","expires_in":3600}`,
				))
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(filepath.Join(t.TempDir(), "tokens.json"))
		if err := store.Save("test-id", credstore.Token{
			AccessToken:  "old-access-token",
			RefreshToken: "refresh-456",
			ExpiresAt:    time.Now().Add(2 * time.Minute),
			ClientID:     "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		// Partial config has no endpoints/retry client — those only exist in
		// the full config built lazily by loadFull.
		partial := &AppConfig{
			ClientID:         "test-id",
			Store:            store,
			RefreshThreshold: defaultRefreshThreshold,
		}

		var loadFullCalls int
		loadFull := func() *AppConfig {
			loadFullCalls++
			return &AppConfig{
				ClientID:            "test-id",
				Endpoints:           oauth.Endpoints{TokenURL: srv.URL + "/oauth/token"},
				RefreshTokenTimeout: defaultRefreshTokenTimeout,
				MaxResponseBodySize: defaultMaxResponseBodySize,
				RetryClient:         rc,
				Store:               store,
			}
		}

		var stdout, stderr bytes.Buffer
		code := runTokenGet(context.Background(), partial, loadFull, false, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if loadFullCalls != 1 {
			t.Errorf("loadFull called %d times, want 1", loadFullCalls)
		}
		if strings.TrimSpace(stdout.String()) != "new-access-token-value" {
			t.Errorf("stdout: got %q, want refreshed token", stdout.String())
		}
	})
}

func TestNeedsRefresh(t *testing.T) {
	now := time.Now()
	const threshold = 5 * time.Minute
	tests := []struct {
		name string
		tok  credstore.Token
		want bool
	}{
		{
			name: "empty access token always refreshes",
			tok:  credstore.Token{ExpiresAt: now.Add(time.Hour)},
			want: true,
		},
		{
			name: "far from expiry does not refresh",
			tok:  credstore.Token{AccessToken: "a", ExpiresAt: now.Add(time.Hour)},
			want: false,
		},
		{
			name: "just outside threshold does not refresh",
			tok:  credstore.Token{AccessToken: "a", ExpiresAt: now.Add(threshold + time.Second)},
			want: false,
		},
		{
			name: "exactly at threshold refreshes",
			tok:  credstore.Token{AccessToken: "a", ExpiresAt: now.Add(threshold)},
			want: true,
		},
		{
			name: "inside threshold refreshes",
			tok:  credstore.Token{AccessToken: "a", ExpiresAt: now.Add(2 * time.Minute)},
			want: true,
		},
		{
			name: "already expired refreshes",
			tok:  credstore.Token{AccessToken: "a", ExpiresAt: now.Add(-time.Minute)},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsRefresh(tc.tok, threshold, now); got != tc.want {
				t.Errorf("needsRefresh() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRunTokenInspect(t *testing.T) {
	t.Run("no token stored", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		cfg := &AppConfig{ClientID: "test-id", Store: store}
		var stdout, stderr bytes.Buffer
		code := runTokenInspect(context.Background(), cfg, &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "no stored token") {
			t.Errorf("expected 'no stored token' in stderr, got: %q", stderr.String())
		}
	})

	t.Run("server returns valid json pretty printed", func(t *testing.T) {
		var gotAuth string
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(
					`{"active":true,"scope":"email profile","client_id":"test-id","sub":"user-42","exp":1800000000}`,
				))
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "access-xyz",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &AppConfig{
			ClientID:                 "test-id",
			Endpoints:                oauth.Endpoints{TokenInfoURL: srv.URL + "/oauth/tokeninfo"},
			TokenVerificationTimeout: defaultTokenVerificationTimeout,
			MaxResponseBodySize:      defaultMaxResponseBodySize,
			RetryClient:              rc,
			Store:                    store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenInspect(context.Background(), cfg, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if gotAuth != "Bearer access-xyz" {
			t.Errorf("Authorization header: got %q, want %q", gotAuth, "Bearer access-xyz")
		}
		// Pretty-printed JSON should be 2-space indented and parse back cleanly.
		if !strings.Contains(stdout.String(), "  \"active\": true") {
			t.Errorf("expected pretty-printed JSON, got: %q", stdout.String())
		}
		var parsed map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if parsed["sub"] != "user-42" {
			t.Errorf("sub: got %v, want user-42", parsed["sub"])
		}
	})

	t.Run("server returns oauth error", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(
					`{"error":"invalid_token","error_description":"token revoked"}`,
				))
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "access-xyz",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &AppConfig{
			ClientID:                 "test-id",
			Endpoints:                oauth.Endpoints{TokenInfoURL: srv.URL + "/oauth/tokeninfo"},
			TokenVerificationTimeout: defaultTokenVerificationTimeout,
			MaxResponseBodySize:      defaultMaxResponseBodySize,
			RetryClient:              rc,
			Store:                    store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenInspect(context.Background(), cfg, &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "invalid_token") {
			t.Errorf("expected 'invalid_token' in stderr, got: %q", stderr.String())
		}
	})

	t.Run("server returns non-json body printed verbatim", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("token is fine"))
			}),
		)
		defer srv.Close()

		rc, err := retry.NewClient()
		if err != nil {
			t.Fatal(err)
		}
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "access-xyz",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &AppConfig{
			ClientID:                 "test-id",
			Endpoints:                oauth.Endpoints{TokenInfoURL: srv.URL + "/oauth/tokeninfo"},
			TokenVerificationTimeout: defaultTokenVerificationTimeout,
			MaxResponseBodySize:      defaultMaxResponseBodySize,
			RetryClient:              rc,
			Store:                    store,
		}

		var stdout, stderr bytes.Buffer
		code := runTokenInspect(context.Background(), cfg, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "token is fine") {
			t.Errorf("expected raw body in stdout, got: %q", stdout.String())
		}
	})
}

// makeJWT builds an unsigned JWT-shaped token for testing runTokenDecode,
// which exercises JWT payload parsing indirectly. The signature segment is a
// fixed placeholder — runTokenDecode never verifies it.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString(
		[]byte(`{"alg":"HS256","typ":"JWT"}`),
	)
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
	return header + "." + payload + "." + sig
}

func TestRunTokenDecode(t *testing.T) {
	t.Run("no token stored", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "", &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "no stored token") {
			t.Errorf("expected 'no stored token' in stderr, got: %q", stderr.String())
		}
	})

	t.Run("opaque token rejected", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "opaque-token-no-dots",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "", &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "not a JWT") {
			t.Errorf("expected 'not a JWT' in stderr, got: %q", stderr.String())
		}
		if !strings.Contains(stderr.String(), "token inspect") {
			t.Errorf("expected hint pointing at 'token inspect', got: %q", stderr.String())
		}
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "header.!!!not-base64!!!.sig",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "", &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "decode payload") {
			t.Errorf("expected 'decode payload' in stderr, got: %q", stderr.String())
		}
		// Hint about opaque tokens must not appear for JWT-shaped-but-corrupted
		// tokens — the hint is only meaningful when the token isn't JWT.
		if strings.Contains(stderr.String(), "token inspect") {
			t.Errorf(
				"opaque-token hint should not appear for malformed JWT, got: %q",
				stderr.String(),
			)
		}
	})

	t.Run("too many segments rejected", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "a.b.c.d.e",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "", &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "not a JWT") {
			t.Errorf("expected 'not a JWT' in stderr, got: %q", stderr.String())
		}
		// 4+ segment tokens are clearly malformed JWTs, not opaque tokens —
		// the opaque-token hint must not appear.
		if strings.Contains(stderr.String(), "token inspect") {
			t.Errorf(
				"opaque-token hint should not appear for too-many-segments token, got: %q",
				stderr.String(),
			)
		}
		// Diagnostic must report the true segment count (5), not the capped
		// SplitN result (4).
		if !strings.Contains(stderr.String(), "got 5") {
			t.Errorf("expected accurate segment count 'got 5' in stderr, got: %q", stderr.String())
		}
	})

	t.Run("invalid json payload", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		// Valid base64url encoding of bytes that are not JSON.
		nonJSON := base64.RawURLEncoding.EncodeToString([]byte("not json at all"))
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "header." + nonJSON + ".sig",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "", &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "parse claims") {
			t.Errorf("expected 'parse claims' in stderr, got: %q", stderr.String())
		}
		// JWT-shaped tokens that fail JSON parsing are still JWTs structurally,
		// so the opaque-token hint should not appear.
		if strings.Contains(stderr.String(), "token inspect") {
			t.Errorf(
				"opaque-token hint should not appear for JWT with non-JSON payload, got: %q",
				stderr.String(),
			)
		}
	})

	t.Run("full claims pretty printed", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		jwt := makeJWT(t, map[string]any{
			"aud":        "my-service",
			"sub":        "service-account@example.iam",
			"project_id": "my-project",
			"scope":      "email profile",
			"exp":        1800000000,
		})
		if err := store.Save("test-id", credstore.Token{
			AccessToken: jwt,
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "", &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "  \"aud\": \"my-service\"") {
			t.Errorf("expected pretty-printed JSON with aud claim, got: %q", stdout.String())
		}
		var parsed map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if parsed["project_id"] != "my-project" {
			t.Errorf("project_id: got %v, want my-project", parsed["project_id"])
		}
	})

	t.Run("field flag string value raw", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		jwt := makeJWT(t, map[string]any{"aud": "my-service", "sub": "user-1"})
		if err := store.Save("test-id", credstore.Token{
			AccessToken: jwt,
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "aud", &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if stdout.String() != "my-service\n" {
			t.Errorf("got %q, want %q", stdout.String(), "my-service\n")
		}
	})

	t.Run("field flag non-string value json encoded", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		jwt := makeJWT(t, map[string]any{
			"aud":    []string{"svc-a", "svc-b"},
			"groups": map[string]any{"role": "admin"},
		})
		if err := store.Save("test-id", credstore.Token{
			AccessToken: jwt,
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "aud", &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if stdout.String() != `["svc-a","svc-b"]`+"\n" {
			t.Errorf("got %q, want JSON-encoded array", stdout.String())
		}
	})

	t.Run("trailing data rejected", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		// Two concatenated JSON objects in the payload — the first decode
		// would succeed silently without an explicit trailing-data check.
		bad := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"a"}{"x":1}`))
		if err := store.Save("test-id", credstore.Token{
			AccessToken: "header." + bad + ".sig",
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "", &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), "trailing data") {
			t.Errorf("expected 'trailing data' in stderr, got: %q", stderr.String())
		}
	})

	t.Run("large integer claim preserved", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		// 2^53 + 1 — the smallest positive integer that float64 cannot
		// represent exactly. UseNumber must keep it intact.
		const bigInt = "9007199254740993"
		jwt := makeJWT(t, map[string]any{"jti": json.RawMessage(bigInt)})
		if err := store.Save("test-id", credstore.Token{
			AccessToken: jwt,
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "jti", &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit code: got %d, want 0; stderr: %s", code, stderr.String())
		}
		if stdout.String() != bigInt+"\n" {
			t.Errorf("got %q, want %q (precision must be preserved)", stdout.String(), bigInt+"\n")
		}
	})

	t.Run("field flag missing claim", func(t *testing.T) {
		store := credstore.NewTokenFileStore(
			filepath.Join(t.TempDir(), "tokens.json"),
		)
		jwt := makeJWT(t, map[string]any{"sub": "user-1"})
		if err := store.Save("test-id", credstore.Token{
			AccessToken: jwt,
			ExpiresAt:   time.Now().Add(time.Hour),
			ClientID:    "test-id",
		}); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := runTokenDecode(store, "test-id", "aud", &stdout, &stderr)
		if code != 1 {
			t.Errorf("exit code: got %d, want 1", code)
		}
		if !strings.Contains(stderr.String(), `claim "aud" not found`) {
			t.Errorf("expected missing-claim message, got: %q", stderr.String())
		}
	})
}
