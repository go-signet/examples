package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/bearerauth"
)

type verifierFunc func(
	context.Context,
	string,
) (*bearerauth.Identity, error)

func (f verifierFunc) Verify(
	ctx context.Context,
	credential string,
) (*bearerauth.Identity, error) {
	return f(ctx, credential)
}

func TestLoadConfig(t *testing.T) {
	t.Run("tokeninfo with secure defaults", func(t *testing.T) {
		cfg, err := loadConfig(mapEnv(map[string]string{
			"SIGNET_URL":        " https://auth.example.com ",
			"CLIENT_ID":         " orders-api ",
			"EXPECTED_AUDIENCE": " api://orders ",
			"REQUIRED_SCOPES":   "orders.write  orders.read",
		}))
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.signetURL != "https://auth.example.com" {
			t.Errorf("signetURL = %q", cfg.signetURL)
		}
		if cfg.clientID != "orders-api" {
			t.Errorf("clientID = %q", cfg.clientID)
		}
		if cfg.expectedAudience != "api://orders" {
			t.Errorf("expectedAudience = %q", cfg.expectedAudience)
		}
		if cfg.skipAudienceCheck {
			t.Error("skipAudienceCheck = true, want secure default false")
		}
		if !slices.Equal(
			cfg.requiredScopes,
			[]string{"orders.write", "orders.read"},
		) {
			t.Errorf("requiredScopes = %v", cfg.requiredScopes)
		}
		if cfg.serverAddr != defaultServerAddr {
			t.Errorf("serverAddr = %q, want %q", cfg.serverAddr, defaultServerAddr)
		}
		if got := cfg.personalAPIKeyMode(); got != "tokeninfo" {
			t.Errorf("personalAPIKeyMode() = %q", got)
		}

		sdkConfig := cfg.bearerAuthConfig()
		if sdkConfig.Audience != "api://orders" ||
			sdkConfig.SkipAudience ||
			sdkConfig.ClientID != "orders-api" ||
			!slices.Equal(sdkConfig.RequiredScopes, cfg.requiredScopes) {
			t.Errorf("bearerAuthConfig() did not preserve validated settings")
		}
	})

	t.Run("explicit audience opt out and introspection", func(t *testing.T) {
		const secret = "example-client-secret "
		cfg, err := loadConfig(mapEnv(map[string]string{
			"SIGNET_URL":                  "https://auth.example.com",
			"CLIENT_ID":                   "orders-api",
			"SKIP_AUDIENCE_CHECK":         "1",
			"INTROSPECTION_CLIENT_ID":     "orders-api",
			"INTROSPECTION_CLIENT_SECRET": secret,
			"SERVER_ADDR":                 "127.0.0.1:9090",
		}))
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if !cfg.skipAudienceCheck || cfg.expectedAudience != "" {
			t.Error("explicit audience opt-out was not preserved")
		}
		if cfg.introspectionClientSecret != secret {
			t.Error("introspection secret was unexpectedly changed")
		}
		if got := cfg.personalAPIKeyMode(); got != "introspection" {
			t.Errorf("personalAPIKeyMode() = %q", got)
		}
		if cfg.serverAddr != "127.0.0.1:9090" {
			t.Errorf("serverAddr = %q", cfg.serverAddr)
		}
	})
}

func TestLoadConfigRejectsInvalidSettings(t *testing.T) {
	valid := map[string]string{
		"SIGNET_URL":        "https://auth.example.com",
		"CLIENT_ID":         "orders-api",
		"EXPECTED_AUDIENCE": "api://orders",
	}

	tests := []struct {
		name      string
		changes   map[string]string
		wantField string
	}{
		{
			name:      "missing issuer",
			changes:   map[string]string{"SIGNET_URL": ""},
			wantField: "SIGNET_URL",
		},
		{
			name:      "missing client id",
			changes:   map[string]string{"CLIENT_ID": ""},
			wantField: "CLIENT_ID",
		},
		{
			name:      "missing audience",
			changes:   map[string]string{"EXPECTED_AUDIENCE": ""},
			wantField: "EXPECTED_AUDIENCE",
		},
		{
			name: "audience conflicts with opt out",
			changes: map[string]string{
				"SKIP_AUDIENCE_CHECK": "1",
			},
			wantField: "mutually exclusive",
		},
		{
			name: "invalid audience opt out",
			changes: map[string]string{
				"SKIP_AUDIENCE_CHECK": "true",
			},
			wantField: "SKIP_AUDIENCE_CHECK",
		},
		{
			name: "introspection id only",
			changes: map[string]string{
				"INTROSPECTION_CLIENT_ID": "orders-api",
			},
			wantField: "must be set together",
		},
		{
			name: "introspection secret only",
			changes: map[string]string{
				"INTROSPECTION_CLIENT_SECRET": "example-secret",
			},
			wantField: "must be set together",
		},
		{
			name: "whitespace introspection secret",
			changes: map[string]string{
				"INTROSPECTION_CLIENT_ID":     "orders-api",
				"INTROSPECTION_CLIENT_SECRET": "   ",
			},
			wantField: "must not be blank",
		},
		{
			name: "whitespace introspection secret without id",
			changes: map[string]string{
				"INTROSPECTION_CLIENT_SECRET": "   ",
			},
			wantField: "must be set together",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := make(map[string]string, len(valid)+len(tt.changes))
			for key, value := range valid {
				values[key] = value
			}
			for key, value := range tt.changes {
				values[key] = value
			}

			_, err := loadConfig(mapEnv(values))
			if err == nil {
				t.Fatal("loadConfig() error = nil")
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("loadConfig() error did not name the invalid setting")
			}
			if strings.Contains(err.Error(), "example-secret") {
				t.Error("loadConfig() error exposed the introspection secret")
			}
		})
	}
}

func TestBearerCredential(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{name: "standard", header: "Bearer opaque-value", want: "opaque-value", wantOK: true},
		{name: "case insensitive", header: "bEaReR opaque-value", want: "opaque-value", wantOK: true},
		{name: "ordinary whitespace", header: " \tBearer   opaque-value\t", want: "opaque-value", wantOK: true},
		{name: "missing", header: "", wantOK: false},
		{name: "missing value", header: "Bearer", wantOK: false},
		{name: "other scheme", header: "Basic opaque-value", wantOK: false},
		{name: "embedded whitespace", header: "Bearer first second", wantOK: false},
		{name: "scheme attached to value", header: "Beareropaque-value", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := bearerCredential(tt.header)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf(
					"bearerCredential() = (%q, %v), want (%q, %v)",
					got,
					ok,
					tt.want,
					tt.wantOK,
				)
			}
		})
	}
}

func TestWhoAmIAcceptsBothCredentialTypes(t *testing.T) {
	expiresAt := time.Date(2030, 5, 6, 7, 8, 9, 123, time.UTC)

	tests := []struct {
		name           string
		credentialType bearerauth.CredentialType
	}{
		{name: "JWT", credentialType: bearerauth.CredentialJWT},
		{
			name:           "Personal API Key",
			credentialType: bearerauth.CredentialPersonalAPIKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const presentedCredential = "opaque-test-credential"

			var (
				mu       sync.Mutex
				received string
			)
			verifier := verifierFunc(func(
				_ context.Context,
				credential string,
			) (*bearerauth.Identity, error) {
				mu.Lock()
				received = credential
				mu.Unlock()

				return &bearerauth.Identity{
					Subject:        "user-42",
					SubjectType:    bearerauth.SubjectUser,
					Issuer:         "https://auth.example.com",
					ClientID:       "orders-api",
					Scopes:         []string{"orders.read", "orders.write"},
					ExpiresAt:      expiresAt,
					CredentialType: tt.credentialType,
				}, nil
			})

			var logs bytes.Buffer
			server := httptest.NewServer(
				newHandler(verifier, log.New(&logs, "", 0)),
			)
			defer server.Close()

			req, err := http.NewRequest(
				http.MethodGet,
				server.URL+"/api/whoami",
				nil,
			)
			if err != nil {
				t.Fatalf("NewRequest() error = %v", err)
			}
			req.Header.Set("Authorization", "bEaReR "+presentedCredential)

			response, err := server.Client().Do(req)
			if err != nil {
				t.Fatalf("Do() error = %v", err)
			}
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.StatusCode)
			}
			if got := response.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := response.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}

			var got identityResponse
			if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
				t.Fatalf("Decode() error = %v", err)
			}

			if got.Subject != "user-42" ||
				got.SubjectType != bearerauth.SubjectUser ||
				got.Issuer != "https://auth.example.com" ||
				got.ClientID != "orders-api" ||
				!slices.Equal(got.Scopes, []string{"orders.read", "orders.write"}) ||
				!got.ExpiresAt.Equal(expiresAt) ||
				got.CredentialType != tt.credentialType {
				t.Errorf("identity response did not match the normalized identity")
			}

			mu.Lock()
			gotCredential := received
			mu.Unlock()
			if gotCredential != presentedCredential {
				t.Error("verifier did not receive exactly the credential value")
			}
			if strings.Contains(logs.String(), presentedCredential) {
				t.Error("logs exposed the presented credential")
			}
		})
	}
}

func TestHandlerSafelyReusesVerifierConcurrently(t *testing.T) {
	const requestCount = 32

	var calls atomic.Int32
	verifier := verifierFunc(func(
		_ context.Context,
		_ string,
	) (*bearerauth.Identity, error) {
		calls.Add(1)
		return &bearerauth.Identity{
			Subject:        "user-42",
			SubjectType:    bearerauth.SubjectUser,
			Issuer:         "https://auth.example.com",
			ClientID:       "orders-api",
			Scopes:         []string{"orders.read"},
			ExpiresAt:      time.Now().Add(time.Hour),
			CredentialType: bearerauth.CredentialJWT,
		}, nil
	})
	server := httptest.NewServer(newHandler(verifier, nil))
	defer server.Close()

	failures := make(chan error, requestCount)
	var group sync.WaitGroup
	for i := 0; i < requestCount; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()

			req, err := http.NewRequest(
				http.MethodGet,
				server.URL+"/api/whoami",
				nil,
			)
			if err != nil {
				failures <- fmt.Errorf("request %d: create: %w", index, err)
				return
			}
			req.Header.Set(
				"Authorization",
				fmt.Sprintf("Bearer credential-%d", index),
			)

			response, err := server.Client().Do(req)
			if err != nil {
				failures <- fmt.Errorf("request %d: send: %w", index, err)
				return
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				failures <- fmt.Errorf(
					"request %d: status = %d, want 200",
					index,
					response.StatusCode,
				)
			}
		}(i)
	}
	group.Wait()
	close(failures)

	for err := range failures {
		t.Error(err)
	}
	if got := calls.Load(); got != requestCount {
		t.Errorf("verifier calls = %d, want %d", got, requestCount)
	}
}

func TestRequireBearerRejectsMalformedHeadersBeforeVerification(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
	}{
		{name: "missing"},
		{name: "empty", headers: []string{""}},
		{name: "other scheme", headers: []string{"Basic opaque-value"}},
		{name: "missing value", headers: []string{"Bearer"}},
		{name: "embedded whitespace", headers: []string{"Bearer first second"}},
		{
			name:    "multiple authorization fields",
			headers: []string{"Bearer first", "Bearer second"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			verifier := verifierFunc(func(
				context.Context,
				string,
			) (*bearerauth.Identity, error) {
				calls++
				return nil, errors.New("must not be called")
			})

			var logs bytes.Buffer
			handler := newHandler(verifier, log.New(&logs, "", 0))
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/whoami",
				nil,
			)
			for _, value := range tt.headers {
				request.Header.Add("Authorization", value)
			}
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", recorder.Code)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
			if got := recorder.Body.String(); got != "{\"error\":\"unauthorized\"}\n" {
				t.Errorf("body = %q", got)
			}
			if calls != 0 {
				t.Errorf("verifier calls = %d, want 0", calls)
			}
			if !strings.Contains(
				logs.String(),
				"category=missing_or_malformed_authorization",
			) {
				t.Error("safe failure category was not logged")
			}
			if !strings.Contains(logs.String(), "status=401") {
				t.Error("safe HTTP status was not logged")
			}
		})
	}
}

func TestVerificationErrorHTTPMapping(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		identity       *bearerauth.Identity
		wantStatus     int
		wantChallenge  string
		wantBody       string
		wantCategory   string
		wantRetryAfter string
	}{
		{
			name:          "invalid credential",
			err:           fmt.Errorf("static context: %w", bearerauth.ErrInvalidCredential),
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Bearer error="invalid_token"`,
			wantBody:      "{\"error\":\"unauthorized\"}\n",
			wantCategory:  "invalid_credential",
		},
		{
			name:          "untrusted issuer",
			err:           bearerauth.ErrUntrustedIssuer,
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Bearer error="invalid_token"`,
			wantBody:      "{\"error\":\"unauthorized\"}\n",
			wantCategory:  "untrusted_issuer",
		},
		{
			name:          "client app not allowed",
			err:           bearerauth.ErrClientAppNotAllowed,
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: `Bearer error="invalid_token"`,
			wantBody:      "{\"error\":\"unauthorized\"}\n",
			wantCategory:  "client_app_not_allowed",
		},
		{
			name: "insufficient scope",
			err: &bearerauth.InsufficientScopeError{
				MissingScope: "orders.write",
			},
			wantStatus: http.StatusForbidden,
			wantChallenge: `Bearer error="insufficient_scope", ` +
				`scope="orders.write"`,
			wantBody:     "{\"error\":\"forbidden\"}\n",
			wantCategory: "insufficient_scope",
		},
		{
			name:           "verifier unavailable",
			err:            fmt.Errorf("static context: %w", bearerauth.ErrVerifierUnavailable),
			wantStatus:     http.StatusServiceUnavailable,
			wantBody:       "{\"error\":\"service_unavailable\"}\n",
			wantCategory:   "verifier_unavailable",
			wantRetryAfter: "1",
		},
		{
			name:         "unexpected error",
			err:          errors.New("unexpected verifier failure"),
			wantStatus:   http.StatusInternalServerError,
			wantBody:     "{\"error\":\"internal_server_error\"}\n",
			wantCategory: "unexpected_error",
		},
		{
			name:         "insufficient scope sentinel without typed detail fails closed",
			err:          bearerauth.ErrInsufficientScope,
			wantStatus:   http.StatusInternalServerError,
			wantBody:     "{\"error\":\"internal_server_error\"}\n",
			wantCategory: "unexpected_error",
		},
		{
			name:         "nil identity fails closed",
			identity:     nil,
			wantStatus:   http.StatusInternalServerError,
			wantBody:     "{\"error\":\"internal_server_error\"}\n",
			wantCategory: "invalid_verifier_result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const presentedCredential = "opaque-sensitive-value"

			verifier := verifierFunc(func(
				context.Context,
				string,
			) (*bearerauth.Identity, error) {
				return tt.identity, tt.err
			})
			var logs bytes.Buffer
			handler := newHandler(verifier, log.New(&logs, "", 0))
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/whoami",
				nil,
			)
			request.Header.Set(
				"Authorization",
				"Bearer "+presentedCredential,
			)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			if recorder.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}
			if got := recorder.Header().Get("WWW-Authenticate"); got != tt.wantChallenge {
				t.Errorf(
					"WWW-Authenticate = %q, want %q",
					got,
					tt.wantChallenge,
				)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
			if got := recorder.Header().Get("Retry-After"); got != tt.wantRetryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tt.wantRetryAfter)
			}
			if got := recorder.Body.String(); got != tt.wantBody {
				t.Errorf("body = %q, want %q", got, tt.wantBody)
			}
			if !strings.Contains(logs.String(), "category="+tt.wantCategory) {
				t.Errorf("safe log category %q was not recorded", tt.wantCategory)
			}
			if !strings.Contains(
				logs.String(),
				fmt.Sprintf("status=%d", tt.wantStatus),
			) {
				t.Errorf("safe log status %d was not recorded", tt.wantStatus)
			}
			if strings.Contains(logs.String(), presentedCredential) ||
				strings.Contains(recorder.Body.String(), presentedCredential) {
				t.Error("credential material was exposed")
			}
		})
	}
}

func TestVerifierErrorsNeverReachResponseOrLogs(t *testing.T) {
	const sensitiveValue = "sensitive-value-that-must-not-be-emitted"

	verifier := verifierFunc(func(
		context.Context,
		string,
	) (*bearerauth.Identity, error) {
		return nil, fmt.Errorf(
			"dependency echoed %s: %w",
			sensitiveValue,
			bearerauth.ErrInvalidCredential,
		)
	})
	var logs bytes.Buffer
	handler := newHandler(verifier, log.New(&logs, "", 0))
	request := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	request.Header.Set("Authorization", "Bearer "+sensitiveValue)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if strings.Contains(logs.String(), sensitiveValue) ||
		strings.Contains(recorder.Body.String(), sensitiveValue) ||
		strings.Contains(
			recorder.Header().Get("WWW-Authenticate"),
			sensitiveValue,
		) {
		t.Error("a verifier error or credential was exposed")
	}
}

func TestHealthAndRouting(t *testing.T) {
	handler := newHandler(
		verifierFunc(func(
			context.Context,
			string,
		) (*bearerauth.Identity, error) {
			return nil, errors.New("must not be called")
		}),
		nil,
	)

	t.Run("health is public", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/health", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", recorder.Code)
		}
		if got := recorder.Body.String(); got != "{\"status\":\"ok\"}\n" {
			t.Errorf("body = %q", got)
		}
	})

	t.Run("method is constrained", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/health", nil)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", recorder.Code)
		}
	})
}

func TestWhoAmIFailsClosedWithoutMiddlewareIdentity(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/whoami", nil)
	recorder := httptest.NewRecorder()

	whoamiHandler(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", recorder.Code)
	}
	if got := recorder.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want empty", got)
	}
	if got := recorder.Body.String(); got != "{\"error\":\"internal_server_error\"}\n" {
		t.Errorf("body = %q", got)
	}
}

func TestHTTPServerBounds(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newHTTPServer("127.0.0.1:0", handler)

	if server.Addr != "127.0.0.1:0" ||
		server.Handler == nil ||
		server.ReadHeaderTimeout != 10*time.Second ||
		server.ReadTimeout != 15*time.Second ||
		server.WriteTimeout != 15*time.Second ||
		server.IdleTimeout != 60*time.Second ||
		server.MaxHeaderBytes != 8<<10 {
		t.Error("newHTTPServer() did not apply the bounded server settings")
	}
}

func TestServeShutsDownOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var logs bytes.Buffer
	server := newHTTPServer(
		"127.0.0.1:0",
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	)

	if err := serve(ctx, server, "tokeninfo", log.New(&logs, "", 0)); err != nil {
		t.Fatalf("serve() error = %v", err)
	}

	for _, event := range []string{
		"server listening",
		"personal_api_key_verification=tokeninfo",
		"server shutting down",
		"server stopped",
	} {
		if !strings.Contains(logs.String(), event) {
			t.Errorf("log does not contain %q", event)
		}
	}
}

func mapEnv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}
