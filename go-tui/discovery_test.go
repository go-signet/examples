package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	retry "github.com/appleboy/go-httpretry"
)

func TestDefaultEndpoints(t *testing.T) {
	ep := defaultEndpoints("http://example.com")

	want := map[string]string{
		"AuthorizeURL":           "http://example.com/oauth/authorize",
		"TokenURL":               "http://example.com/oauth/token",
		"DeviceAuthorizationURL": "http://example.com/oauth/device/code",
		"TokenInfoURL":           "http://example.com/oauth/tokeninfo",
		"UserinfoURL":            "http://example.com/oauth/userinfo",
		"RevocationURL":          "http://example.com/oauth/revoke",
	}

	got := map[string]string{
		"AuthorizeURL":           ep.AuthorizeURL,
		"TokenURL":               ep.TokenURL,
		"DeviceAuthorizationURL": ep.DeviceAuthorizationURL,
		"TokenInfoURL":           ep.TokenInfoURL,
		"UserinfoURL":            ep.UserinfoURL,
		"RevocationURL":          ep.RevocationURL,
	}

	for field, wantVal := range want {
		if got[field] != wantVal {
			t.Errorf("%s = %q, want %q", field, got[field], wantVal)
		}
	}
}

func TestResolveEndpoints_Success(t *testing.T) {
	// Use a pointer so the handler closure can reference the final URL.
	var srvURL string
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
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
			if err := json.NewEncoder(w).Encode(meta); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}),
	)
	defer srv.Close()
	srvURL = srv.URL

	rc, err := retry.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{
		ServerURL:        srv.URL,
		RetryClient:      rc,
		DiscoveryTimeout: defaultDiscoveryTimeout,
	}

	resolveEndpoints(context.Background(), cfg)

	if cfg.Endpoints.AuthorizeURL != srv.URL+"/auth" {
		t.Errorf("AuthorizeURL = %q, want %q", cfg.Endpoints.AuthorizeURL, srv.URL+"/auth")
	}
	if cfg.Endpoints.TokenURL != srv.URL+"/token" {
		t.Errorf("TokenURL = %q, want %q", cfg.Endpoints.TokenURL, srv.URL+"/token")
	}
	if cfg.Endpoints.DeviceAuthorizationURL != srv.URL+"/device" {
		t.Errorf(
			"DeviceAuthorizationURL = %q, want %q",
			cfg.Endpoints.DeviceAuthorizationURL,
			srv.URL+"/device",
		)
	}
	if cfg.Endpoints.UserinfoURL != srv.URL+"/userinfo" {
		t.Errorf("UserinfoURL = %q, want %q", cfg.Endpoints.UserinfoURL, srv.URL+"/userinfo")
	}
	if cfg.Endpoints.RevocationURL != srv.URL+"/revoke" {
		t.Errorf("RevocationURL = %q, want %q", cfg.Endpoints.RevocationURL, srv.URL+"/revoke")
	}
	// TokenInfoURL is derived from issuer by the SDK (not a standard OIDC field).
	wantTokenInfo := srv.URL + "/oauth/tokeninfo"
	if cfg.Endpoints.TokenInfoURL != wantTokenInfo {
		t.Errorf("TokenInfoURL = %q, want %q", cfg.Endpoints.TokenInfoURL, wantTokenInfo)
	}
}

func TestResolveEndpoints_FallbackOn404(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}),
	)
	defer srv.Close()

	rc, err := retry.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{
		ServerURL:        srv.URL,
		RetryClient:      rc,
		DiscoveryTimeout: defaultDiscoveryTimeout,
	}

	resolveEndpoints(context.Background(), cfg)

	// Should fall back to defaults
	want := defaultEndpoints(srv.URL)
	if cfg.Endpoints != want {
		t.Errorf("expected default endpoints on 404 fallback\ngot:  %+v\nwant: %+v",
			cfg.Endpoints, want)
	}
}

func TestResolveEndpoints_FallbackOnTimeout(t *testing.T) {
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(5 * time.Second)
		}),
	)
	defer srv.Close()

	rc, err := retry.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{
		ServerURL:        srv.URL,
		RetryClient:      rc,
		DiscoveryTimeout: defaultDiscoveryTimeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	resolveEndpoints(ctx, cfg)

	want := defaultEndpoints(srv.URL)
	if cfg.Endpoints != want {
		t.Errorf("expected default endpoints on timeout fallback\ngot:  %+v\nwant: %+v",
			cfg.Endpoints, want)
	}
}

func TestResolveEndpoints_FallbackOnNetworkError(t *testing.T) {
	rc, err := retry.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{
		ServerURL:        "http://127.0.0.1:1", // port 1 is unreachable
		RetryClient:      rc,
		DiscoveryTimeout: defaultDiscoveryTimeout,
	}

	resolveEndpoints(context.Background(), cfg)

	want := defaultEndpoints(cfg.ServerURL)
	if cfg.Endpoints != want {
		t.Errorf("expected default endpoints on network error\ngot:  %+v\nwant: %+v",
			cfg.Endpoints, want)
	}
}
