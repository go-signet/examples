package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestRunResources(t *testing.T) {
	for _, tc := range []struct {
		name        string
		resources   []string
		explicitAPI bool
		tokenError  bool
		apiStatus   int
		wantError   string
	}{
		{name: "legacy discovery userinfo", apiStatus: 200},
		{name: "one resource", resources: []string{"https://api.example.com"}, explicitAPI: true, apiStatus: 200},
		{name: "multiple resources", resources: []string{"https://api.example.com", "https://other.example.com"}, explicitAPI: true, apiStatus: 200},
		{name: "resource requires API URL", resources: []string{"https://api.example.com"}, wantError: "set API_URL"},
		{name: "issuer rejects resource", resources: []string{"https://api.example.com"}, explicitAPI: true, tokenError: true, wantError: "invalid_target"},
		{name: "API rejects audience", resources: []string{"https://api.example.com"}, explicitAPI: true, apiStatus: 401, wantError: "HTTP 401"},
		{name: "API rejects scope", resources: []string{"https://api.example.com"}, explicitAPI: true, apiStatus: 403, wantError: "HTTP 403"},
		{name: "redirect is not followed", resources: []string{"https://api.example.com"}, explicitAPI: true, apiStatus: 302, wantError: "HTTP 302"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests, tokenCalls, apiCalls, redirected := 0, 0, 0, 0
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "token_endpoint": srv.URL + "/token", "userinfo_endpoint": srv.URL + "/userinfo"})
				case "/token":
					tokenCalls++
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					if !reflect.DeepEqual(r.PostForm["resource"], tc.resources) {
						t.Errorf("resources = %v, want %v", r.PostForm["resource"], tc.resources)
					}
					for key, want := range map[string]string{"grant_type": "client_credentials", "client_id": "test-client", "client_secret": "test-secret", "scope": "profile email"} {
						if got := r.PostForm.Get(key); got != want {
							t.Errorf("%s = %q, want %q", key, got, want)
						}
					}
					if tc.tokenError {
						w.WriteHeader(400)
						fmt.Fprint(w, `{"error":"invalid_target"}`)
						return
					}
					fmt.Fprint(w, `{"access_token":"resource-token","token_type":"Bearer","expires_in":3600}`)
				case "/api/data", "/userinfo":
					apiCalls++
					wantPath := "/userinfo"
					if tc.explicitAPI {
						wantPath = "/api/data"
					}
					if r.URL.Path != wantPath {
						t.Errorf("called %s, want %s", r.URL.Path, wantPath)
					}
					if r.Header.Get("Authorization") != "Bearer resource-token" {
						t.Error("missing bearer token")
					}
					if tc.apiStatus == 302 {
						w.Header().Set("Location", srv.URL+"/redirected")
					}
					w.WriteHeader(tc.apiStatus)
					fmt.Fprint(w, `{"result":"fixture"}`)
				case "/redirected":
					redirected++
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			cfg := config{signetURL: srv.URL, clientID: "test-client", clientSecret: "test-secret", resources: tc.resources}
			if tc.explicitAPI {
				cfg.apiURL = srv.URL + "/api/data"
			}
			var out bytes.Buffer
			err := run(context.Background(), cfg, &out)
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %v, want %q", err, tc.wantError)
			}
			if len(tc.resources) > 0 && !tc.explicitAPI {
				if requests != 0 {
					t.Fatalf("configuration error made %d requests", requests)
				}
				return
			}
			if tokenCalls != 1 {
				t.Errorf("token calls = %d", tokenCalls)
			}
			if tc.tokenError {
				if apiCalls != 0 {
					t.Error("API called after token error")
				}
				return
			}
			if apiCalls != 1 || redirected != 0 {
				t.Errorf("API calls=%d redirected=%d", apiCalls, redirected)
			}
			if !strings.Contains(out.String(), fmt.Sprintf("Status: %d", tc.apiStatus)) {
				t.Errorf("missing status in %q", out.String())
			}
		})
	}
}
