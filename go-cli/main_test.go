package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-signet/sdk-go/oauth"
)

func TestPrintTokenInfoAudience(t *testing.T) {
	for _, tc := range []struct{ name, claim, want string }{
		{"single", `,"aud":"https://api.example.com"`, "[https://api.example.com]"},
		{"multiple", `,"aud":["https://api.example.com","https://other.example.com"]`, "[https://api.example.com https://other.example.com]"},
		{"omitted", "", "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test-token" {
					t.Error("missing bearer token")
				}
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/userinfo" {
					// Resource-targeted tokens may not be accepted by userinfo. Metadata
					// must still be printed when that best-effort request fails.
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, `{"error":"insufficient_scope"}`)
					return
				}
				fmt.Fprintf(w, `{"active":true,"scope":"email"%s}`, tc.claim)
			}))
			defer srv.Close()
			client, err := oauth.NewClient("test-client", oauth.Endpoints{UserinfoURL: srv.URL + "/userinfo", TokenInfoURL: srv.URL + "/tokeninfo"})
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			printTokenInfo(context.Background(), &out, client, &oauth.Token{AccessToken: "test-token"})
			for _, want := range []string{"UserInfo error:", "TokenInfo Active: true", "TokenInfo Audience: " + tc.want} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output %q missing %q", out.String(), want)
				}
			}
		})
	}
}
