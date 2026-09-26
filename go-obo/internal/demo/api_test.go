package demo

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// issuerFixture tests the application's HTTP contract with real RSA/JWKS
// verification. It is NOT an implementation of Signet's consent/policy engine.
type issuerFixture struct {
	t                *testing.T
	server           *httptest.Server
	key              *rsa.PrivateKey
	mu               sync.Mutex
	active           bool
	introspectStatus int
	badJSON          bool
	delay            time.Duration
	exchangeCode     string
	subject          string
	badNonce         bool
	assertions       []string
	delegated        []string
	tokenCalls       int
	introspectCalls  int
	codes            map[string]url.Values
}

func newIssuer(t *testing.T) *issuerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &issuerFixture{t: t, key: key, active: true, subject: "user-alice", codes: map[string]url.Values{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}
func (f *issuerFixture) sign(claims map[string]any) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"demo-key","typ":"JWT"}`))
	b, err := json.Marshal(claims)
	if err != nil {
		f.t.Fatal(err)
	}
	input := h + "." + base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}
func (f *issuerFixture) claims(aud, client, scope, subject string) map[string]any {
	return map[string]any{"iss": f.server.URL, "sub": subject, "user_id": subject, "client_id": client, "type": "access", "aud": aud, "scope": scope, "exp": time.Now().Add(2 * time.Minute).Unix(), "iat": time.Now().Unix()}
}
func (f *issuerFixture) source(subject string) string {
	return f.sign(f.claims("https://api-a.example.com", "web", InputScope, subject))
}
func (f *issuerFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, 200, map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks", "introspection_endpoint": f.server.URL + "/introspect", "id_token_signing_alg_values_supported": []string{"RS256"}, "authorization_response_iss_parameter_supported": true})
	case "/jwks":
		writeJSON(w, 200, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "demo-key", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": "AQAB"}}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("resource") != "https://api-a.example.com" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("scope") != "openid "+InputScope {
			f.t.Error("incorrect authorization request")
		}
		code := randomID()
		f.codes[code] = q
		u, _ := url.Parse(q.Get("redirect_uri"))
		u.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {f.server.URL}}.Encode()
		http.Redirect(w, r, u.String(), 302)
	case "/token":
		f.tokenCalls++
		if err := r.ParseForm(); err != nil {
			f.t.Error(err)
		}
		if r.Header.Get("Authorization") != "" {
			f.t.Error("must not mix client authentication methods")
		}
		if r.PostForm.Get("grant_type") == "authorization_code" {
			q, ok := f.codes[r.PostForm.Get("code")]
			delete(f.codes, r.PostForm.Get("code"))
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") || r.PostForm.Get("redirect_uri") != q.Get("redirect_uri") || r.PostForm.Get("client_id") != q.Get("client_id") {
				writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
				return
			}
			if q.Get("client_id") == "web" && r.PostForm.Get("client_secret") != "web-secret" {
				f.t.Error("wrong web credentials")
			}
			if q.Get("client_id") == "cli" && r.PostForm.Get("client_secret") != "" {
				f.t.Error("CLI sent a secret")
			}
			source := f.sign(f.claims("https://api-a.example.com", q.Get("client_id"), InputScope, f.subject))
			nonce := q.Get("nonce")
			if f.badNonce {
				nonce = "wrong"
			}
			id := f.sign(map[string]any{"iss": f.server.URL, "sub": f.subject, "aud": q.Get("client_id"), "nonce": nonce, "exp": time.Now().Add(time.Minute).Unix()})
			writeJSON(w, 200, map[string]any{"access_token": source, "token_type": "Bearer", "expires_in": 120, "id_token": id})
			return
		}
		want := map[string]string{"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "requested_token_use": "on_behalf_of", "resource": "https://api-b.example.com", "scope": OutputScope, "client_id": "api-a", "client_secret": "a-secret"}
		for k, v := range want {
			if r.PostForm.Get(k) != v || len(r.PostForm[k]) != 1 {
				f.t.Errorf("incorrect OBO field %s", k)
			}
		}
		if len(r.PostForm) != 7 || r.URL.RawQuery != "" {
			f.t.Error("extra OBO fields")
		}
		raw := r.PostForm.Get("assertion")
		f.assertions = append(f.assertions, raw)
		if f.exchangeCode != "" {
			writeJSON(w, 400, map[string]string{"error": f.exchangeCode, "error_description": "DO-NOT-LEAK-SECRET"})
			return
		}
		// Read the already-verified assertion just to choose test output subject.
		parts := strings.Split(raw, ".")
		var in map[string]any
		if len(parts) != 3 {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		_ = json.Unmarshal(payload, &in)
		claims := f.claims("https://api-b.example.com", "api-a", OutputScope, in["sub"].(string))
		claims["act"] = map[string]string{"sub": "client:api-a"}
		token := f.sign(claims)
		f.delegated = append(f.delegated, token)
		writeJSON(w, 200, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 120, "scope": OutputScope})
	case "/introspect":
		f.introspectCalls++
		_ = r.ParseForm()
		if r.PostForm.Get("client_id") != "api-b" || r.PostForm.Get("client_secret") != "b-secret" || r.PostForm.Get("token") == "" {
			f.t.Error("incorrect B introspection credentials")
		}
		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-r.Context().Done():
				return
			}
		}
		if f.introspectStatus != 0 {
			w.WriteHeader(f.introspectStatus)
			fmt.Fprint(w, "DO-NOT-LEAK-SECRET")
			return
		}
		if f.badJSON {
			fmt.Fprint(w, `{"active":true} trailing garbage`)
			return
		}
		writeJSON(w, 200, map[string]bool{"active": f.active})
	default:
		http.NotFound(w, r)
	}
}
func fixtureConfig(f *issuerFixture) Config {
	return Config{Issuer: f.server.URL, WebID: "web", WebSecret: "web-secret", CLIID: "cli", AID: "api-a", ASecret: "a-secret", BID: "api-b", BSecret: "b-secret", AudienceA: "https://api-a.example.com", AudienceB: "https://api-b.example.com", URLA: "http://127.0.0.1:8091", URLB: "http://127.0.0.1:8092", WebRedirect: "http://127.0.0.1:8090/callback"}
}
func stack(t *testing.T) (*issuerFixture, Config, *API, *API) {
	t.Helper()
	f := newIssuer(t)
	c := fixtureConfig(f)
	b, err := NewAPI(t.Context(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	bs := httptest.NewServer(b.Handler())
	t.Cleanup(bs.Close)
	c.URLB = bs.URL
	a, err := NewAPI(t.Context(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	as := httptest.NewServer(a.Handler())
	t.Cleanup(as.Close)
	c.URLA = as.URL
	return f, c, a, b
}
func callHandler(h http.Handler, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/orders", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOBOEndToEnd(t *testing.T) {
	f, c, _, b := stack(t)
	source := f.source("user-alice")
	for range 2 {
		result, err := fetchOrders(t.Context(), newHTTPClient(c.URLA), c.URLA, source)
		if err != nil {
			t.Fatal(err)
		}
		if result.Source.Subject != "user-alice" || result.Downstream.Subject != "user-alice" || result.Downstream.Actor != "client:api-a" || result.Downstream.ClientID != "api-a" || result.Orders[0].Owner != "user-alice" {
			t.Fatalf("incorrect identities: %+v", result)
		}
	}
	f.mu.Lock()
	if len(f.assertions) != 2 || f.assertions[0] != source || f.introspectCalls != 2 {
		t.Error("source should be reused, verdicts must not be cached")
	}
	old := f.delegated[0]
	f.mu.Unlock()
	if w := callHandler(b.Handler(), source); w.Code != 401 {
		t.Fatalf("source token accepted by B: %d", w.Code)
	}
	f.mu.Lock()
	f.active = false
	f.exchangeCode = "invalid_grant"
	f.mu.Unlock()
	if _, err := fetchOrders(t.Context(), newHTTPClient(c.URLA), c.URLA, source); err == nil {
		t.Fatal("exchange succeeded after simulated revocation")
	}
	if w := callHandler(b.Handler(), old); w.Code != 401 {
		t.Fatalf("inactive OBO token accepted: %d", w.Code)
	}
}

func TestAPIBRejectsInvalidClaims(t *testing.T) {
	f, _, _, b := stack(t)
	cases := []struct {
		name   string
		modify func(map[string]any)
		status int
	}{
		{"audience", func(c map[string]any) { c["aud"] = "https://api-a.example.com" }, 401},
		{"multiple audiences", func(c map[string]any) { c["aud"] = []string{"https://api-b.example.com", "https://other.example.com"} }, 401},
		{"issuer", func(c map[string]any) { c["iss"] = "https://other.example.com" }, 401},
		{"expiry", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, 401},
		{"refresh token", func(c map[string]any) { c["type"] = "refresh" }, 401},
		{"missing actor", func(c map[string]any) { delete(c, "act") }, 401},
		{"wrong actor", func(c map[string]any) { c["act"] = map[string]string{"sub": "client:other"} }, 401},
		{"nested actor", func(c map[string]any) {
			c["act"] = map[string]any{"sub": "client:api-a", "act": map[string]string{"sub": "client:other"}}
		}, 401},
		{"wrong client", func(c map[string]any) { c["client_id"] = "other" }, 401},
		{"machine", func(c map[string]any) { c["sub"] = "client:api-a"; c["user_id"] = "client:api-a" }, 401},
		{"subject mismatch", func(c map[string]any) { c["user_id"] = "other-user" }, 401},
		{"scope", func(c map[string]any) { c["scope"] = "orders.write" }, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := f.claims("https://api-b.example.com", "api-a", OutputScope, "user-alice")
			claims["act"] = map[string]string{"sub": "client:api-a"}
			tc.modify(claims)
			w := callHandler(b.Handler(), f.sign(claims))
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.introspectCalls != 0 {
		t.Error("invalid claims should be rejected before introspection")
	}
}

func TestAPIRejectsDelegatedSourceAndSeparatesUsers(t *testing.T) {
	f, c, a, _ := stack(t)
	for _, user := range []string{"user-alice", "user-bob"} {
		result, err := fetchOrders(t.Context(), newHTTPClient(c.URLA), c.URLA, f.source(user))
		if err != nil {
			t.Fatal(err)
		}
		if result.Orders[0].Owner != user {
			t.Fatal("cross-user data")
		}
	}
	claims := f.claims(c.AudienceA, "api-a", InputScope, "user-alice")
	claims["act"] = map[string]string{"sub": "client:api-a"}
	if w := callHandler(a.Handler(), f.sign(claims)); w.Code != 401 {
		t.Fatal("delegated source accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.assertions) != 2 {
		t.Error("rejected request must not exchange")
	}
}

func TestIntrospectionFailuresDenyData(t *testing.T) {
	f, _, _, b := stack(t)
	claims := f.claims("https://api-b.example.com", "api-a", OutputScope, "user-alice")
	claims["act"] = map[string]string{"sub": "client:api-a"}
	token := f.sign(claims)
	for _, status := range []int{429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f.mu.Lock()
			f.introspectStatus = status
			before := f.introspectCalls
			f.mu.Unlock()
			w := callHandler(b.Handler(), token)
			if w.Code != 503 || strings.Contains(w.Body.String(), "DO-NOT-LEAK") {
				t.Fatalf("unexpected response: %s", w.Body.String())
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.introspectCalls != before+1 {
				t.Error("unexpected retry")
			}
		})
	}
	f.mu.Lock()
	f.introspectStatus = 0
	f.badJSON = true
	f.mu.Unlock()
	if w := callHandler(b.Handler(), token); w.Code != 503 {
		t.Fatal("invalid JSON accepted")
	}
	f.mu.Lock()
	f.badJSON = false
	f.delay = time.Second
	f.mu.Unlock()
	r := httptest.NewRequest("GET", "/api/orders", nil)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Millisecond)
	defer cancel()
	r = r.WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	b.Handler().ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("timeout: %d", w.Code)
	}
}

func TestOAuthErrorsAreSanitized(t *testing.T) {
	f, _, a, _ := stack(t)
	source := f.source("user-alice")
	for code, status := range map[string]int{"invalid_grant": 403, "invalid_scope": 403, "invalid_target": 403, "unauthorized_client": 403, "invalid_client": 502, "unsupported_grant_type": 502} {
		f.mu.Lock()
		f.exchangeCode = code
		f.mu.Unlock()
		w := callHandler(a.Handler(), source)
		if w.Code != status || strings.Contains(w.Body.String(), "DO-NOT-LEAK") || strings.Contains(w.Body.String(), source) {
			t.Fatalf("unsafe/wrong response: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestHTTPRedirectsAndBodyLimit(t *testing.T) {
	var received bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = true }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer s.Close()
	r, _ := http.NewRequest("POST", s.URL, strings.NewReader("client_secret=secret"))
	hc := newHTTPClient(s.URL, target.URL)
	resp, err := hc.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if received || resp.StatusCode != 307 {
		t.Fatal("redirect followed")
	}
	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", maxBody+1)) }))
	defer large.Close()
	resp, err = newHTTPClient(large.URL).Get(large.URL)
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("oversized response accepted")
	}
}
