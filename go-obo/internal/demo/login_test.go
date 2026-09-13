package demo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func noRedirectBrowser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func get(t *testing.T, hc *http.Client, raw string) *http.Response {
	t.Helper()
	resp, err := hc.Get(raw)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// No real user login or consent is automated here. /authorize is an explicit
// test double that returns an authorization code with the request's bindings.
func webLogin(t *testing.T, w *Web, s *httptest.Server, browser *http.Client) string {
	t.Helper()
	resp := get(t, browser, s.URL+"/login")
	auth := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	resp = get(t, browser, auth)
	callback := resp.Header.Get("Location")
	resp.Body.Close()
	resp = get(t, browser, callback)
	body := readBody(t, resp)
	if resp.StatusCode != 303 {
		t.Fatalf("callback: %d %s", resp.StatusCode, body)
	}
	u, _ := url.Parse(s.URL)
	for _, c := range browser.Jar.Cookies(u) {
		if c.Name == sessionCookie {
			return c.Value
		}
	}
	t.Fatal("missing session cookie")
	return ""
}
func newTestWeb(t *testing.T, c Config) (*Web, *httptest.Server) {
	t.Helper()
	s := httptest.NewUnstartedServer(nil)
	c.WebRedirect = "http://" + s.Listener.Addr().String() + "/callback"
	w, err := NewWeb(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Handler = w.Handler()
	s.Start()
	t.Cleanup(s.Close)
	return w, s
}
func TestWebLoginOrdersLogoutAndIsolation(t *testing.T) {
	f, c, _, _ := stack(t)
	w, s := newTestWeb(t, c)
	browser := noRedirectBrowser()
	id := webLogin(t, w, s, browser)
	session, ok := w.store.getSession(id)
	if !ok {
		t.Fatal("missing session")
	}
	resp, err := browser.PostForm(s.URL+"/orders", url.Values{"csrf": {session.CSRF}})
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, "Example notebook") || strings.Contains(body, session.Login.Token) || strings.Contains(body, "a-secret") {
		t.Fatalf("unexpected orders response %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("missing no-store")
	}
	for _, form := range []url.Values{{}, {"csrf": {"wrong"}}, {"csrf": {session.CSRF, session.CSRF}}} {
		resp, err = browser.PostForm(s.URL+"/orders", form)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatal("CSRF accepted")
		}
	}
	f.mu.Lock()
	f.subject = "user-bob"
	f.mu.Unlock()
	other := noRedirectBrowser()
	otherID := webLogin(t, w, s, other)
	otherSession, _ := w.store.getSession(otherID)
	if otherSession.Login.Identity.Subject == session.Login.Identity.Subject {
		t.Fatal("sessions not isolated")
	}
	resp, err = other.PostForm(s.URL+"/orders", url.Values{"csrf": {session.CSRF}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("cross-session CSRF accepted")
	}
	resp, err = browser.PostForm(s.URL+"/logout", url.Values{"csrf": {session.CSRF}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Fatal("logout failed")
	}
	if _, ok := w.store.getSession(id); ok {
		t.Fatal("old session survived logout")
	}
	resp, err = browser.PostForm(s.URL+"/orders", url.Values{"csrf": {session.CSRF}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("logged-out request accepted")
	}
}

func callbackQuery(t *testing.T, f *loginFlow, tx transaction) url.Values {
	t.Helper()
	auth := f.config.AuthCodeURL(tx.State)
	u, _ := url.Parse(auth)
	q := u.Query()
	q.Set("nonce", tx.Nonce)
	q.Set("resource", f.audience)
	q.Set("code_challenge_method", "S256")
	// Same S256 derivation as the actual browser request.
	q.Set("code_challenge", pkceChallenge(tx.Verifier))
	u.RawQuery = q.Encode()
	resp := get(t, noRedirectBrowser(), u.String())
	defer resp.Body.Close()
	cb, _ := url.Parse(resp.Header.Get("Location"))
	return cb.Query()
}

func TestLoginCallbackBindings(t *testing.T) {
	f := newIssuer(t)
	flow, err := newLogin(t.Context(), fixtureConfig(f), false)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		modify func(url.Values)
	}{
		{"missing state", func(q url.Values) { q.Del("state") }},
		{"wrong state", func(q url.Values) { q.Set("state", "wrong") }},
		{"duplicate state", func(q url.Values) { q.Add("state", q.Get("state")) }},
		{"wrong issuer", func(q url.Values) { q.Set("iss", "https://wrong.example") }},
		{"missing issuer", func(q url.Values) { q.Del("iss") }},
		{"duplicate code", func(q url.Values) { q.Add("code", q.Get("code")) }},
		{"denied", func(q url.Values) {
			q.Del("code")
			q.Set("error", "access_denied")
			q.Set("error_description", "DO-NOT-LEAK")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, _ := flow.start()
			q := callbackQuery(t, flow, tx)
			tc.modify(q)
			f.mu.Lock()
			before := f.tokenCalls
			f.mu.Unlock()
			_, err := flow.finish(t.Context(), tx, q)
			if err == nil || strings.Contains(err.Error(), "DO-NOT-LEAK") {
				t.Fatal("invalid callback accepted/leaked")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.tokenCalls != before {
				t.Fatal("invalid callback reached token endpoint")
			}
		})
	}
	tx, _ := flow.start()
	q := callbackQuery(t, flow, tx)
	f.mu.Lock()
	f.badNonce = true
	f.mu.Unlock()
	if _, err := flow.finish(t.Context(), tx, q); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	f.mu.Lock()
	f.badNonce = false
	f.mu.Unlock()
	tx, _ = flow.start()
	q = callbackQuery(t, flow, tx)
	tx.Verifier = "different"
	if _, err := flow.finish(t.Context(), tx, q); err == nil {
		t.Fatal("wrong verifier accepted")
	}
	tx, _ = flow.start()
	q = callbackQuery(t, flow, tx)
	tx.Expires = time.Now().Add(-time.Second)
	if _, err := flow.finish(t.Context(), tx, q); err == nil {
		t.Fatal("expired transaction accepted")
	}
}

func TestTransactionReplayAndSessionExpiry(t *testing.T) {
	s := newStore()
	tx := transaction{State: "state", Expires: time.Now().Add(time.Minute)}
	s.putTransaction("cookie", tx)
	if _, ok := s.takeTransaction("wrong-cookie", url.Values{"state": {"state"}}); ok {
		t.Fatal("cross-browser transaction accepted")
	}
	if _, ok := s.takeTransaction("cookie", url.Values{"state": {"state"}}); !ok {
		t.Fatal("first callback rejected")
	}
	if _, ok := s.takeTransaction("cookie", url.Values{"state": {"state"}}); ok {
		t.Fatal("replay accepted")
	}
	s.putSession("expired", session{Login: loginResult{Identity: Identity{ExpiresAt: time.Now().Add(-time.Second)}}})
	if _, ok := s.getSession("expired"); ok {
		t.Fatal("expired session accepted")
	}
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			for range 50 {
				key := randomID()
				s.putTransaction(key, tx)
				s.takeTransaction(key, url.Values{"state": {"state"}})
				s.getSession("none")
			}
		})
	}
	wg.Wait()
}

// Captures the CLI output safely while a test browser completes login.
type cliOutput struct {
	mu   sync.Mutex
	body bytes.Buffer
	urls chan string
}

func (o *cliOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n, err := o.body.Write(p)
	for _, line := range strings.Split(string(p), "\n") {
		if strings.HasPrefix(line, "http") {
			select {
			case o.urls <- line:
			default:
			}
		}
	}
	return n, err
}
func (o *cliOutput) String() string { o.mu.Lock(); defer o.mu.Unlock(); return o.body.String() }
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func TestCLIFlowAndCancellation(t *testing.T) {
	_, c, _, _ := stack(t)
	c.CLIAddr = freeAddr(t)
	out := &cliOutput{urls: make(chan string, 1)}
	done := make(chan error, 1)
	go func() { done <- RunCLI(t.Context(), c, out) }()
	var auth string
	select {
	case auth = <-out.urls:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("CLI did not start")
	}
	browser := noRedirectBrowser()
	resp := get(t, browser, auth)
	callback := resp.Header.Get("Location")
	resp.Body.Close()
	resp = get(t, browser, callback)
	if resp.StatusCode != 200 {
		t.Fatalf("CLI callback %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CLI did not finish")
	}
	body := out.String()
	at := strings.Index(body, "{\n")
	if at < 0 {
		t.Fatal("missing JSON")
	}
	var result OrdersResult
	if json.Unmarshal([]byte(body[at:]), &result) != nil || result.Downstream.Subject != "user-alice" {
		t.Fatal("missing result")
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "eyJ") {
		t.Fatal("CLI leaked credentials")
	}
	l, err := net.Listen("tcp", c.CLIAddr)
	if err != nil {
		t.Fatal("CLI did not close listener")
	}
	l.Close()
	ctx, cancel := context.WithCancel(t.Context())
	out = &cliOutput{urls: make(chan string, 1)}
	go func() { done <- RunCLI(ctx, c, out) }()
	select {
	case <-out.urls:
		cancel()
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("CLI did not restart")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation ignored")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CLI cancellation hung")
	}
}

func pkceChallenge(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
