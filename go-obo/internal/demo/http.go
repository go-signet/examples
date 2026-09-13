package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-signet/sdk-go/oauth"
)

const maxBody = 1 << 20

// The transport pins requests to configured origins, bounds response bodies,
// and never prints headers or bodies. http.Client also refuses redirects.
type guardedTransport struct {
	origins map[string]bool
	base    http.RoundTripper
}

func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }
func (t guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.origins[origin(r.URL)] {
		return nil, errors.New("untrusted HTTP origin")
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > maxBody {
		resp.Body.Close()
		return nil, errors.New("response too large")
	}
	// All successful endpoints used by these clients return JSON. Validate the
	// complete, bounded document before SDK decoders read it: a valid first JSON
	// value followed by garbage must not become an active introspection verdict.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, errors.New("response too large")
	}
	if resp.StatusCode == http.StatusOK && !json.Valid(body) {
		return nil, errors.New("invalid upstream JSON")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}
func newHTTPClient(rawURLs ...string) *http.Client {
	origins := make(map[string]bool)
	for _, raw := range rawURLs {
		if u, err := safeURL(raw); err == nil {
			origins[origin(u)] = true
		}
	}
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: guardedTransport{origins, http.DefaultTransport}}
}

func discover(ctx context.Context, issuer string, hc *http.Client) (*oidc.Provider, oauth.Endpoints, bool, error) {
	u, err := safeURL(issuer)
	if err != nil {
		return nil, oauth.Endpoints{}, false, errors.New("invalid issuer URL")
	}
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, hc), issuer)
	if err != nil {
		return nil, oauth.Endpoints{}, false, errors.New("discovery failed; check SIGNET_URL and connectivity")
	}
	var m struct {
		Token          string `json:"token_endpoint"`
		Auth           string `json:"authorization_endpoint"`
		JWKS           string `json:"jwks_uri"`
		Introspect     string `json:"introspection_endpoint"`
		ResponseIssuer bool   `json:"authorization_response_iss_parameter_supported"`
	}
	if err := p.Claims(&m); err != nil {
		return nil, oauth.Endpoints{}, false, errors.New("invalid discovery document")
	}
	if m.Introspect == "" {
		m.Introspect = strings.TrimRight(issuer, "/") + "/oauth/introspect"
	}
	for _, raw := range []string{m.Token, m.Auth, m.JWKS, m.Introspect} {
		e, err := safeURL(raw)
		if err != nil || origin(e) != origin(u) {
			return nil, oauth.Endpoints{}, false, errors.New("discovery endpoints must remain on the configured issuer origin")
		}
	}
	return p, oauth.Endpoints{TokenURL: m.Token, AuthorizeURL: m.Auth, IntrospectionURL: m.Introspect}, m.ResponseIssuer, nil
}

type publicError struct {
	Code   string `json:"error"`
	Status int    `json:"-"`
}

func (e *publicError) Error() string            { return e.Code }
func fail(status int, code string) *publicError { return &publicError{Code: code, Status: status} }
func writeError(w http.ResponseWriter, err error) {
	e := fail(http.StatusBadGateway, "upstream_unavailable")
	var known *publicError
	if errors.As(err, &known) {
		e = known
	}
	if e.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	writeJSON(w, e.Status, e)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: noStore(h), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10}
}

// Serve stops accepting requests on Ctrl+C and drains active requests.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.New("cannot listen; check configured address and port")
	}
	s := server(addr, h)
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	log.Printf("listening on %s", addr)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(stop); err != nil {
			_ = s.Close()
		}
		return nil
	}
}
