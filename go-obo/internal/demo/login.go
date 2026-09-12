package demo

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-signet/sdk-go/jwksauth"
	"golang.org/x/oauth2"
)

type transaction struct {
	State, Nonce, Verifier string
	Expires                time.Time
}
type loginResult struct {
	Token    string
	Identity Identity
}
type loginFlow struct {
	config           oauth2.Config
	issuer, audience string
	responseIssuer   bool
	ids              *oidc.IDTokenVerifier
	access           *jwksauth.Verifier
	http             *http.Client
}

func randomID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func equal(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func newLogin(ctx context.Context, c Config, cli bool) (*loginFlow, error) {
	hc := newHTTPClient(c.Issuer, c.URLA)
	p, ep, responseIssuer, err := discover(ctx, c.Issuer, hc)
	if err != nil {
		return nil, err
	}
	id, secret, redirect := c.WebID, c.WebSecret, c.WebRedirect
	if cli {
		id, secret, redirect = c.CLIID, "", "http://"+c.CLIAddr+"/callback"
	}
	access, err := jwksauth.NewVerifier(oidc.ClientContext(ctx, hc), c.Issuer, c.AudienceA)
	if err != nil {
		return nil, fail(503, "discovery_failed")
	}
	return &loginFlow{config: oauth2.Config{ClientID: id, ClientSecret: secret, RedirectURL: redirect, Scopes: []string{"openid", InputScope}, Endpoint: oauth2.Endpoint{AuthURL: ep.AuthorizeURL, TokenURL: ep.TokenURL, AuthStyle: oauth2.AuthStyleInParams}}, issuer: c.Issuer, audience: c.AudienceA, responseIssuer: responseIssuer, ids: p.Verifier(&oidc.Config{ClientID: id}), access: access, http: hc}, nil
}

func (f *loginFlow) start() (transaction, string) {
	tx := transaction{State: randomID(), Nonce: randomID(), Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(5 * time.Minute)}
	return tx, f.config.AuthCodeURL(tx.State, oidc.Nonce(tx.Nonce), oauth2.S256ChallengeOption(tx.Verifier), oauth2.SetAuthURLParam("resource", f.audience))
}

func validState(tx transaction, q url.Values) bool {
	return time.Now().Before(tx.Expires) && len(q["state"]) == 1 && equal(tx.State, q.Get("state"))
}

func (f *loginFlow) finish(ctx context.Context, tx transaction, q url.Values) (*loginResult, error) {
	if !validState(tx, q) {
		return nil, fail(400, "invalid_state")
	}
	for _, k := range []string{"code", "error", "iss"} {
		if len(q[k]) > 1 {
			return nil, fail(400, "invalid_callback")
		}
	}
	iss := q.Get("iss")
	if (f.responseIssuer && iss == "") || (iss != "" && iss != f.issuer) {
		return nil, fail(400, "invalid_issuer")
	}
	if q.Get("error") != "" {
		return nil, fail(400, "authorization_denied")
	}
	if q.Get("code") == "" {
		return nil, fail(400, "missing_code")
	}
	ctx = oidc.ClientContext(ctx, f.http)
	tok, err := f.config.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		return nil, fail(502, "code_exchange_failed")
	}
	if tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "Bearer") {
		return nil, fail(502, "invalid_login_response")
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fail(502, "missing_id_token")
	}
	id, err := f.ids.Verify(ctx, rawID)
	if err != nil || !equal(id.Nonce, tx.Nonce) {
		return nil, fail(401, "invalid_id_token")
	}
	if id.AccessTokenHash != "" {
		if err := id.VerifyAccessToken(tok.AccessToken); err != nil {
			return nil, fail(401, "invalid_id_token")
		}
	}
	access, err := f.access.Verify(ctx, tok.AccessToken)
	if err != nil {
		return nil, fail(401, "invalid_token")
	}
	identity, err := validateUser(access, f.audience, "", InputScope)
	if err != nil {
		return nil, err
	}
	if identity.Subject != id.Subject || identity.ClientID != f.config.ClientID {
		return nil, fail(401, "subject_mismatch")
	}
	// Only the access token survives this call. No refresh token or ID token is
	// persisted. Its verified JWT expiry controls the local session lifetime.
	return &loginResult{Token: tok.AccessToken, Identity: identity}, nil
}

type session struct {
	Login loginResult
	CSRF  string
}
type memoryStore struct {
	mu           sync.Mutex
	transactions map[string]transaction
	sessions     map[string]session
}

func newStore() *memoryStore {
	return &memoryStore{transactions: map[string]transaction{}, sessions: map[string]session{}}
}
func (s *memoryStore) sweep() {
	for k, v := range s.transactions {
		if !time.Now().Before(v.Expires) {
			delete(s.transactions, k)
		}
	}
	for k, v := range s.sessions {
		if !time.Now().Before(v.Login.Identity.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
}
func (s *memoryStore) putTransaction(key string, tx transaction) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	if len(s.transactions) >= 1000 {
		return false
	}
	s.transactions[key] = tx
	return true
}
func (s *memoryStore) takeTransaction(key string, q url.Values) (transaction, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	tx, ok := s.transactions[key]
	if !ok || !validState(tx, q) {
		return transaction{}, false
	}
	delete(s.transactions, key)
	return tx, true
}
func (s *memoryStore) putSession(key string, v session) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	if len(s.sessions) >= 1000 {
		return false
	}
	s.sessions[key] = v
	return true
}
func (s *memoryStore) getSession(key string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep()
	v, ok := s.sessions[key]
	return v, ok
}
func (s *memoryStore) deleteSession(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, key)
}

// RunMaintenance also removes expired secrets when no requests arrive.
func (s *memoryStore) RunMaintenance(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.mu.Lock()
			s.sweep()
			s.mu.Unlock()
		}
	}
}
