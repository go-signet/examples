package demo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-signet/sdk-go/jwksauth"
	"github.com/go-signet/sdk-go/oauth"
)

// Identity contains only explicitly selected, verified claims. Never serialize
// an oauth.Token or the JWT's arbitrary extra claims into an application reply.
type Identity struct {
	Subject   string    `json:"sub"`
	ClientID  string    `json:"client_id"`
	Actor     string    `json:"actor,omitempty"`
	Audience  []string  `json:"aud"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Order struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
	Item  string `json:"item"`
}
type OrdersResult struct {
	Source     *Identity `json:"source,omitempty"`
	Downstream Identity  `json:"downstream"`
	Orders     []Order   `json:"orders"`
	Demo       bool      `json:"demo"`
}

type API struct {
	config     Config
	downstream bool
	verifier   *jwksauth.Verifier
	oauth      *oauth.Client
	http       *http.Client
}

func newOAuthClient(id, secret string, endpoints oauth.Endpoints, hc *http.Client) (*oauth.Client, error) {
	// No automatic retries: an exchange is issuance, and an authorization failure
	// cannot be repaired by repeating it. Callers can explicitly start a new action.
	rc, err := oauth.NewDefaultHTTPClient(retry.WithHTTPClient(hc), retry.WithMaxRetries(0))
	if err != nil {
		return nil, errors.New("cannot configure OAuth HTTP client")
	}
	return oauth.NewClient(id, endpoints, oauth.WithClientSecret(secret), oauth.WithHTTPClient(rc))
}

func NewAPI(ctx context.Context, c Config, downstream bool) (*API, error) {
	hc := newHTTPClient(c.Issuer, c.URLB)
	_, endpoints, _, err := discover(ctx, c.Issuer, hc)
	if err != nil {
		return nil, err
	}
	aud, id, secret := c.AudienceA, c.AID, c.ASecret
	if downstream {
		aud, id, secret = c.AudienceB, c.BID, c.BSecret
	}
	v, err := jwksauth.NewVerifier(oidc.ClientContext(ctx, hc), c.Issuer, aud)
	if err != nil {
		return nil, errors.New("cannot initialize JWT verifier")
	}
	oc, err := newOAuthClient(id, secret, endpoints, hc)
	if err != nil {
		return nil, err
	}
	return &API{config: c, downstream: downstream, verifier: v, oauth: oc, http: hc}, nil
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /api/orders", a.orders)
	return noStore(mux)
}

func bearer(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || len(values[0]) > 8<<10 {
		return "", fail(401, "invalid_token")
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.ContainsAny(parts[1], ",\r\n") {
		return "", fail(401, "invalid_token")
	}
	return parts[1], nil
}

func validateUser(info *jwksauth.TokenInfo, audience, actorID, scope string) (Identity, error) {
	var raw struct {
		Type   string `json:"type"`
		UserID string `json:"user_id"`
	}
	if info == nil || info.IDToken == nil {
		return Identity{}, fail(401, "invalid_token")
	}
	err := info.IDToken.Claims(&raw)
	if err != nil || raw.Type != "access" || info.Subject == "" || strings.HasPrefix(info.Subject, "client:") || raw.UserID != info.Subject ||
		len(info.Audience) != 1 || info.Audience[0] != audience || info.Claims.ClientID == "" {
		return Identity{}, fail(401, "invalid_token")
	}
	actor := info.Claims.Actor
	if actorID == "" && actor != nil || actorID != "" && (actor == nil || actor.Subject != "client:"+actorID || info.Claims.ClientID != actorID) {
		return Identity{}, fail(401, "invalid_actor")
	}
	if !info.HasScope(scope) {
		return Identity{}, fail(403, "insufficient_scope")
	}
	i := Identity{Subject: info.Subject, ClientID: info.Claims.ClientID, Audience: info.Audience, Scope: info.Claims.Scope, ExpiresAt: info.Expiry}
	if actor != nil {
		i.Actor = actor.Subject
	}
	return i, nil
}

func (a *API) orders(w http.ResponseWriter, r *http.Request) {
	// Prevent this teaching endpoint from becoming a generic token-exchange proxy.
	if r.URL.RawQuery != "" {
		writeError(w, fail(400, "unexpected_query"))
		return
	}
	raw, err := bearer(r)
	if err != nil {
		writeError(w, err)
		return
	}
	info, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		writeError(w, fail(401, "invalid_token"))
		return
	}
	aud, actor, scope := a.config.AudienceA, "", InputScope
	if a.downstream {
		aud, actor, scope = a.config.AudienceB, a.config.AID, OutputScope
	}
	identity, err := validateUser(info, aud, actor, scope)
	if err != nil {
		writeError(w, err)
		return
	}
	if a.downstream {
		// With ownership enforcement the response can be ONLY {active:true}.
		// Identity and permissions came from the verified JWT above, never from
		// unsigned payload decoding or assumptions about introspection metadata.
		verdict, err := a.oauth.Introspect(r.Context(), raw)
		if err != nil {
			writeError(w, fail(503, "introspection_unavailable"))
			return
		}
		if !verdict.Active {
			writeError(w, fail(401, "inactive_token"))
			return
		}
		sum := sha256.Sum256([]byte(identity.Subject))
		writeJSON(w, 200, OrdersResult{Downstream: identity, Demo: true, Orders: []Order{{ID: "demo-" + hex.EncodeToString(sum[:6]), Owner: identity.Subject, Item: "Example notebook"}}})
		return
	}
	// A authenticates as itself but the assertion is the user's F-issued token.
	token, err := a.oauth.ExchangeOnBehalfOf(r.Context(), oauth.OnBehalfOfRequest{Assertion: raw, Resource: a.config.AudienceB, Scopes: []string{OutputScope}})
	if err != nil {
		writeError(w, exchangeError(err))
		return
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.ExpiresIn <= 0 || token.ExpiresIn > 300 || token.RefreshToken != "" || token.IDToken != "" {
		writeError(w, fail(502, "invalid_exchange_response"))
		return
	}
	result, err := fetchOrders(r.Context(), a.http, a.config.URLB, token.AccessToken)
	if err != nil {
		writeError(w, err)
		return
	}
	if result.Downstream.Subject != identity.Subject {
		writeError(w, fail(502, "subject_mismatch"))
		return
	}
	result.Source = &identity
	writeJSON(w, 200, result)
}

func exchangeError(err error) error {
	var oe *oauth.Error
	if errors.As(err, &oe) {
		switch oe.Code {
		case "invalid_grant", "invalid_scope", "unauthorized_client", "invalid_target":
			return fail(403, oe.Code)
		case "invalid_client", "unsupported_grant_type", "invalid_request":
			return fail(502, oe.Code)
		}
	}
	return fail(503, "exchange_unavailable")
}

func fetchOrders(ctx context.Context, hc *http.Client, base, token string) (*OrdersResult, error) {
	r, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(base, "/")+"/api/orders", nil)
	if err != nil {
		return nil, fail(502, "invalid_api_url")
	}
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := hc.Do(r)
	if err != nil {
		return nil, fail(503, "api_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// Only relay known codes. Never relay arbitrary upstream error text.
		var upstream publicError
		_ = json.NewDecoder(resp.Body).Decode(&upstream)
		allowed := map[string]bool{"invalid_token": true, "invalid_actor": true, "inactive_token": true, "insufficient_scope": true, "invalid_grant": true, "invalid_scope": true, "unauthorized_client": true, "invalid_target": true, "introspection_unavailable": true, "exchange_unavailable": true, "invalid_client": true, "unsupported_grant_type": true, "invalid_request": true}
		if allowed[upstream.Code] && (resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 502 || resp.StatusCode == 503) {
			return nil, fail(resp.StatusCode, upstream.Code)
		}
		return nil, fail(502, "api_rejected_request")
	}
	var result OrdersResult
	d := json.NewDecoder(resp.Body)
	if err := d.Decode(&result); err != nil {
		return nil, fail(502, "invalid_api_response")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fail(502, "invalid_api_response")
	}
	return &result, nil
}
