package demo

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:embed templates/index.html
var templates embed.FS
var index = template.Must(template.ParseFS(templates, "templates/index.html"))

const sessionCookie = "obo_session"
const loginCookie = "obo_login"

type Web struct {
	flow   *loginFlow
	store  *memoryStore
	config Config
	secure bool
	origin string
}

func NewWeb(ctx context.Context, c Config) (*Web, error) {
	f, err := newLogin(ctx, c, false)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(c.WebRedirect)
	return &Web{flow: f, store: newStore(), config: c, secure: u.Scheme == "https", origin: origin(u)}, nil
}
func (a *Web) RunMaintenance(ctx context.Context) { a.store.RunMaintenance(ctx) }
func (a *Web) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", a.home)
	m.HandleFunc("GET /login", a.login)
	m.HandleFunc("GET /callback", a.callback)
	m.HandleFunc("POST /orders", a.orders)
	m.HandleFunc("POST /logout", a.logout)
	return noStore(m)
}
func (a *Web) cookie(w http.ResponseWriter, name, value string, expiry time.Time) {
	c := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, Expires: expiry}
	if value == "" {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}
func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
func (a *Web) render(w http.ResponseWriter, s *session, result string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = index.Execute(w, struct {
		Session *session
		Result  string
	}{s, result})
}
func (a *Web) home(w http.ResponseWriter, r *http.Request) {
	s, ok := a.store.getSession(cookieValue(r, sessionCookie))
	if !ok {
		a.render(w, nil, "")
		return
	}
	a.render(w, &s, "")
}
func (a *Web) login(w http.ResponseWriter, r *http.Request) {
	tx, authURL := a.flow.start()
	key := randomID()
	if !a.store.putTransaction(key, tx) {
		writeError(w, fail(503, "login_capacity"))
		return
	}
	a.cookie(w, loginCookie, key, tx.Expires)
	http.Redirect(w, r, authURL, http.StatusFound)
}
func (a *Web) callback(w http.ResponseWriter, r *http.Request) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, fail(400, "invalid_callback"))
		return
	}
	tx, ok := a.store.takeTransaction(cookieValue(r, loginCookie), q)
	if !ok {
		writeError(w, fail(400, "invalid_state"))
		return
	}
	a.cookie(w, loginCookie, "", time.Unix(1, 0))
	result, err := a.flow.finish(r.Context(), tx, q)
	if err != nil {
		writeError(w, err)
		return
	}
	key := randomID()
	s := session{Login: *result, CSRF: randomID()}
	if !a.store.putSession(key, s) {
		writeError(w, fail(503, "session_capacity"))
		return
	}
	a.store.deleteSession(cookieValue(r, sessionCookie))
	a.cookie(w, sessionCookie, key, result.Identity.ExpiresAt)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (a *Web) postSession(w http.ResponseWriter, r *http.Request) (session, bool) {
	s, ok := a.store.getSession(cookieValue(r, sessionCookie))
	if !ok {
		writeError(w, fail(401, "login_required"))
		return session{}, false
	}
	// Synchronizer token + Origin check. Do not derive the expected origin from
	// untrusted Host/X-Forwarded-* headers.
	if o := r.Header.Get("Origin"); o != "" && o != a.origin {
		writeError(w, fail(403, "invalid_csrf"))
		return session{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || r.ParseForm() != nil || len(r.PostForm["csrf"]) != 1 || !equal(s.CSRF, r.PostForm.Get("csrf")) {
		writeError(w, fail(403, "invalid_csrf"))
		return session{}, false
	}
	return s, true
}
func (a *Web) orders(w http.ResponseWriter, r *http.Request) {
	s, ok := a.postSession(w, r)
	if !ok {
		return
	}
	result, err := fetchOrders(r.Context(), a.flow.http, a.config.URLA, s.Login.Token)
	if err != nil {
		writeError(w, err)
		return
	}
	if result.Source == nil || result.Source.Subject != s.Login.Identity.Subject || result.Downstream.Subject != s.Login.Identity.Subject {
		writeError(w, fail(502, "subject_mismatch"))
		return
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	a.render(w, &s, string(b))
}
func (a *Web) logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.postSession(w, r); !ok {
		return
	}
	a.store.deleteSession(cookieValue(r, sessionCookie))
	a.cookie(w, sessionCookie, "", time.Unix(1, 0))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
