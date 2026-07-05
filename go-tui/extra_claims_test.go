package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// parseClaimValue
// -----------------------------------------------------------------------

func TestParseClaimValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want any
	}{
		{"plain string", "acme", "acme"},
		{"empty stays empty string", "", ""},
		{"integer keeps json.Number type", "42", json.Number("42")},
		{"bool true", "true", true},
		{"bool false", "false", false},
		{"null literal", "null", nil},
		{"json array", `["a","b"]`, []any{"a", "b"}},
		{"json object", `{"k":1}`, map[string]any{"k": json.Number("1")}},
		{"quoted string keeps quotes off", `"acme"`, "acme"},
		{"unquoted starting with t but not bool stays string", "tomato", "tomato"},
		{"hyphen-prefixed non-number stays string", "-not-a-number", "-not-a-number"},
		{"negative number keeps json.Number type", "-42", json.Number("-42")},
		{"trailing data after number falls back to raw", "42 extra", "42 extra"},
		{"trailing data after object falls back to raw", `{"k":1} x`, `{"k":1} x`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseClaimValue(tc.in)
			if !equalAny(got, tc.want) {
				t.Errorf("parseClaimValue(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
			// For numeric inputs also assert the concrete Go type so a
			// regression that drops UseNumber (and silently coerces to
			// float64) would fail this test even though equalAny still
			// compares JSON-equal forms.
			if _, isNum := tc.want.(json.Number); isNum {
				if _, ok := got.(json.Number); !ok {
					t.Errorf("parseClaimValue(%q) returned %T, want json.Number", tc.in, got)
				}
			}
		})
	}
}

func equalAny(a, b any) bool {
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(ab) == string(bb)
}

// -----------------------------------------------------------------------
// parseExtraClaimPair
// -----------------------------------------------------------------------

func TestParseExtraClaimPair(t *testing.T) {
	t.Run("valid string", func(t *testing.T) {
		k, v, err := parseExtraClaimPair("project=acme")
		if err != nil || k != "project" || v != "acme" {
			t.Fatalf("got (%q, %v, %v)", k, v, err)
		}
	})

	t.Run("value containing equals signs is preserved", func(t *testing.T) {
		k, v, err := parseExtraClaimPair("token=a=b=c")
		if err != nil || k != "token" || v != "a=b=c" {
			t.Fatalf("got (%q, %v, %v)", k, v, err)
		}
	})

	t.Run("typed int value", func(t *testing.T) {
		k, v, err := parseExtraClaimPair("count=42")
		if err != nil || k != "count" || string(v.(json.Number)) != "42" {
			t.Fatalf("got (%q, %v, %v)", k, v, err)
		}
	})

	t.Run("missing equals", func(t *testing.T) {
		_, _, err := parseExtraClaimPair("project")
		if err == nil {
			t.Fatal("expected error for missing =")
		}
	})

	t.Run("empty key", func(t *testing.T) {
		_, _, err := parseExtraClaimPair("=value")
		if err == nil {
			t.Fatal("expected error for empty key")
		}
	})

	t.Run("empty value preserved", func(t *testing.T) {
		k, v, err := parseExtraClaimPair("trace=")
		if err != nil || k != "trace" || v != "" {
			t.Fatalf("got (%q, %v, %v)", k, v, err)
		}
	})

	t.Run("surrounding key whitespace trimmed", func(t *testing.T) {
		// Matches godotenv key-trimming on the --extra-claims-file path so a
		// flag with an incidental space still overrides the file's key.
		k, v, err := parseExtraClaimPair("  project  =acme")
		if err != nil || k != "project" || v != "acme" {
			t.Fatalf("got (%q, %v, %v)", k, v, err)
		}
	})

	t.Run("whitespace-only key rejected", func(t *testing.T) {
		_, _, err := parseExtraClaimPair("   =value")
		if err == nil {
			t.Fatal("expected error for whitespace-only key")
		}
	})
}

// -----------------------------------------------------------------------
// resolveExtraClaims
// -----------------------------------------------------------------------

func TestResolveExtraClaims_FlagOnly(t *testing.T) {
	got, err := resolveExtraClaims([]string{"project=acme", "count=42"}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{"project": "acme", "count": float64(42)}
	assertJSONEqual(t, got, want)
}

func TestResolveExtraClaims_NoInputReturnsEmpty(t *testing.T) {
	got, err := resolveExtraClaims(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string when no input, got %q", got)
	}
}

func TestResolveExtraClaims_FileOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claims.env")
	const body = `# leading comment
project=acme
count=7
enabled=true
trace_id=req-42
`
	mustWriteFile(t, path, body)

	got, err := resolveExtraClaims(nil, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{
		"project":  "acme",
		"count":    float64(7),
		"enabled":  true,
		"trace_id": "req-42",
	}
	assertJSONEqual(t, got, want)
}

func TestResolveExtraClaims_FlagOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "claims.env")
	mustWriteFile(t, path, "project=from-file\ntrace=keep\n")

	got, err := resolveExtraClaims([]string{"project=from-flag"}, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]any{"project": "from-flag", "trace": "keep"}
	assertJSONEqual(t, got, want)
}

func TestResolveExtraClaims_MalformedFlagPair(t *testing.T) {
	// Use a pair that looks secret-ish to confirm the value is NOT echoed.
	const secret = "looks-like-a-secret-token"
	_, err := resolveExtraClaims([]string{secret}, "")
	if err == nil {
		t.Fatal("expected error for malformed pair")
	}
	if !strings.Contains(err.Error(), "key=value") {
		t.Errorf("error should mention key=value form, got: %v", err)
	}
	if !strings.Contains(err.Error(), "#1") {
		t.Errorf("error should reference pair index, got: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error must not echo the malformed pair value, got: %v", err)
	}
}

func TestResolveExtraClaims_FileNotFound(t *testing.T) {
	_, err := resolveExtraClaims(nil, "/nonexistent/path/claims.env")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestResolveExtraClaims_EmptyFileNoFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.env")
	mustWriteFile(t, path, "# only comments\n\n")

	got, err := resolveExtraClaims(nil, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty result for empty file, got %q", got)
	}
}

// -----------------------------------------------------------------------
// Wire-level integration: each grant sends extra_claims when set
// -----------------------------------------------------------------------

func TestRefreshAccessToken_SendsExtraClaims(t *testing.T) {
	gotForm := captureTokenEndpointForm(t,
		`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600}`)
	cfg := testConfig(t)
	cfg.ServerURL = gotForm.serverURL
	cfg.Endpoints = defaultEndpoints(gotForm.serverURL)
	cfg.ExtraClaims = `{"project":"acme"}`

	if _, err := refreshAccessToken(context.Background(), cfg, "old-refresh"); err != nil {
		t.Fatalf("refreshAccessToken() error: %v", err)
	}

	form := gotForm.value(t)
	if got := form.Get("extra_claims"); got != `{"project":"acme"}` {
		t.Errorf("extra_claims = %q, want %q", got, `{"project":"acme"}`)
	}
	if got := form.Get("grant_type"); got != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", got)
	}
}

func TestRefreshAccessToken_OmitsExtraClaimsWhenUnset(t *testing.T) {
	gotForm := captureTokenEndpointForm(t,
		`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600}`)
	cfg := testConfig(t)
	cfg.ServerURL = gotForm.serverURL
	cfg.Endpoints = defaultEndpoints(gotForm.serverURL)
	cfg.ExtraClaims = ""

	if _, err := refreshAccessToken(context.Background(), cfg, "old-refresh"); err != nil {
		t.Fatalf("refreshAccessToken() error: %v", err)
	}

	form := gotForm.value(t)
	if _, present := form["extra_claims"]; present {
		t.Errorf("extra_claims should be absent, got %q", form.Get("extra_claims"))
	}
}

func TestExchangeCode_SendsExtraClaims(t *testing.T) {
	gotForm := captureTokenEndpointForm(t,
		`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600}`)
	cfg := testConfig(t)
	cfg.ServerURL = gotForm.serverURL
	cfg.Endpoints = defaultEndpoints(gotForm.serverURL)
	cfg.ExtraClaims = `{"trace_id":"req-42"}`

	if _, err := exchangeCode(context.Background(), cfg, "auth-code", "verifier"); err != nil {
		t.Fatalf("exchangeCode() error: %v", err)
	}

	form := gotForm.value(t)
	if got := form.Get("extra_claims"); got != `{"trace_id":"req-42"}` {
		t.Errorf("extra_claims = %q", got)
	}
	if got := form.Get("grant_type"); got != "authorization_code" {
		t.Errorf("grant_type = %q, want authorization_code", got)
	}
}

func TestExchangeCode_OmitsExtraClaimsWhenUnset(t *testing.T) {
	gotForm := captureTokenEndpointForm(t,
		`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600}`)
	cfg := testConfig(t)
	cfg.ServerURL = gotForm.serverURL
	cfg.Endpoints = defaultEndpoints(gotForm.serverURL)
	cfg.ExtraClaims = ""

	if _, err := exchangeCode(context.Background(), cfg, "auth-code", "verifier"); err != nil {
		t.Fatalf("exchangeCode() error: %v", err)
	}
	if _, present := gotForm.value(t)["extra_claims"]; present {
		t.Error("extra_claims should be absent when cfg.ExtraClaims is empty")
	}
}

func TestExchangeDeviceCode_OmitsExtraClaimsWhenUnset(t *testing.T) {
	gotForm := captureTokenEndpointForm(t,
		`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600}`)
	cfg := testConfig(t)
	cfg.ServerURL = gotForm.serverURL
	cfg.Endpoints = defaultEndpoints(gotForm.serverURL)
	cfg.ExtraClaims = ""

	_, err := exchangeDeviceCode(
		context.Background(), cfg, cfg.Endpoints.TokenURL, cfg.ClientID, "device-code-xyz",
	)
	if err != nil {
		t.Fatalf("exchangeDeviceCode() error: %v", err)
	}
	if _, present := gotForm.value(t)["extra_claims"]; present {
		t.Error("extra_claims should be absent when cfg.ExtraClaims is empty")
	}
}

// Values containing form-reserved characters (&, =, +) and multibyte runes
// must round-trip intact through url.Values.Encode + r.ParseForm.
func TestRefreshAccessToken_ExtraClaimsSurviveURLEncoding(t *testing.T) {
	gotForm := captureTokenEndpointForm(t,
		`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600}`)
	cfg := testConfig(t)
	cfg.ServerURL = gotForm.serverURL
	cfg.Endpoints = defaultEndpoints(gotForm.serverURL)

	// Build via resolveExtraClaims so the test exercises the full pipe.
	resolved, err := resolveExtraClaims(
		[]string{"trace_id=a&b=c+d", "name=世界", "tags=[\"x\",\"y\"]"}, "")
	if err != nil {
		t.Fatalf("resolveExtraClaims() error: %v", err)
	}
	cfg.ExtraClaims = resolved

	if _, err := refreshAccessToken(context.Background(), cfg, "old-refresh"); err != nil {
		t.Fatalf("refreshAccessToken() error: %v", err)
	}
	got := gotForm.value(t).Get("extra_claims")
	if got != resolved {
		t.Errorf("extra_claims round-trip mismatch\n  sent: %s\n  got:  %s", resolved, got)
	}
	// Also confirm the JSON deserializes back to the original values.
	var claims map[string]any
	if err := json.Unmarshal([]byte(got), &claims); err != nil {
		t.Fatalf("server-side decode failed: %v", err)
	}
	if claims["trace_id"] != "a&b=c+d" {
		t.Errorf("trace_id = %v, want %q", claims["trace_id"], "a&b=c+d")
	}
	if claims["name"] != "世界" {
		t.Errorf("name = %v, want %q", claims["name"], "世界")
	}
}

// Integers above 2^53 must round-trip exactly. Without UseNumber they would
// be coerced to float64 and silently rounded.
func TestParseClaimValue_PreservesLargeIntegerPrecision(t *testing.T) {
	const big = "9007199254740993" // 2^53 + 1, not exactly representable as float64
	got := parseClaimValue(big)
	num, ok := got.(json.Number)
	if !ok {
		t.Fatalf("expected json.Number, got %T (%v)", got, got)
	}
	if string(num) != big {
		t.Errorf("precision lost: got %s, want %s", num, big)
	}

	// And confirm it survives the full resolveExtraClaims → re-encode path.
	resolved, err := resolveExtraClaims([]string{"id=" + big}, "")
	if err != nil {
		t.Fatalf("resolveExtraClaims() error: %v", err)
	}
	want := `{"id":` + big + `}`
	if resolved != want {
		t.Errorf("encoded extra_claims = %s, want %s", resolved, want)
	}
}

func TestLoadExtraClaimsFile_RejectsOversizedInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.env")

	// Build a file just over maxExtraClaimsFileSize using unique keys per
	// line so godotenv can't collapse them into one entry.
	var b strings.Builder
	for i := 0; b.Len() <= int(maxExtraClaimsFileSize); i++ {
		fmt.Fprintf(&b, "key_%06d=%s\n", i, strings.Repeat("v", 64))
	}
	mustWriteFile(t, path, b.String())

	_, err := loadExtraClaimsFile(path)
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected 'too large' in error, got: %v", err)
	}
}

func TestLoadExtraClaimsFile_AcceptsAtSizeLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exact.env")

	// Build a file at exactly maxExtraClaimsFileSize so the boundary check
	// (limit+1 read with > comparison) is exercised: this size must succeed.
	var b strings.Builder
	for i := 0; b.Len() < int(maxExtraClaimsFileSize); i++ {
		fmt.Fprintf(&b, "key_%06d=%s\n", i, strings.Repeat("v", 64))
	}
	body := b.String()
	if int64(len(body)) > maxExtraClaimsFileSize {
		body = body[:maxExtraClaimsFileSize]
	}
	mustWriteFile(t, path, body)

	if _, err := loadExtraClaimsFile(path); err != nil {
		t.Fatalf("expected file at size limit to succeed, got: %v", err)
	}
}

func TestLoadExtraClaimsFile_MalformedSyntax(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.env")
	// godotenv rejects lines with mismatched quotes.
	mustWriteFile(t, path, "key=\"unterminated\n")

	if _, err := loadExtraClaimsFile(path); err == nil {
		t.Fatal("expected error for malformed env file")
	}
}

func TestExchangeDeviceCode_SendsExtraClaims(t *testing.T) {
	gotForm := captureTokenEndpointForm(t,
		`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600}`)
	cfg := testConfig(t)
	cfg.ServerURL = gotForm.serverURL
	cfg.Endpoints = defaultEndpoints(gotForm.serverURL)
	cfg.ExtraClaims = `{"project":"acme","count":7}`

	_, err := exchangeDeviceCode(
		context.Background(), cfg, cfg.Endpoints.TokenURL, cfg.ClientID, "device-code-xyz",
	)
	if err != nil {
		t.Fatalf("exchangeDeviceCode() error: %v", err)
	}

	form := gotForm.value(t)
	if got := form.Get("extra_claims"); got != `{"project":"acme","count":7}` {
		t.Errorf("extra_claims = %q", got)
	}
	if got := form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:device_code" {
		t.Errorf("grant_type = %q", got)
	}
}

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

type formCapture struct {
	serverURL string
	captured  chan map[string][]string
}

// value blocks until the test server records a request, then returns the
// captured form values. Times out instead of hanging so a missed capture
// (e.g., the request never reached our server) fails loudly rather than
// silently passing.
func (f *formCapture) value(t *testing.T) formValues {
	t.Helper()
	select {
	case v := <-f.captured:
		return formValues(v)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for token endpoint request")
		return nil
	}
}

type formValues map[string][]string

func (f formValues) Get(key string) string {
	if v, ok := f[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// captureTokenEndpointForm spins up an httptest server that records the form
// posted to it and replies with the given JSON body. The server is registered
// for cleanup with t.Cleanup.
func captureTokenEndpointForm(t *testing.T, jsonResponse string) *formCapture {
	t.Helper()
	captured := make(chan map[string][]string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		captured <- r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jsonResponse))
	}))
	t.Cleanup(srv.Close)
	return &formCapture{serverURL: srv.URL, captured: captured}
}

func mustWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertJSONEqual(t *testing.T, gotJSON string, want map[string]any) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(gotJSON), &got); err != nil {
		t.Fatalf("got is not valid JSON: %v\n  got: %s", err, gotJSON)
	}
	gotBytes, _ := json.Marshal(got)
	wantBytes, _ := json.Marshal(want)
	if string(gotBytes) != string(wantBytes) {
		t.Errorf("JSON mismatch\n  got:  %s\n  want: %s", gotBytes, wantBytes)
	}
}
