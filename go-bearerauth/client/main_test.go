package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		environment map[string]string
		want        config
		wantErr     string
	}{
		{
			name: "defaults API URL and trims token",
			environment: map[string]string{
				"BEARER_TOKEN": "  test-token  ",
			},
			want: config{
				apiURL:      defaultAPIURL,
				bearerToken: "test-token",
			},
		},
		{
			name: "uses configured API URL",
			environment: map[string]string{
				"API_URL":      "  https://api.example.test/whoami  ",
				"BEARER_TOKEN": "sgk_example",
			},
			want: config{
				apiURL:      "https://api.example.test/whoami",
				bearerToken: "sgk_example",
			},
		},
		{
			name:        "rejects missing token",
			environment: map[string]string{},
			wantErr:     "BEARER_TOKEN is required",
		},
		{
			name: "rejects empty token",
			environment: map[string]string{
				"BEARER_TOKEN": " \t ",
			},
			wantErr: "BEARER_TOKEN is required",
		},
		{
			name: "rejects line breaks",
			environment: map[string]string{
				"BEARER_TOKEN": "test-token\nunexpected-header",
			},
			wantErr: "BEARER_TOKEN must not contain line breaks",
		},
		{
			name: "rejects relative API URL",
			environment: map[string]string{
				"API_URL":      "/api/whoami",
				"BEARER_TOKEN": "test-token",
			},
			wantErr: "API_URL must be an absolute http(s) URL without userinfo or a fragment",
		},
		{
			name: "rejects API URL userinfo",
			environment: map[string]string{
				"API_URL":      "https://user:secret@api.example.test/whoami",
				"BEARER_TOKEN": "test-token",
			},
			wantErr: "API_URL must be an absolute http(s) URL without userinfo or a fragment",
		},
		{
			name: "rejects non HTTP API URL",
			environment: map[string]string{
				"API_URL":      "ftp://api.example.test/whoami",
				"BEARER_TOKEN": "test-token",
			},
			wantErr: "API_URL must be an absolute http(s) URL without userinfo or a fragment",
		},
		{
			name: "rejects API URL fragment",
			environment: map[string]string{
				"API_URL":      "https://api.example.test/whoami#credential",
				"BEARER_TOKEN": "test-token",
			},
			wantErr: "API_URL must be an absolute http(s) URL without userinfo or a fragment",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := loadConfig(mapGetenv(tt.environment))
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("loadConfig() error = nil, want %q", tt.wantErr)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("loadConfig() error = %q, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("loadConfig() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestExecuteSuccess(t *testing.T) {
	t.Parallel()

	const token = "jwt-secret-value"
	requests := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(r.Context())
		w.Header().Set("WWW-Authenticate", `Bearer realm="go-bearerauth"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"subject":"user-123","credential_type":"jwt"}`)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(
		context.Background(),
		mapGetenv(map[string]string{
			"API_URL":      server.URL + "/api/whoami",
			"BEARER_TOKEN": token,
		}),
		server.Client(),
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("execute() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("execute() stderr = %q, want empty", stderr.String())
	}

	select {
	case req := <-requests:
		if req.Method != http.MethodGet {
			t.Errorf("request method = %q, want GET", req.Method)
		}
		if req.URL.Path != "/api/whoami" {
			t.Errorf("request path = %q, want /api/whoami", req.URL.Path)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer credential", got)
		}
	default:
		t.Fatal("server did not receive a request")
	}

	wantOutput := "" +
		"Status: 200 OK\n" +
		"WWW-Authenticate: Bearer realm=\"go-bearerauth\"\n" +
		"Body: {\"subject\":\"user-123\",\"credential_type\":\"jwt\"}\n"
	if got := stdout.String(); got != wantOutput {
		t.Fatalf("execute() stdout = %q, want %q", got, wantOutput)
	}
	if strings.Contains(stdout.String(), token) {
		t.Fatal("stdout contains bearer credential")
	}
}

func TestExecuteNon2xxShowsSafeResponseAndFails(t *testing.T) {
	t.Parallel()

	const token = "sgk_one-time-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(
			"WWW-Authenticate",
			`Bearer error="invalid_token", error_description="rejected `+token+`"`,
		)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `credential `+token+` is invalid`)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(
		context.Background(),
		mapGetenv(map[string]string{
			"API_URL":      server.URL,
			"BEARER_TOKEN": token,
		}),
		server.Client(),
		&stdout,
		&stderr,
	)

	if exitCode != 1 {
		t.Fatalf("execute() exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stdout.String(), "Status: 401 Unauthorized\n") {
		t.Errorf("stdout does not contain response status: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `WWW-Authenticate: Bearer error="invalid_token"`) {
		t.Errorf("stdout does not contain challenge: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Body: credential [REDACTED] is invalid\n") {
		t.Errorf("stdout does not contain safe response body: %q", stdout.String())
	}
	if got, want := stderr.String(), "error: server returned HTTP 401 Unauthorized\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
	if strings.Contains(stdout.String(), token) || strings.Contains(stderr.String(), token) {
		t.Fatal("client output contains bearer credential")
	}
}

func TestExecuteTruncatesResponseBody(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("x", maxResponseBodySize+64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(
		context.Background(),
		mapGetenv(map[string]string{
			"API_URL":      server.URL,
			"BEARER_TOKEN": "test-token",
		}),
		server.Client(),
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("execute() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if got := strings.Count(stdout.String(), "x"); got != maxResponseBodySize {
		t.Errorf("printed body contains %d bytes, want %d", got, maxResponseBodySize)
	}
	if !strings.HasSuffix(
		stdout.String(),
		"\n(response body truncated to 1 MiB)\n",
	) {
		t.Errorf("stdout does not report truncation: suffix = %q", tail(stdout.String(), 80))
	}
}

func TestDefaultHTTPClientRefusesRedirect(t *testing.T) {
	t.Parallel()

	const token = "redirect-sensitive-token"
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			destinationCalls.Add(1)
		},
	))
	defer destination.Close()

	redirect := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
		},
	))
	defer redirect.Close()

	var output bytes.Buffer
	err := callAPI(
		context.Background(),
		newHTTPClient(),
		config{
			apiURL:      redirect.URL,
			bearerToken: token,
		},
		&output,
	)

	if err == nil || err.Error() != "server returned HTTP 307 Temporary Redirect" {
		t.Fatalf("callAPI() error = %v, want safe HTTP 307 error", err)
	}
	if got := destinationCalls.Load(); got != 0 {
		t.Fatalf("redirect destination calls = %d, want 0", got)
	}
	if !strings.Contains(output.String(), "Status: 307 Temporary Redirect\n") {
		t.Errorf("output does not report refused redirect: %q", output.String())
	}
	if strings.Contains(output.String(), token) || strings.Contains(err.Error(), token) {
		t.Fatal("redirect result exposed bearer credential")
	}
}

func TestExecuteRedactsCredentialFromTransportError(t *testing.T) {
	t.Parallel()

	const token = "transport-secret"
	doer := httpDoerFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q, want Bearer credential", got)
		}
		deadline, ok := req.Context().Deadline()
		if !ok {
			t.Error("request context has no deadline")
		} else if remaining := time.Until(deadline); remaining <= 0 || remaining > requestTimeout {
			t.Errorf("request deadline remaining = %v, want within (0, %v]", remaining, requestTimeout)
		}
		return nil, errors.New("transport accidentally echoed " + token)
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(
		context.Background(),
		mapGetenv(map[string]string{
			"API_URL":      "https://api.example.test/whoami",
			"BEARER_TOKEN": token,
		}),
		doer,
		&stdout,
		&stderr,
	)

	if exitCode != 1 {
		t.Fatalf("execute() exit code = %d, want 1", exitCode)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if strings.Contains(stderr.String(), token) {
		t.Fatalf("stderr contains bearer credential: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "[REDACTED]") {
		t.Errorf("stderr does not indicate redaction: %q", stderr.String())
	}
}

func TestExecuteConfigurationFailureDoesNotSendRequest(t *testing.T) {
	t.Parallel()

	doer := httpDoerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP client was called with invalid configuration")
		return nil, nil
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(
		context.Background(),
		mapGetenv(nil),
		doer,
		&stdout,
		&stderr,
	)

	if exitCode != 2 {
		t.Fatalf("execute() exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if got, want := stderr.String(), "configuration error: BEARER_TOKEN is required\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

func TestExecuteInvalidURLIsConfigurationErrorAndDoesNotEchoIt(t *testing.T) {
	t.Parallel()

	const token = "url-secret"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := execute(
		context.Background(),
		mapGetenv(map[string]string{
			"API_URL":      "://invalid/" + token,
			"BEARER_TOKEN": token,
		}),
		http.DefaultClient,
		&stdout,
		&stderr,
	)

	if exitCode != 2 {
		t.Fatalf("execute() exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty", stdout.String())
	}
	if strings.Contains(stderr.String(), token) {
		t.Fatalf("stderr contains value that may be a credential: %q", stderr.String())
	}
	if !strings.Contains(
		stderr.String(),
		"API_URL must be an absolute http(s) URL without userinfo or a fragment",
	) {
		t.Errorf("stderr does not explain the error: %q", stderr.String())
	}
}

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (f httpDoerFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func mapGetenv(environment map[string]string) func(string) string {
	return func(key string) string {
		return environment[key]
	}
}

func tail(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[len(value)-max:]
}
