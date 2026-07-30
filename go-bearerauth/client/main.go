// Command client calls the protected endpoint from the go-bearerauth example.
//
// Set BEARER_TOKEN to either a JWT access token or a complete sgk_ Personal
// API Key. API_URL defaults to http://localhost:8080/api/whoami.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const (
	defaultAPIURL       = "http://localhost:8080/api/whoami"
	requestTimeout      = 10 * time.Second
	maxResponseBodySize = 1 << 20 // 1 MiB
)

type config struct {
	apiURL      string
	bearerToken string
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func main() {
	// Existing environment variables take precedence over values in .env.
	_ = godotenv.Load()

	client := newHTTPClient()
	exitCode := execute(
		context.Background(),
		os.Getenv,
		client,
		os.Stdout,
		os.Stderr,
	)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		// Refuse redirects so the Bearer credential is sent only to API_URL.
		// In particular, never let an HTTPS endpoint redirect it to plaintext
		// HTTP or to another host that happens to be considered trusted.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// execute contains the process-level behavior so tests can verify exit codes
// and output without starting a subprocess.
func execute(
	ctx context.Context,
	getenv func(string) string,
	client httpDoer,
	stdout io.Writer,
	stderr io.Writer,
) int {
	cfg, err := loadConfig(getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "configuration error: %s\n", err)
		return 2
	}

	if err := callAPI(ctx, client, cfg, stdout); err != nil {
		_, _ = fmt.Fprintf(
			stderr,
			"error: %s\n",
			redactCredential(err.Error(), cfg.bearerToken),
		)
		return 1
	}

	return 0
}

func loadConfig(getenv func(string) string) (config, error) {
	apiURL := strings.TrimSpace(getenv("API_URL"))
	if apiURL == "" {
		apiURL = defaultAPIURL
	}
	parsedURL, err := url.Parse(apiURL)
	if err != nil ||
		(parsedURL.Scheme != "http" && parsedURL.Scheme != "https") ||
		parsedURL.Host == "" ||
		parsedURL.User != nil ||
		parsedURL.Fragment != "" {
		// Keep this error static: API_URL may itself contain accidentally
		// pasted credential material.
		return config{}, errors.New(
			"API_URL must be an absolute http(s) URL without userinfo or a fragment",
		)
	}

	bearerToken := strings.TrimSpace(getenv("BEARER_TOKEN"))
	if bearerToken == "" {
		return config{}, errors.New("BEARER_TOKEN is required")
	}
	if strings.ContainsAny(bearerToken, "\r\n") {
		return config{}, errors.New("BEARER_TOKEN must not contain line breaks")
	}

	return config{
		apiURL:      apiURL,
		bearerToken: bearerToken,
	}, nil
}

func callAPI(
	ctx context.Context,
	client httpDoer,
	cfg config,
	output io.Writer,
) error {
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		requestCtx,
		http.MethodGet,
		cfg.apiURL,
		nil,
	)
	if err != nil {
		// Do not echo API_URL: a mistakenly pasted credential should not be
		// copied into terminal output.
		return errors.New("API_URL is not a valid request URL")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.bearerToken)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf(
			"request failed: %s",
			redactCredential(err.Error(), cfg.bearerToken),
		)
	}
	if resp == nil {
		return errors.New("request failed: HTTP client returned no response")
	}
	defer resp.Body.Close()

	body, truncated, err := readResponseBody(resp.Body)
	if err != nil {
		return fmt.Errorf(
			"read response body: %s",
			redactCredential(err.Error(), cfg.bearerToken),
		)
	}

	if err := printResponse(output, resp, body, truncated, cfg.bearerToken); err != nil {
		return fmt.Errorf(
			"write response output: %s",
			redactCredential(err.Error(), cfg.bearerToken),
		)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("server returned HTTP %s", safeHTTPStatus(resp.StatusCode))
	}

	return nil
}

func readResponseBody(body io.Reader) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxResponseBodySize+1))
	if err != nil {
		return nil, false, err
	}

	truncated := len(data) > maxResponseBodySize
	if truncated {
		data = data[:maxResponseBodySize]
	}

	return data, truncated, nil
}

func printResponse(
	output io.Writer,
	resp *http.Response,
	body []byte,
	truncated bool,
	bearerToken string,
) error {
	var rendered bytes.Buffer
	_, _ = fmt.Fprintf(&rendered, "Status: %s\n", safeHTTPStatus(resp.StatusCode))

	if challenge := resp.Header.Get("WWW-Authenticate"); challenge != "" {
		_, _ = fmt.Fprintf(
			&rendered,
			"WWW-Authenticate: %s\n",
			redactCredential(challenge, bearerToken),
		)
	}

	safeBody := redactCredential(string(body), bearerToken)
	_, _ = fmt.Fprintf(&rendered, "Body: %s", safeBody)
	if len(safeBody) == 0 || safeBody[len(safeBody)-1] != '\n' {
		_ = rendered.WriteByte('\n')
	}
	if truncated {
		_, _ = fmt.Fprintln(&rendered, "(response body truncated to 1 MiB)")
	}

	_, err := io.Copy(output, &rendered)
	return err
}

func safeHTTPStatus(statusCode int) string {
	if statusText := http.StatusText(statusCode); statusText != "" {
		return fmt.Sprintf("%d %s", statusCode, statusText)
	}
	return fmt.Sprintf("%d", statusCode)
}

func redactCredential(value, bearerToken string) string {
	if bearerToken == "" {
		return value
	}
	return strings.ReplaceAll(value, bearerToken, "[REDACTED]")
}
