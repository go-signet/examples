// M2M (Machine-to-Machine) example using Client Credentials grant.
//
// This example demonstrates service-to-service authentication where
// no user interaction is needed. The token is automatically cached
// and refreshed before expiry.
//
// Usage:
//
//	export SIGNET_URL=https://auth.example.com
//	export CLIENT_ID=your-client-id
//	export CLIENT_SECRET=your-client-secret
//	go run main.go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-signet/sdk-go/clientcreds"
	"github.com/go-signet/sdk-go/discovery"
	"github.com/go-signet/sdk-go/oauth"
	"github.com/joho/godotenv"
)

type config struct {
	signetURL, clientID, clientSecret string
	resources                         []string
	apiURL                            string
}

func main() {
	_ = godotenv.Load()
	cfg := config{
		signetURL:    os.Getenv("SIGNET_URL"),
		clientID:     os.Getenv("CLIENT_ID"),
		clientSecret: os.Getenv("CLIENT_SECRET"),
		resources:    strings.Fields(os.Getenv("RESOURCES")),
		apiURL:       strings.TrimSpace(os.Getenv("API_URL")),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := run(ctx, cfg, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, cfg config, out io.Writer) error {
	if cfg.signetURL == "" || cfg.clientID == "" || cfg.clientSecret == "" {
		return fmt.Errorf("set SIGNET_URL, CLIENT_ID, and CLIENT_SECRET")
	}
	if len(cfg.resources) > 0 && cfg.apiURL == "" {
		return fmt.Errorf("set API_URL when requesting RESOURCES")
	}

	// 1. Auto-discover endpoints
	disco, err := discovery.NewClient(cfg.signetURL)
	if err != nil {
		return err
	}
	meta, err := disco.Fetch(ctx)
	if err != nil {
		return err
	}

	// 2. Create OAuth client
	endpoints := meta.Endpoints()
	client, err := oauth.NewClient(cfg.clientID, endpoints,
		oauth.WithClientSecret(cfg.clientSecret),
	)
	if err != nil {
		return err
	}

	// 3. Create auto-refreshing token source
	ts := clientcreds.NewTokenSource(client,
		clientcreds.WithScopes("profile", "email"),
		clientcreds.WithResources(cfg.resources...),
		clientcreds.WithExpiryDelta(30*time.Second),
	)

	// 4. Call the target API. A resource identifier is an audience, not
	// necessarily the URL of an HTTP endpoint, so configure API_URL separately.
	targetURL := cfg.apiURL
	if targetURL == "" {
		targetURL = endpoints.UserinfoURL
	}
	if targetURL == "" {
		return fmt.Errorf("set API_URL or use an issuer advertising userinfo_endpoint")
	}
	httpClient := ts.HTTPClient()
	// The token transport attaches a credential to every request. Do not let
	// an API redirect send the resource-targeted token to a different endpoint.
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	const maxBodySize = 1 << 20 // 1 MB
	lr := io.LimitReader(resp.Body, maxBodySize+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	truncated := len(body) > maxBodySize
	if truncated {
		body = body[:maxBodySize]
	}
	fmt.Fprintf(out, "Status: %d\nBody: %s\n", resp.StatusCode, body)
	if truncated {
		fmt.Fprintln(out, "(response body truncated to 1 MB)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}
	return nil
}
