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
	"os"
	"time"

	"github.com/go-signet/sdk-go/clientcreds"
	"github.com/go-signet/sdk-go/discovery"
	"github.com/go-signet/sdk-go/oauth"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	signetURL := os.Getenv("SIGNET_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	if signetURL == "" || clientID == "" || clientSecret == "" {
		log.Fatal("Set SIGNET_URL, CLIENT_ID, and CLIENT_SECRET")
	}

	ctx := context.Background()

	// 1. Auto-discover endpoints
	disco, err := discovery.NewClient(signetURL)
	if err != nil {
		log.Fatal(err)
	}
	meta, err := disco.Fetch(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Create OAuth client
	endpoints := meta.Endpoints()
	client, err := oauth.NewClient(clientID, endpoints,
		oauth.WithClientSecret(clientSecret),
	)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Create auto-refreshing token source
	ts := clientcreds.NewTokenSource(client,
		clientcreds.WithScopes("profile", "email"),
		clientcreds.WithExpiryDelta(30*time.Second),
	)

	// 4. Use the auto-authenticated HTTP client against the userinfo endpoint
	// the issuer advertised in discovery. Don't hardcode the path: that breaks
	// on a trailing slash in SIGNET_URL (https://host//oauth/userinfo) and
	// on any issuer whose userinfo endpoint isn't at <base>/oauth/userinfo.
	if endpoints.UserinfoURL == "" {
		log.Fatal("Signet discovery did not advertise a userinfo_endpoint")
	}
	httpClient := ts.HTTPClient()
	resp, err := httpClient.Get(endpoints.UserinfoURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	const maxBodySize = 1 << 20 // 1 MB
	lr := io.LimitReader(resp.Body, maxBodySize+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	truncated := len(body) > maxBodySize
	if truncated {
		body = body[:maxBodySize]
	}
	fmt.Printf("Status: %d\nBody: %s\n", resp.StatusCode, body)
	if truncated {
		fmt.Println("(response body truncated to 1 MB)")
	}
}
