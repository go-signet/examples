// CLI example with auto-detection of browser availability.
//
// If a browser is available (local machine), it uses Authorization Code + PKCE.
// If not (SSH session), it falls back to Device Code flow.
// Tokens are persisted to OS keyring (with file fallback) for reuse.
//
// Usage:
//
//	export SIGNET_URL=https://auth.example.com
//	export CLIENT_ID=your-client-id
//	go run main.go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/go-signet/sdk-go"
	"github.com/go-signet/sdk-go/oauth"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	signetURL := os.Getenv("SIGNET_URL")
	clientID := os.Getenv("CLIENT_ID")
	if signetURL == "" || clientID == "" {
		log.Fatal("Set SIGNET_URL and CLIENT_ID")
	}

	ctx := context.Background()
	client, token, err := signet.New(ctx,
		signetURL,
		clientID,
		signet.WithScopes("profile", "email"),
		signet.WithResources(strings.Fields(os.Getenv("RESOURCES"))...),
	)
	if err != nil {
		log.Fatal(err)
	}
	printTokenInfo(ctx, os.Stdout, client, token)
}

func maskToken(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "****"
	}
	return s[:8] + "..."
}

func printTokenInfo(ctx context.Context, out io.Writer, client *oauth.Client, token *oauth.Token) {
	// UserInfo is best-effort: a transient failure here (5xx, timeout) must
	// not suppress the token and introspection details this command exists
	// to print, so report it and keep going rather than returning early.
	if info, err := client.UserInfo(ctx, token.AccessToken); err != nil {
		fmt.Fprintf(out, "UserInfo error: %v\n", err)
	} else {
		fmt.Fprintf(out, "User: %s (%s)\n", info.Name, info.Email)
		fmt.Fprintf(out, "Subject: %s\n", info.Sub)
	}

	fmt.Fprintf(out, "Access Token: %s\n", maskToken(token.AccessToken))
	fmt.Fprintf(out, "Refresh Token: %s\n", maskToken(token.RefreshToken))
	fmt.Fprintf(out, "Token Type: %s\n", token.TokenType)
	fmt.Fprintf(out, "Expires In: %d\n", token.ExpiresIn)
	fmt.Fprintf(out, "Expires At: %s\n", token.ExpiresAt)
	fmt.Fprintf(out, "Scope: %s\n", token.Scope)
	fmt.Fprintf(out, "ID Token: %s\n", maskToken(token.IDToken))

	// Fetch token info for detailed scope and metadata
	tokenInfo, err := client.TokenInfoRequest(ctx, token.AccessToken)
	if err != nil {
		fmt.Fprintf(out, "TokenInfo error: %v\n", err)
		return
	}
	fmt.Fprintf(out, "TokenInfo Active: %v\n", tokenInfo.Active)
	fmt.Fprintf(out, "TokenInfo UserID: %s\n", tokenInfo.UserID)
	fmt.Fprintf(out, "TokenInfo ClientID: %s\n", tokenInfo.ClientID)
	fmt.Fprintf(out, "TokenInfo Scope: %s\n", tokenInfo.Scope)
	fmt.Fprintf(out, "TokenInfo SubjectType: %s\n", tokenInfo.SubjectType)
	fmt.Fprintf(out, "TokenInfo Issuer: %s\n", tokenInfo.Iss)
	fmt.Fprintf(out, "TokenInfo Exp: %d\n", tokenInfo.Exp)
	fmt.Fprintf(out, "TokenInfo Audience: %v\n", tokenInfo.Audience)
}
