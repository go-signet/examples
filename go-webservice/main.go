// Web Service example using Bearer token middleware.
//
// This example demonstrates how to protect API endpoints with
// Bearer token validation. Works with any Go HTTP framework.
//
// Usage:
//
//	export SIGNET_URL=https://auth.example.com
//	export CLIENT_ID=your-client-id
//	go run main.go
//
// Test:
//
//	curl -H "Authorization: Bearer <token>" http://localhost:8080/api/profile
//	curl -H "Authorization: Bearer <token>" http://localhost:8080/api/data
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-signet/sdk-go/discovery"
	"github.com/go-signet/sdk-go/middleware"
	"github.com/go-signet/sdk-go/oauth"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	signetURL := os.Getenv("SIGNET_URL")
	clientID := os.Getenv("CLIENT_ID")

	if signetURL == "" || clientID == "" {
		log.Fatal("Set SIGNET_URL, CLIENT_ID")
	}

	// 1. Auto-discover endpoints
	disco, err := discovery.NewClient(signetURL)
	if err != nil {
		log.Fatal(err)
	}
	meta, err := disco.Fetch(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// 2. Create OAuth client for token validation
	oauthClient, err := oauth.NewClient(clientID, meta.Endpoints())
	if err != nil {
		log.Fatal(err)
	}

	// 3. Create middleware
	auth := middleware.BearerAuth(
		middleware.WithOAuthClient(oauthClient),
	)

	authWithScope := middleware.BearerAuth(
		middleware.WithOAuthClient(oauthClient),
		middleware.WithRequiredScopes("read"),
	)

	// 4. Register routes
	mux := http.NewServeMux()
	mux.Handle("/api/profile", auth(http.HandlerFunc(profileHandler)))
	mux.Handle("/api/data", authWithScope(http.HandlerFunc(dataHandler)))
	mux.HandleFunc("/health", healthHandler)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Bound the Authorization header well below Go's 1 MiB default —
		// real access tokens are <2 KiB, so there's no reason to read an
		// oversized header before forwarding the token to introspection.
		MaxHeaderBytes: 8 << 10,
	}
	log.Println("Listening on :8080")
	log.Fatal(srv.ListenAndServe())
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := middleware.TokenInfoFromContext(r.Context())
	if !ok {
		// BearerAuth always populates TokenInfo before invoking the handler,
		// so a miss means the middleware was not applied — a server
		// misconfiguration, not a client auth failure. Report it as 5xx.
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"user_id":      info.UserID,
		"client_id":    info.ClientID,
		"scope":        info.Scope,
		"subject_type": info.SubjectType,
	})
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := middleware.TokenInfoFromContext(r.Context())
	if !ok {
		// BearerAuth always populates TokenInfo before invoking the handler,
		// so a miss means the middleware was not applied — a server
		// misconfiguration, not a client auth failure. Report it as 5xx.
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Additional scope check within handler
	msg := "You have read-only access"
	if middleware.HasScope(r.Context(), "write") {
		msg = "You have read+write access"
	}

	writeJSON(w, map[string]string{
		"message": msg,
		"user":    info.UserID,
	})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

// writeJSON sets the JSON content type and encodes v as the response body.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
