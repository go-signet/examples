package main

import (
	"testing"
	"time"

	"github.com/go-signet/examples/go-tui/tui"
	"github.com/go-signet/sdk-go/credstore"
)

func TestToTUITokenStorage(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)

	tests := []struct {
		name           string
		token          *credstore.Token
		flow           string
		storageBackend string
		wantNil        bool
		wantFlow       string
	}{
		{
			name:    "nil token returns nil",
			token:   nil,
			flow:    "browser",
			wantNil: true,
		},
		{
			name: "converts all fields",
			token: &credstore.Token{
				AccessToken:  "acc",
				RefreshToken: "ref",
				TokenType:    "Bearer",
				ExpiresAt:    expiry,
				ClientID:     "client-1",
			},
			flow:           "browser",
			storageBackend: "keyring: signet-cli",
			wantFlow:       "browser",
		},
		{
			name: "empty flow is preserved",
			token: &credstore.Token{
				AccessToken: "acc",
				ClientID:    "client-2",
			},
			flow:           "",
			storageBackend: "file: .signet-tokens.json",
			wantFlow:       "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toTUITokenStorage(tc.token, tc.flow, tc.storageBackend)
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			if got.AccessToken != tc.token.AccessToken {
				t.Errorf("AccessToken = %q, want %q", got.AccessToken, tc.token.AccessToken)
			}
			if got.RefreshToken != tc.token.RefreshToken {
				t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, tc.token.RefreshToken)
			}
			if got.TokenType != tc.token.TokenType {
				t.Errorf("TokenType = %q, want %q", got.TokenType, tc.token.TokenType)
			}
			if !got.ExpiresAt.Equal(tc.token.ExpiresAt) {
				t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, tc.token.ExpiresAt)
			}
			if got.ClientID != tc.token.ClientID {
				t.Errorf("ClientID = %q, want %q", got.ClientID, tc.token.ClientID)
			}
			if got.Flow != tc.wantFlow {
				t.Errorf("Flow = %q, want %q", got.Flow, tc.wantFlow)
			}
			if got.StorageBackend != tc.storageBackend {
				t.Errorf("StorageBackend = %q, want %q", got.StorageBackend, tc.storageBackend)
			}
		})
	}
}

func TestFromTUITokenStorage(t *testing.T) {
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)

	tests := []struct {
		name    string
		storage *tui.TokenStorage
		wantNil bool
	}{
		{
			name:    "nil storage returns nil",
			storage: nil,
			wantNil: true,
		},
		{
			name: "converts all fields",
			storage: &tui.TokenStorage{
				AccessToken:  "acc",
				RefreshToken: "ref",
				TokenType:    "Bearer",
				ExpiresAt:    expiry,
				ClientID:     "client-1",
				Flow:         "device",
			},
		},
		{
			name: "flow field is not copied",
			storage: &tui.TokenStorage{
				AccessToken: "acc",
				ClientID:    "client-2",
				Flow:        "browser",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fromTUITokenStorage(tc.storage)
			if tc.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			if got.AccessToken != tc.storage.AccessToken {
				t.Errorf("AccessToken = %q, want %q", got.AccessToken, tc.storage.AccessToken)
			}
			if got.RefreshToken != tc.storage.RefreshToken {
				t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, tc.storage.RefreshToken)
			}
			if got.TokenType != tc.storage.TokenType {
				t.Errorf("TokenType = %q, want %q", got.TokenType, tc.storage.TokenType)
			}
			if !got.ExpiresAt.Equal(tc.storage.ExpiresAt) {
				t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, tc.storage.ExpiresAt)
			}
			if got.ClientID != tc.storage.ClientID {
				t.Errorf("ClientID = %q, want %q", got.ClientID, tc.storage.ClientID)
			}
		})
	}
}

func TestFlowFromTUI(t *testing.T) {
	tests := []struct {
		name string
		ts   *tui.TokenStorage
		want string
	}{
		{"nil returns empty string", nil, ""},
		{"returns flow field", &tui.TokenStorage{Flow: "browser"}, "browser"},
		{"empty flow", &tui.TokenStorage{Flow: ""}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := flowFromTUI(tc.ts); got != tc.want {
				t.Errorf("flowFromTUI() = %q, want %q", got, tc.want)
			}
		})
	}
}
