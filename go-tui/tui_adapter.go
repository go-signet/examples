package main

import (
	"github.com/go-signet/examples/go-tui/tui"
	"github.com/go-signet/sdk-go/credstore"
)

// toTUITokenStorage converts credstore.Token to tui.TokenStorage.
func toTUITokenStorage(token *credstore.Token, flow, storageBackend string) *tui.TokenStorage {
	if token == nil {
		return nil
	}
	return &tui.TokenStorage{
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
		TokenType:      token.TokenType,
		ExpiresAt:      token.ExpiresAt,
		ClientID:       token.ClientID,
		Flow:           flow,
		StorageBackend: storageBackend,
	}
}

// flowFromTUI extracts the Flow field from tui.TokenStorage (nil-safe).
func flowFromTUI(ts *tui.TokenStorage) string {
	if ts == nil {
		return ""
	}
	return ts.Flow
}

// fromTUITokenStorage converts tui.TokenStorage to credstore.Token.
func fromTUITokenStorage(tuiStorage *tui.TokenStorage) *credstore.Token {
	if tuiStorage == nil {
		return nil
	}
	return &credstore.Token{
		AccessToken:  tuiStorage.AccessToken,
		RefreshToken: tuiStorage.RefreshToken,
		TokenType:    tuiStorage.TokenType,
		ExpiresAt:    tuiStorage.ExpiresAt,
		ClientID:     tuiStorage.ClientID,
	}
}
