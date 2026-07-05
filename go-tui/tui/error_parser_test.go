package tui

import (
	"errors"
	"strings"
	"testing"
)

func TestParseError(t *testing.T) {
	tests := []struct {
		name                    string
		input                   error
		expectedCode            string
		expectedFriendlyMessage string
		shouldDeduplicate       bool
	}{
		{
			name:                    "simple unauthorized_client error from callback",
			input:                   errors.New("unauthorized_client: Client is not authorized"),
			expectedCode:            "unauthorized_client",
			expectedFriendlyMessage: "The client is not authorized to use this authorization method. Please verify your client ID and permissions.",
			shouldDeduplicate:       false,
		},
		{
			name:                    "unauthorized_client with repetition",
			input:                   errors.New("unauthorized_client: unauthorized_client"),
			expectedCode:            "unauthorized_client",
			expectedFriendlyMessage: "The client is not authorized to use this authorization method. Please verify your client ID and permissions.",
			shouldDeduplicate:       true,
		},
		{
			name: "nested authentication failed error",
			input: errors.New(
				"authentication failed: authentication failed: token_exchange_failed: unauthorized_client: unauthorized_client",
			),
			expectedCode:            "unauthorized_client",
			expectedFriendlyMessage: "The client is not authorized to use this authorization method. Please verify your client ID and permissions.",
			shouldDeduplicate:       true,
		},
		{
			name: "actual browser flow error format",
			input: errors.New(
				"token_exchange_failed: unauthorized_client: Client is not authorized",
			),
			expectedCode:            "unauthorized_client",
			expectedFriendlyMessage: "The client is not authorized to use this authorization method. Please verify your client ID and permissions.",
			shouldDeduplicate:       false,
		},
		{
			name: "access_denied error",
			input: errors.New(
				"authentication failed: access_denied: user denied authorization",
			),
			expectedCode:            "access_denied",
			expectedFriendlyMessage: "Authorization was denied. You may have cancelled the request or don't have permission to access this resource.",
			shouldDeduplicate:       false,
		},
		{
			name: "invalid_grant error",
			input: errors.New(
				"token exchange failed: invalid_grant: authorization code expired",
			),
			expectedCode:            "invalid_grant",
			expectedFriendlyMessage: "The authorization code or refresh token is invalid or expired.",
			shouldDeduplicate:       false,
		},
		{
			name: "server_error",
			input: errors.New(
				"request failed: server_error: internal server error",
			),
			expectedCode:            "server_error",
			expectedFriendlyMessage: "The authorization server encountered an error. Please try again later.",
			shouldDeduplicate:       false,
		},
		{
			name:                    "no oauth error code",
			input:                   errors.New("network connection failed"),
			expectedCode:            "",
			expectedFriendlyMessage: "Network connection failed",
			shouldDeduplicate:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := parseError(tt.input)

			if parsed == nil {
				t.Fatal("expected parsed error, got nil")
			}

			if parsed.ErrorCode != tt.expectedCode {
				t.Errorf("expected error code %q, got %q", tt.expectedCode, parsed.ErrorCode)
			}

			if parsed.UserFriendlyMessage != tt.expectedFriendlyMessage {
				t.Errorf(
					"expected friendly message %q, got %q",
					tt.expectedFriendlyMessage,
					parsed.UserFriendlyMessage,
				)
			}

			if tt.shouldDeduplicate {
				// Check that duplicates were removed
				original := tt.input.Error()
				if parsed.Details == original {
					t.Errorf(
						"expected deduplication, but details match original: %q",
						parsed.Details,
					)
				}
			}
		})
	}
}

func TestGetErrorRecommendations(t *testing.T) {
	tests := []struct {
		name          string
		input         error
		expectedCount int
		shouldContain string
	}{
		{
			name:          "unauthorized_client recommendations",
			input:         errors.New("authentication failed: unauthorized_client"),
			expectedCount: 4,
			shouldContain: "client ID",
		},
		{
			name:          "access_denied recommendations",
			input:         errors.New("access_denied: user denied"),
			expectedCount: 3,
			shouldContain: "Deny",
		},
		{
			name:          "network error recommendations",
			input:         errors.New("connection refused"),
			expectedCount: 4,
			shouldContain: "internet connection",
		},
		{
			name:          "timeout recommendations",
			input:         errors.New("context deadline exceeded"),
			expectedCount: 3,
			shouldContain: "slow to respond",
		},
		{
			name:          "browser error recommendations",
			input:         errors.New("failed to open browser"),
			expectedCount: 3,
			shouldContain: "device flow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := parseError(tt.input)
			recs := getErrorRecommendations(parsed)

			if len(recs) != tt.expectedCount {
				t.Errorf("expected %d recommendations, got %d", tt.expectedCount, len(recs))
			}

			found := false
			for _, rec := range recs {
				if strings.Contains(strings.ToLower(rec), strings.ToLower(tt.shouldContain)) {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("expected recommendations to contain %q, but didn't find it in: %v",
					tt.shouldContain, recs)
			}
		})
	}
}

func TestExtractCleanMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "removes authentication failed prefix",
			input:    "authentication failed: invalid credentials",
			expected: "Invalid credentials",
		},
		{
			name:     "removes token exchange failed prefix",
			input:    "token exchange failed: server error",
			expected: "Server error",
		},
		{
			name:     "removes multiple prefixes",
			input:    "authentication failed: token exchange failed: connection refused",
			expected: "Connection refused",
		},
		{
			name:     "capitalizes first letter",
			input:    "connection timeout",
			expected: "Connection timeout",
		},
		{
			name:     "handles already clean message",
			input:    "Invalid request",
			expected: "Invalid request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCleanMessage(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
