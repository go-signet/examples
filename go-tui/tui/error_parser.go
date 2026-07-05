package tui

import (
	"slices"
	"strings"
)

// ParsedError represents a parsed OAuth error with its components.
type ParsedError struct {
	// Raw is the original error message
	Raw string
	// ErrorCode is the OAuth error code (e.g., "unauthorized_client", "access_denied")
	ErrorCode string
	// ErrorDescription is the error description from the OAuth response
	ErrorDescription string
	// UserFriendlyMessage is a sanitized, user-friendly message
	UserFriendlyMessage string
	// Details contains additional context (e.g., original error chain)
	Details string
}

// OAuth error codes that we can sanitize
var oauthErrorCodes = []string{
	"access_denied",
	"invalid_request",
	"unauthorized_client",
	"unsupported_response_type",
	"invalid_scope",
	"server_error",
	"temporarily_unavailable",
	"invalid_client",
	"invalid_grant",
	"unsupported_grant_type",
}

// parseError parses an error message and extracts OAuth error information.
func parseError(err error) *ParsedError {
	if err == nil {
		return nil
	}

	errMsg := err.Error()
	parsed := &ParsedError{
		Raw: errMsg,
	}

	// Try to extract OAuth error code (prioritize earlier occurrences)
	for _, code := range oauthErrorCodes {
		if strings.Contains(errMsg, code) {
			parsed.ErrorCode = code
			break
		}
	}

	// Extract error description if present
	// Format: "error_code: description" or "prefix: error_code: description"
	if parsed.ErrorCode != "" {
		// Find the part after the error code
		parts := strings.SplitN(errMsg, parsed.ErrorCode, 2)
		if len(parts) == 2 {
			desc := strings.TrimPrefix(parts[1], ": ")
			desc = strings.TrimSpace(desc)
			// Only use it if it's not another error code or generic text
			if desc != "" && !isErrorCode(desc) && desc != parsed.ErrorCode {
				parsed.ErrorDescription = desc
			}
		}
	}

	// Deduplicate repeated error messages
	// e.g., "authentication failed: authentication failed: ..." -> "authentication failed: ..."
	parts := strings.Split(errMsg, ": ")
	uniqueParts := make([]string, 0, len(parts))
	seen := make(map[string]bool)

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && !seen[part] {
			uniqueParts = append(uniqueParts, part)
			seen[part] = true
		}
	}

	deduped := strings.Join(uniqueParts, ": ")
	parsed.Details = deduped

	// Generate user-friendly message
	if parsed.ErrorCode != "" {
		parsed.UserFriendlyMessage = sanitizeOAuthErrorForTUI(
			parsed.ErrorCode,
			parsed.ErrorDescription,
		)
	} else {
		// Extract a clean message without technical prefixes
		parsed.UserFriendlyMessage = extractCleanMessage(deduped)
	}

	return parsed
}

// isErrorCode checks if a string is one of our known error codes
func isErrorCode(s string) bool {
	return slices.Contains(oauthErrorCodes, s)
}

// oauthErrorMessages maps standard OAuth error codes to user-friendly TUI messages.
// This is the authoritative map; other packages should delegate here via OAuthErrorMessage.
var oauthErrorMessages = map[string]string{
	"access_denied":             "Authorization was denied. You may have cancelled the request or don't have permission to access this resource.",
	"invalid_request":           "The authorization request was invalid. Please check your configuration.",
	"unauthorized_client":       "The client is not authorized to use this authorization method. Please verify your client ID and permissions.",
	"unsupported_response_type": "The server does not support the requested response type. Please check your configuration.",
	"invalid_client":            "Client authentication failed. Please check your client ID and secret.",
	"invalid_grant":             "The authorization code or refresh token is invalid or expired.",
	"unsupported_grant_type":    "The authorization grant type is not supported by this server.",
	"invalid_scope":             "One or more requested scopes are invalid or not allowed.",
	"server_error":              "The authorization server encountered an error. Please try again later.",
	"temporarily_unavailable":   "The authorization server is temporarily unavailable. Please try again in a few moments.",
}

// OAuthErrorMessage returns the user-friendly TUI message for a given OAuth error code.
func OAuthErrorMessage(code string) (string, bool) {
	msg, ok := oauthErrorMessages[code]
	return msg, ok
}

// sanitizeOAuthErrorForTUI converts OAuth error codes to user-friendly messages.
func sanitizeOAuthErrorForTUI(errorCode, errorDescription string) string {
	if msg, ok := oauthErrorMessages[errorCode]; ok {
		return msg
	}
	if errorDescription != "" {
		return errorDescription
	}
	return "Authentication failed. Please check your configuration and try again."
}

// extractCleanMessage extracts a clean, user-facing message from an error chain.
func extractCleanMessage(errMsg string) string {
	// Remove common technical prefixes (case-insensitive)
	prefixes := []string{
		"authentication failed: ",
		"token exchange failed: ",
		"token poll failed: ",
		"request failed: ",
		"failed to ",
	}

	cleaned := errMsg
	for _, prefix := range prefixes {
		if len(cleaned) >= len(prefix) && strings.EqualFold(cleaned[:len(prefix)], prefix) {
			cleaned = cleaned[len(prefix):]
		}
	}

	// Capitalize first letter
	if len(cleaned) > 0 {
		cleaned = strings.ToUpper(string(cleaned[0])) + cleaned[1:]
	}

	return cleaned
}

// getErrorRecommendations returns context-specific recommendations based on the parsed error.
func getErrorRecommendations(parsed *ParsedError) []string {
	if parsed == nil {
		return nil
	}

	errMsg := strings.ToLower(parsed.Raw)

	// Network errors
	if strings.Contains(errMsg, "connection refused") ||
		strings.Contains(errMsg, "no such host") ||
		strings.Contains(errMsg, "network") {
		return []string{
			"Check your internet connection",
			"Verify the server URL is correct",
			"Check if the authorization server is running",
			"Try disabling VPN or proxy if enabled",
		}
	}

	// Timeout errors
	if strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "deadline exceeded") {
		return []string{
			"Check your internet connection speed",
			"The server might be slow to respond - try again",
			"If using VPN, try disabling it temporarily",
		}
	}

	// OAuth-specific recommendations
	switch parsed.ErrorCode {
	case "unauthorized_client":
		return []string{
			"Verify your client ID is correct and registered with the server",
			"Ensure the client is authorized for this grant type",
			"Check that the redirect URI matches the one registered",
			"Contact your administrator to verify client permissions",
		}

	case "access_denied":
		return []string{
			"You may have clicked 'Deny' on the authorization page",
			"Your account may not have permission to access this resource",
			"Try authenticating again and click 'Allow' when prompted",
		}

	case "invalid_grant", "invalid_client":
		return []string{
			"Verify your client ID and secret (if applicable) are correct",
			"The authorization code may have expired - try again",
			"Clear any cached credentials and retry",
		}

	case "invalid_scope":
		return []string{
			"One or more requested permissions (scopes) are not available",
			"Check your scope configuration",
			"Contact your administrator to verify allowed scopes",
		}

	case "server_error", "temporarily_unavailable":
		return []string{
			"The authorization server is experiencing issues",
			"Wait a few moments and try again",
			"If the problem persists, contact your administrator",
		}
	}

	// Browser errors
	if strings.Contains(errMsg, "browser") ||
		strings.Contains(errMsg, "failed to open") {
		return []string{
			"Ensure a web browser is installed and accessible",
			"Try running in a different environment (desktop vs SSH)",
			"Use device flow with --device flag as an alternative",
		}
	}

	// Generic token errors
	if strings.Contains(errMsg, "token") && parsed.ErrorCode == "" {
		return []string{
			"The token exchange failed - try authenticating again",
			"Verify your client credentials are correct",
			"Check if your authorization code expired",
		}
	}

	// Default recommendations
	return []string{
		"Try authenticating again from the beginning",
		"Verify all configuration values are correct",
		"Check the error details below for more information",
		"Contact your administrator if the problem persists",
	}
}
