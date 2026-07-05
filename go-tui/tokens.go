package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"github.com/go-signet/sdk-go/credstore"
)

// tokenResponse holds the standard OAuth 2.0 token endpoint response (RFC 6749 §5.1).
// Shared by browser flow (authorization code exchange), device flow, and token refresh.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// ErrorResponse is an OAuth error payload.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// parseOAuthError attempts to unmarshal an OAuth error response from raw JSON.
// Returns the parsed response and true if successful, or a zero value and false
// if the body is not a valid OAuth error (missing "error" field).
func parseOAuthError(body []byte) (ErrorResponse, bool) {
	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil || errResp.Error == "" {
		return ErrorResponse{}, false
	}
	return errResp, true
}

// readResponseBody reads the response body with a size limit to guard against oversized responses.
func readResponseBody(resp *http.Response, maxSize int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, nil
}

// formatHTTPError attempts to parse an OAuth error response from body,
// falling back to a generic status+body error message.
func formatHTTPError(body []byte, statusCode int) error {
	if errResp, ok := parseOAuthError(body); ok {
		desc := strings.TrimSpace(errResp.ErrorDescription)
		if desc != "" {
			return fmt.Errorf("%s: %s", errResp.Error, desc)
		}
		return errors.New(errResp.Error)
	}
	return fmt.Errorf("server returned status %d: %s", statusCode, string(body))
}

// ErrRefreshTokenExpired indicates the refresh token has expired or is invalid.
var ErrRefreshTokenExpired = errors.New("refresh token expired or invalid")

// ErrNoRefreshToken indicates no refresh token is stored, so the access token
// cannot be refreshed and re-authentication is required. Kept distinct from
// ErrRefreshTokenExpired so diagnostics don't imply a token was present.
var ErrNoRefreshToken = errors.New("no refresh token available")

// doTokenExchange performs a standard OAuth 2.0 token POST and returns the
// parsed tokenResponse on success. On non-200 responses it returns a formatted
// error including the OAuth error code/description when available.
// The optional errHook is called with the parsed ErrorResponse before the
// default error formatting, allowing callers to handle specific error codes
// (e.g., invalid_grant → ErrRefreshTokenExpired). If errHook returns a
// non-nil error, that error is returned directly.
func doTokenExchange(
	ctx context.Context,
	cfg *AppConfig,
	tokenURL string,
	data url.Values,
	errHook func(errResp ErrorResponse, body []byte) error,
) (*tokenResponse, error) {
	resp, err := cfg.RetryClient.Post(ctx, tokenURL,
		retry.WithBody("application/x-www-form-urlencoded", strings.NewReader(data.Encode())),
	)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBody(resp, cfg.MaxResponseBodySize)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if errResp, ok := parseOAuthError(body); ok {
			if errHook != nil {
				if hookErr := errHook(errResp, body); hookErr != nil {
					return nil, hookErr
				}
			}
		}
		return nil, formatHTTPError(body, resp.StatusCode)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if err := validateTokenResponse(
		tokenResp.AccessToken,
		tokenResp.TokenType,
		tokenResp.ExpiresIn,
	); err != nil {
		return nil, fmt.Errorf("invalid token response: %w", err)
	}

	return &tokenResp, nil
}

// expiryFromNow returns the absolute expiry time for a token that the server
// says expires in expiresIn seconds from now.
func expiryFromNow(expiresIn int) time.Time {
	return time.Now().Add(time.Duration(expiresIn) * time.Second)
}

// setClientSecret adds the client_secret form parameter for confidential
// clients. Public (PKCE) clients omit it.
func (c *AppConfig) setClientSecret(data url.Values) {
	if !c.IsPublicClient() {
		data.Set("client_secret", c.ClientSecret)
	}
}

// setExtraClaims adds the extra_claims form parameter when configured.
func (c *AppConfig) setExtraClaims(data url.Values) {
	if c.ExtraClaims != "" {
		data.Set(extraClaimsFormKey, c.ExtraClaims)
	}
}

// tokenResponseToCredstore converts a tokenResponse to a credstore.Token.
func tokenResponseToCredstore(cfg *AppConfig, tr *tokenResponse) *credstore.Token {
	return &credstore.Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		ExpiresAt:    expiryFromNow(tr.ExpiresIn),
		ClientID:     cfg.ClientID,
	}
}

// validateTokenResponse performs basic sanity checks on a token response.
func validateTokenResponse(accessToken, tokenType string, expiresIn int) error {
	if accessToken == "" {
		return errors.New("access_token is empty")
	}
	if len(accessToken) < 10 {
		return fmt.Errorf("access_token is too short (length: %d)", len(accessToken))
	}
	if expiresIn <= 0 {
		return fmt.Errorf("expires_in must be positive, got: %d", expiresIn)
	}
	if tokenType != "" && tokenType != "Bearer" {
		return fmt.Errorf("unexpected token_type: %s (expected Bearer)", tokenType)
	}
	return nil
}
