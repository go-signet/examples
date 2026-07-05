package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	retry "github.com/appleboy/go-httpretry"
)

// UserInfo holds the claims returned by GET /oauth/userinfo.
//
// The server always emits "sub" and "iss".
// Profile claims (name, preferred_username, picture, updated_at) are included
// when the token carries the "profile" scope.
// Email claims (email, email_verified) are included with the "email" scope.
type UserInfo struct {
	Sub    string `json:"sub"`
	Issuer string `json:"iss"`

	// profile scope
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Picture           string `json:"picture,omitempty"`
	// UpdatedAt is seconds since Unix epoch per OIDC Core §5.1.
	UpdatedAt int64 `json:"updated_at,omitempty"`

	// email scope
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}

// fetchUserInfo calls GET /oauth/userinfo with a Bearer token and returns the
// parsed claims per OIDC Core §5.3.
func fetchUserInfo(ctx context.Context, cfg *AppConfig, accessToken string) (*UserInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.UserInfoTimeout)
	defer cancel()

	resp, err := cfg.RetryClient.Get(ctx, cfg.Endpoints.UserinfoURL,
		retry.WithHeader("Authorization", "Bearer "+accessToken),
		retry.WithHeader("Accept", "application/json"),
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
		return nil, formatHTTPError(body, resp.StatusCode)
	}

	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse UserInfo response: %w", err)
	}
	if info.Sub == "" {
		return nil, errors.New("UserInfo response missing required 'sub' claim")
	}
	return &info, nil
}

// formatUserInfo returns a human-readable summary of UserInfo claims.
func formatUserInfo(info *UserInfo) string {
	var sb strings.Builder

	write := func(label, value string) {
		if value != "" {
			fmt.Fprintf(&sb, "  %-22s %s\n", label+":", value)
		}
	}

	write("Subject (sub)", info.Sub)
	write("Issuer (iss)", info.Issuer)
	write("Name", info.Name)
	write("Preferred username", info.PreferredUsername)
	write("Picture", info.Picture)
	if info.UpdatedAt != 0 {
		write("Updated at", time.Unix(info.UpdatedAt, 0).UTC().Format(time.RFC3339))
	}
	write("Email", info.Email)
	if info.EmailVerified != nil {
		write("Email verified", strconv.FormatBool(*info.EmailVerified))
	}

	return strings.TrimRight(sb.String(), "\n")
}
