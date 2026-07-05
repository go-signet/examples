package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"github.com/go-signet/examples/go-tui/tui"
	"github.com/go-signet/sdk-go/credstore"
	"golang.org/x/oauth2"
)

// deviceCodeResponse holds the device authorization response (RFC 8628 §3.2).
type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

const (
	defaultPollInterval = 5                // seconds, RFC 8628 §3.5 recommended minimum
	maxPollInterval     = 60 * time.Second // RFC 8628 §3.5 cap for slow_down backoff
)

// requestDeviceCode requests a device code from the OAuth server.
func requestDeviceCode(ctx context.Context, cfg *AppConfig) (*oauth2.DeviceAuthResponse, error) {
	reqCtx, cancel := context.WithTimeout(ctx, cfg.DeviceCodeRequestTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("client_id", cfg.ClientID)
	data.Set("scope", cfg.Scope)

	resp, err := cfg.RetryClient.Post(reqCtx, cfg.Endpoints.DeviceAuthorizationURL,
		retry.WithBody("application/x-www-form-urlencoded", strings.NewReader(data.Encode())),
	)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBody(resp, cfg.MaxResponseBodySize)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"device code request failed: %w",
			formatHTTPError(body, resp.StatusCode),
		)
	}

	var deviceResp deviceCodeResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse device code response: %w", err)
	}

	return &oauth2.DeviceAuthResponse{
		DeviceCode:              deviceResp.DeviceCode,
		UserCode:                deviceResp.UserCode,
		VerificationURI:         deviceResp.VerificationURI,
		VerificationURIComplete: deviceResp.VerificationURIComplete,
		Expiry:                  expiryFromNow(deviceResp.ExpiresIn),
		Interval:                int64(deviceResp.Interval),
	}, nil
}

// pollErrorAction represents the action to take after handling a poll error.
type pollErrorAction int

const (
	pollContinue pollErrorAction = iota // authorization_pending — keep polling
	pollBackoff                         // slow_down — increase interval and continue
	pollFail                            // terminal error
)

// pollErrorResult holds the outcome of handling a device poll error.
type pollErrorResult struct {
	action pollErrorAction
	err    error
}

// handleDevicePollError parses an error from exchangeDeviceCode and determines
// the appropriate action. For slow_down, it updates the interval and resets the ticker.
func handleDevicePollError(
	err error,
	pollInterval *time.Duration,
	pollTicker *time.Ticker,
) pollErrorResult {
	var oauthErr *oauth2.RetrieveError
	if !errors.As(err, &oauthErr) {
		return pollErrorResult{pollFail, fmt.Errorf("token exchange failed: %w", err)}
	}

	errResp, ok := parseOAuthError(oauthErr.Body)
	if !ok {
		return pollErrorResult{
			pollFail,
			fmt.Errorf("token exchange failed (body: %s): %w", oauthErr.Body, err),
		}
	}

	switch errResp.Error {
	case "authorization_pending":
		return pollErrorResult{action: pollContinue}

	case "slow_down":
		// RFC 8628 §3.5: lengthen the interval on each slow_down. Grow the
		// current interval by 1.5x (capped at maxPollInterval) instead of
		// compounding a separate multiplier, which ballooned the interval
		// super-exponentially (base × 1.5^(1+2+…)) and hit the cap almost
		// immediately.
		*pollInterval = min(*pollInterval*3/2, maxPollInterval)
		pollTicker.Reset(*pollInterval)
		return pollErrorResult{action: pollBackoff}

	case "expired_token":
		return pollErrorResult{pollFail, errors.New("device code expired, please restart the flow")}

	case "access_denied":
		return pollErrorResult{pollFail, errors.New("user denied authorization")}

	default:
		return pollErrorResult{
			pollFail,
			fmt.Errorf("authorization failed: %s - %s", errResp.Error, errResp.ErrorDescription),
		}
	}
}

// exchangeDeviceCode exchanges a device code for an access token.
func exchangeDeviceCode(
	ctx context.Context,
	cfg *AppConfig,
	tokenURL, cID, deviceCode string,
) (*oauth2.Token, error) {
	reqCtx, cancel := context.WithTimeout(ctx, cfg.TokenExchangeTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)
	data.Set("client_id", cID)
	cfg.setExtraClaims(data)

	resp, err := cfg.RetryClient.Post(reqCtx, tokenURL,
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
		return nil, &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
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

	return &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		Expiry:       expiryFromNow(tokenResp.ExpiresIn),
	}, nil
}

// performDeviceFlowWithUpdates runs the OAuth 2.0 Device Authorization Grant
// and sends progress updates through the provided channel.
func performDeviceFlowWithUpdates(
	ctx context.Context,
	cfg *AppConfig,
	updates chan<- tui.FlowUpdate,
) (*tui.TokenStorage, error) {
	config := &oauth2.Config{
		ClientID: cfg.ClientID,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: cfg.Endpoints.DeviceAuthorizationURL,
			TokenURL:      cfg.Endpoints.TokenURL,
		},
		Scopes: strings.Fields(cfg.Scope),
	}

	updates <- tui.FlowUpdate{
		Type:       tui.StepStart,
		Step:       1,
		TotalSteps: 2,
		Message:    "Requesting device code",
	}

	deviceAuth, err := requestDeviceCode(ctx, cfg)
	if err != nil {
		updates <- tui.FlowUpdate{
			Type:    tui.StepError,
			Step:    1,
			Message: err.Error(),
		}
		return nil, err
	}

	updates <- tui.FlowUpdate{
		Type:       tui.DeviceCodeReceived,
		Step:       1,
		TotalSteps: 2,
		Data: map[string]any{
			"user_code":                 deviceAuth.UserCode,
			"verification_uri":          deviceAuth.VerificationURI,
			"verification_uri_complete": deviceAuth.VerificationURIComplete,
		},
	}

	updates <- tui.FlowUpdate{
		Type:       tui.StepStart,
		Step:       2,
		TotalSteps: 2,
		Message:    "Waiting for authorization",
	}

	token, err := pollForTokenWithUpdates(ctx, cfg, config, deviceAuth, updates)
	if err != nil {
		updates <- tui.FlowUpdate{
			Type:    tui.StepError,
			Step:    2,
			Message: fmt.Sprintf("Authorization failed: %v", err),
		}
		return nil, fmt.Errorf("token poll failed: %w", err)
	}

	updates <- tui.FlowUpdate{
		Type:       tui.StepComplete,
		Step:       2,
		TotalSteps: 2,
	}

	storage := &credstore.Token{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.Type(),
		ExpiresAt:    token.Expiry,
		ClientID:     cfg.ClientID,
	}

	if err := cfg.Store.Save(cfg.ClientID, *storage); err != nil {
		updates <- tui.FlowUpdate{
			Type:    tui.StepError,
			Message: fmt.Sprintf("Warning: Failed to save tokens: %v", err),
		}
	}

	return toTUITokenStorage(storage, "device", cfg.Store.String()), nil
}

// pollForTokenWithUpdates polls for a token while sending progress updates.
// Implements exponential backoff for slow_down errors per RFC 8628.
func pollForTokenWithUpdates(
	ctx context.Context,
	cfg *AppConfig,
	config *oauth2.Config,
	deviceAuth *oauth2.DeviceAuthResponse,
	updates chan<- tui.FlowUpdate,
) (*oauth2.Token, error) {
	// Clamp non-positive server intervals (a missing, zero, or malicious
	// negative value) to the RFC 8628 default — time.NewTicker panics on <= 0.
	interval := deviceAuth.Interval
	if interval <= 0 {
		interval = defaultPollInterval
	}

	pollInterval := time.Duration(interval) * time.Second
	pollCount := 0
	startTime := time.Now()

	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()

	uiTicker := time.NewTicker(500 * time.Millisecond)
	defer uiTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-pollTicker.C:
			pollCount++
			updates <- tui.FlowUpdate{
				Type:    tui.PollingUpdate,
				Message: "Polling authorization server",
				Data: map[string]any{
					"poll_count": pollCount,
					"interval":   pollInterval,
					"elapsed":    time.Since(startTime),
				},
			}

			token, err := exchangeDeviceCode(
				ctx,
				cfg,
				config.Endpoint.TokenURL,
				config.ClientID,
				deviceAuth.DeviceCode,
			)
			if err != nil {
				oldInterval := pollInterval
				result := handleDevicePollError(err, &pollInterval, pollTicker)
				switch result.action {
				case pollContinue:
					continue
				case pollBackoff:
					updates <- tui.FlowUpdate{
						Type:    tui.BackoffChanged,
						Message: "Server requested slower polling",
						Data: map[string]any{
							"old_interval": oldInterval,
							"new_interval": pollInterval,
						},
					}
					continue
				default:
					return nil, result.err
				}
			}

			return token, nil

		case <-uiTicker.C:
			updates <- tui.FlowUpdate{
				Type: tui.TimerTick,
				Data: map[string]any{
					"elapsed": time.Since(startTime),
				},
			}
		}
	}
}
