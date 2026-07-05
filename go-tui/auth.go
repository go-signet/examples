package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"github.com/go-signet/examples/go-tui/tui"
	"github.com/go-signet/sdk-go/credstore"
)

// authenticate selects and runs the appropriate OAuth flow:
//
//  1. --device flag → Device Code Flow (forced)
//  2. Environment signals (SSH, no display, port busy) → Device Code Flow
//  3. Browser available → Authorization Code Flow with PKCE
//     - openBrowser() error → immediate fallback to Device Code Flow
func authenticate(
	ctx context.Context,
	ui tui.Manager,
	cfg *AppConfig,
) (*credstore.Token, string, error) {
	deviceFlow := func(ctx context.Context, updates chan<- tui.FlowUpdate) (*tui.TokenStorage, error) {
		return performDeviceFlowWithUpdates(ctx, cfg, updates)
	}
	browserFlow := func(ctx context.Context, updates chan<- tui.FlowUpdate) (*tui.TokenStorage, bool, error) {
		return performBrowserFlowWithUpdates(ctx, cfg, updates)
	}

	runDeviceFlow := func(reason string) (*credstore.Token, string, error) {
		ui.ShowFlowSelection(reason)
		tuiStorage, err := ui.RunDeviceFlow(ctx, deviceFlow)
		return fromTUITokenStorage(tuiStorage), flowFromTUI(tuiStorage), err
	}

	if cfg.ForceDevice {
		return runDeviceFlow("Device Code Flow (forced via flag)")
	}

	if avail := checkBrowserAvailability(ctx, cfg.CallbackPort); !avail.Available {
		return runDeviceFlow(fmt.Sprintf("Device Code Flow (%s)", avail.Reason))
	}

	ui.ShowFlowSelection("Authorization Code Flow (browser)")
	tuiStorage, ok, err := ui.RunBrowserFlow(ctx, browserFlow)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		// openBrowser() failed; fall back to Device Code Flow immediately.
		return runDeviceFlow("Device Code Flow (browser unavailable)")
	}
	return fromTUITokenStorage(tuiStorage), flowFromTUI(tuiStorage), nil
}

// needsRefresh reports whether the stored token should be proactively
// refreshed: the access token is empty, or it expires within threshold of now.
// A token still further than threshold from expiry returns false so callers
// can reuse it without any network request.
func needsRefresh(tok credstore.Token, threshold time.Duration, now time.Time) bool {
	if tok.AccessToken == "" {
		return true
	}
	// Refresh when expiry is at or before now+threshold (inclusive boundary).
	return !now.Add(threshold).Before(tok.ExpiresAt)
}

// tokenUsable reports whether a stored token can be used as-is right now: it
// has a non-empty access token and has not yet expired. Shared by run() and
// ensureFreshToken so the "reuse the old token" condition — including the empty
// access token and exact expiry-boundary edge cases — stays identical in both.
func tokenUsable(tok credstore.Token, now time.Time) bool {
	return tok.AccessToken != "" && now.Before(tok.ExpiresAt)
}

// ensureFreshToken loads the stored token for cfg.ClientID and, when it falls
// within cfg.RefreshThreshold of expiry, exchanges the refresh token for a new
// one. On refresh failure it degrades gracefully:
//   - old token not yet expired → returns the old token plus a stderr warning
//   - old token expired and refresh failed → returns the refresh error
//     (e.g. ErrRefreshTokenExpired / ErrNoRefreshToken)
//
// cfg only needs the token store, client ID, and refresh threshold. A network
// refresh requires the full network-capable config (server URL validation,
// retry client, endpoints), which is built lazily via loadFull only once a
// refresh is actually required — so reads far from expiry stay fully offline
// and never validate SIGNET_URL or emit transport warnings. When loadFull is
// nil, cfg is used as-is (used by tests that pre-populate everything).
//
// It returns the token to use and whether a refresh actually occurred. The
// load error (including credstore.ErrNotFound) is returned verbatim so callers
// can tailor their diagnostics.
func ensureFreshToken(
	ctx context.Context,
	cfg *AppConfig,
	loadFull func() *AppConfig,
	stderr io.Writer,
) (credstore.Token, bool, error) {
	tok, err := cfg.Store.Load(cfg.ClientID)
	if err != nil {
		return credstore.Token{}, false, err
	}

	// Capture now once so the refresh decision and the graceful-degradation
	// check below reason about the same instant.
	now := time.Now()
	if !needsRefresh(tok, cfg.RefreshThreshold, now) {
		// Far from expiry: reuse as-is without resolving endpoints or making
		// any network request (offline/common path stays zero-cost).
		return tok, false, nil
	}

	// reuseOrFail applies graceful degradation: keep using the old token only
	// while it's still usable — present and not yet expired. An empty or
	// already-expired access token is never reusable, so the cause surfaces as
	// an error instead of silently succeeding with an unusable token.
	reuseOrFail := func(cause error) (credstore.Token, bool, error) {
		if tokenUsable(tok, now) {
			fmt.Fprintf(stderr, "Warning: token refresh failed, using existing token: %v\n", cause)
			return tok, false, nil
		}
		return credstore.Token{}, false, cause
	}

	// Without a refresh token a refresh can only fail after a wasted round
	// trip, so skip the network entirely and degrade gracefully.
	if tok.RefreshToken == "" {
		return reuseOrFail(ErrNoRefreshToken)
	}

	// A network refresh is required, so upgrade to the full network-capable
	// config now (deferring SIGNET_URL validation and transport setup until
	// this point keeps the far-from-expiry path offline).
	full := cfg
	if loadFull != nil {
		full = loadFull()
		// loadFull (loadConfig) builds a fresh store instance that could resolve
		// to a different backend/path than the one we loaded the token from.
		// Pin the store and client ID to the originally loaded config so the
		// refreshed token is saved exactly where it came from.
		full.Store = cfg.Store
		full.ClientID = cfg.ClientID
	}

	// Resolve endpoints lazily too. Callers that pre-populate Endpoints skip
	// this (e.g. tests).
	if full.Endpoints.TokenURL == "" {
		resolveEndpoints(ctx, full)
	}

	newTok, err := refreshAccessToken(ctx, full, tok.RefreshToken)
	if err != nil {
		return reuseOrFail(err)
	}
	return *newTok, true, nil
}

// refreshAccessToken exchanges a refresh token for a new access token.
func refreshAccessToken(
	ctx context.Context,
	cfg *AppConfig,
	refreshToken string,
) (*credstore.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.RefreshTokenTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", cfg.ClientID)
	cfg.setClientSecret(data)
	// Server doesn't persist extra_claims across refresh, so re-send them.
	cfg.setExtraClaims(data)

	tokenResp, err := doTokenExchange(ctx, cfg, cfg.Endpoints.TokenURL, data,
		func(errResp ErrorResponse, _ []byte) error {
			if errResp.Error == "invalid_grant" || errResp.Error == "invalid_token" {
				return ErrRefreshTokenExpired
			}
			return nil // fall through to default error formatting
		},
	)
	if err != nil {
		return nil, err
	}

	storage := tokenResponseToCredstore(cfg, tokenResp)

	// Preserve the old refresh token in fixed-mode (server may not return a new one).
	if storage.RefreshToken == "" {
		storage.RefreshToken = refreshToken
	}

	if err := cfg.Store.Save(cfg.ClientID, *storage); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to save refreshed tokens: %v\n", err)
	}
	return storage, nil
}

// verifyToken verifies an access token with the OAuth server.
func verifyToken(ctx context.Context, cfg *AppConfig, accessToken string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.TokenVerificationTimeout)
	defer cancel()

	resp, err := cfg.RetryClient.Get(ctx, cfg.Endpoints.TokenInfoURL,
		retry.WithHeader("Authorization", "Bearer "+accessToken),
	)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := readResponseBody(resp, cfg.MaxResponseBodySize)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", formatHTTPError(body, resp.StatusCode)
	}

	return string(body), nil
}

// makeAPICallWithAutoRefresh demonstrates the 401 → refresh → retry pattern.
func makeAPICallWithAutoRefresh(
	ctx context.Context,
	cfg *AppConfig,
	storage *credstore.Token,
	ui tui.Manager,
) error {
	resp, err := cfg.RetryClient.Get(ctx, cfg.Endpoints.TokenInfoURL,
		retry.WithHeader("Authorization", "Bearer "+storage.AccessToken),
	)
	if err != nil {
		return fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		ui.ShowStatus(tui.StatusUpdate{Event: tui.EventAccessTokenRejected})

		newStorage, err := refreshAccessToken(ctx, cfg, storage.RefreshToken)
		if err != nil {
			if errors.Is(err, ErrRefreshTokenExpired) {
				return ErrRefreshTokenExpired
			}
			return fmt.Errorf("refresh failed: %w", err)
		}

		// Adopt every refreshed field (TokenType and ClientID too), rather than a
		// partial copy that would silently drop any field added to the token.
		*storage = *newStorage

		ui.ShowStatus(tui.StatusUpdate{Event: tui.EventTokenRefreshedRetrying})

		resp, err = cfg.RetryClient.Get(ctx, cfg.Endpoints.TokenInfoURL,
			retry.WithHeader("Authorization", "Bearer "+storage.AccessToken),
		)
		if err != nil {
			return fmt.Errorf("retry failed: %w", err)
		}
		defer resp.Body.Close()
	}

	body, err := readResponseBody(resp, cfg.MaxResponseBodySize)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API call failed with status %d: %s", resp.StatusCode, string(body))
	}

	ui.ShowStatus(tui.StatusUpdate{Event: tui.EventAPICallSuccess})
	return nil
}
