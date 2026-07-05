package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/go-signet/examples/go-tui/tui"
	"github.com/go-signet/sdk-go/credstore"
)

// buildAuthURL constructs the /oauth/authorize URL with all required parameters.
func buildAuthURL(cfg *AppConfig, state string, pkce *PKCEParams) string {
	params := url.Values{}
	params.Set("client_id", cfg.ClientID)
	params.Set("redirect_uri", cfg.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", cfg.Scope)
	params.Set("state", state)
	params.Set("code_challenge", pkce.Challenge)
	params.Set("code_challenge_method", pkce.Method)
	return cfg.Endpoints.AuthorizeURL + "?" + params.Encode()
}

// exchangeCode exchanges an authorization code for access + refresh tokens.
func exchangeCode(
	ctx context.Context,
	cfg *AppConfig,
	code, codeVerifier string,
) (*credstore.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.TokenExchangeTimeout)
	defer cancel()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", cfg.RedirectURI)
	data.Set("client_id", cfg.ClientID)
	data.Set("code_verifier", codeVerifier)

	cfg.setClientSecret(data)
	cfg.setExtraClaims(data)

	tokenResp, err := doTokenExchange(ctx, cfg, cfg.Endpoints.TokenURL, data, nil)
	if err != nil {
		return nil, err
	}

	return tokenResponseToCredstore(cfg, tokenResp), nil
}

// performBrowserFlowWithUpdates runs the Authorization Code Flow with PKCE
// and sends progress updates through the provided channel.
//
// Every exit path — success, soft error, and hard error — sends at least one
// update before returning, so the Bubble Tea TUI always receives a quit signal
// and never hangs.
//
// Returns:
//   - (storage, true, nil)  on success
//   - (nil, false, nil)     on a soft error (browser unavailable, timeout) —
//     caller should fall back to Device Code Flow
//   - (nil, false, err)     on a hard error (CSRF mismatch, token exchange
//     failure, OAuth server rejection, etc.)
func performBrowserFlowWithUpdates(
	ctx context.Context,
	cfg *AppConfig,
	updates chan<- tui.FlowUpdate,
) (*tui.TokenStorage, bool, error) {
	updates <- tui.FlowUpdate{
		Type:       tui.StepStart,
		Step:       1,
		TotalSteps: 3,
		Message:    "Generating PKCE parameters",
	}

	state, err := generateState()
	if err != nil {
		updates <- tui.FlowUpdate{
			Type:    tui.StepError,
			Message: fmt.Sprintf("Failed to generate state: %v", err),
		}
		return nil, false, fmt.Errorf("failed to generate state: %w", err)
	}

	pkce, err := GeneratePKCE()
	if err != nil {
		updates <- tui.FlowUpdate{
			Type:    tui.StepError,
			Message: fmt.Sprintf("Failed to generate PKCE parameters: %v", err),
		}
		return nil, false, fmt.Errorf("failed to generate PKCE: %w", err)
	}

	authURL := buildAuthURL(cfg, state, pkce)
	updates <- tui.FlowUpdate{
		Type:       tui.StepStart,
		Step:       1,
		TotalSteps: 3,
		Message:    "Opening browser",
		Data: map[string]any{
			"url": authURL,
		},
	}

	if err := openBrowser(ctx, authURL); err != nil {
		// Browser failed to open — soft error, signal the caller to fall back.
		updates <- tui.FlowUpdate{
			Type:     tui.StepError,
			Fallback: true,
			Message:  fmt.Sprintf("Could not open browser: %v", err),
		}
		return nil, false, nil
	}

	updates <- tui.FlowUpdate{Type: tui.BrowserOpened}
	updates <- tui.FlowUpdate{
		Type:       tui.StepStart,
		Step:       2,
		TotalSteps: 3,
		Message:    "Waiting for callback",
		Data: map[string]any{
			"port": cfg.CallbackPort,
		},
	}

	// Start goroutine to send timer updates. Join it before returning (Wait runs
	// after close(done) thanks to LIFO defer order) so the goroutine can never
	// send on `updates` after the caller closes that channel — which would panic
	// with "send on closed channel".
	done := make(chan struct{})
	var timerWG sync.WaitGroup
	defer timerWG.Wait()
	defer close(done)

	timerWG.Go(func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		startTime := time.Now()

		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsed := time.Since(startTime)
				progress := float64(elapsed) / float64(cfg.CallbackTimeout)
				if progress > 1.0 {
					progress = 1.0
				}
				update := tui.FlowUpdate{
					Type:     tui.TimerTick,
					Progress: progress,
					Data: map[string]any{
						"elapsed": elapsed,
						"timeout": cfg.CallbackTimeout,
					},
				}
				select {
				case updates <- update:
				case <-done:
					return
				case <-ctx.Done():
					return
				}
			}
		}
	})

	storage, err := startCallbackServer(ctx, cfg.CallbackPort, state, cfg.CallbackTimeout,
		func(callbackCtx context.Context, code string) (*credstore.Token, error) {
			updates <- tui.FlowUpdate{
				Type:       tui.StepStart,
				Step:       3,
				TotalSteps: 3,
				Message:    "Exchanging tokens",
			}
			return exchangeCode(callbackCtx, cfg, code, pkce.Verifier)
		})
	if err != nil {
		if errors.Is(err, ErrCallbackTimeout) {
			// Soft error — fall back to Device Code Flow silently.
			updates <- tui.FlowUpdate{
				Type:     tui.StepError,
				Fallback: true,
				Message:  "Browser authorization timed out",
			}
			return nil, false, nil
		}
		// Hard error (CSRF mismatch, token exchange failure, OAuth rejection,
		// etc.) — surface it to the user.
		updates <- tui.FlowUpdate{
			Type:    tui.StepError,
			Step:    3,
			Message: err.Error(),
		}
		return nil, false, fmt.Errorf("authentication failed: %w", err)
	}

	updates <- tui.FlowUpdate{Type: tui.CallbackReceived}

	if err := cfg.Store.Save(storage.ClientID, *storage); err != nil {
		updates <- tui.FlowUpdate{
			Type:    tui.StepError,
			Message: fmt.Sprintf("Warning: Failed to save tokens: %v", err),
		}
	}

	updates <- tui.FlowUpdate{
		Type:       tui.StepComplete,
		Step:       3,
		TotalSteps: 3,
	}

	return toTUITokenStorage(storage, "browser", cfg.Store.String()), true, nil
}
