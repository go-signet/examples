package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-signet/sdk-go/credstore"

	"github.com/go-signet/examples/go-tui/tui"
	"github.com/spf13/cobra"
)

// exitCodeError carries a non-zero exit code through Cobra's error chain
// without printing a redundant message (the command already wrote to stderr).
type exitCodeError int

func (e exitCodeError) Error() string { return "" }

func main() {
	if err := buildRootCmd().Execute(); err != nil {
		var exitErr exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(int(exitErr))
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func buildRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "signet-cli",
		Short:         "OAuth 2.0 authentication CLI",
		Version:       getVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			uiManager := tui.SelectManager()
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			resolveEndpoints(ctx, cfg)
			if code := run(ctx, uiManager, cfg); code != 0 {
				return exitCodeError(code)
			}
			return nil
		},
	}
	registerFlags(rootCmd)
	rootCmd.AddCommand(buildVersionCmd())
	rootCmd.AddCommand(buildTokenCmd())
	return rootCmd
}

func buildVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(getVersion())
		},
	}
}

func run(ctx context.Context, ui tui.Manager, cfg *AppConfig) int {
	clientMode := "public (PKCE)"
	if !cfg.IsPublicClient() {
		clientMode = "confidential"
	}
	ui.ShowHeader(clientMode, cfg.ServerURL, cfg.ClientID)

	var storage *credstore.Token
	var flow string

	// Try to reuse or refresh existing tokens.
	existing, err := cfg.Store.Load(cfg.ClientID)
	if err != nil && !errors.Is(err, credstore.ErrNotFound) {
		fmt.Fprintf(os.Stderr, "Error: Failed to load tokens: %v\n", err)
		return 1
	}
	if err == nil {
		ui.ShowStatus(tui.StatusUpdate{Event: tui.EventExistingTokens})
		// Reuse the already-loaded token as-is. Shared by the still-valid,
		// no-refresh-token, and refresh-failed branches below.
		useCached := func() {
			storage = &existing
			flow = "cached"
		}
		// Capture now once so the refresh decision and the graceful-degradation
		// check below reason about the same instant.
		now := time.Now()
		if !needsRefresh(existing, cfg.RefreshThreshold, now) {
			ui.ShowStatus(tui.StatusUpdate{Event: tui.EventTokenStillValid})
			useCached()
		} else {
			// Whether the old token is still usable as-is — shared with
			// ensureFreshToken via tokenUsable so a corrupt token (empty access
			// token but future expiry) is never reused.
			reuseValid := tokenUsable(existing, now)
			if existing.RefreshToken == "" {
				// No refresh token means a refresh can only fail, so skip the
				// network call entirely (no refresh step is shown). Reuse the old
				// token while it's still valid; otherwise fall through to re-auth.
				if reuseValid {
					useCached()
				}
			} else {
				// About to refresh: show an accurate in-progress status —
				// "expired" only when actually expired, otherwise "near expiry".
				if now.Before(existing.ExpiresAt) {
					ui.ShowStatus(tui.StatusUpdate{Event: tui.EventTokenRefreshing})
				} else {
					ui.ShowStatus(tui.StatusUpdate{Event: tui.EventTokenExpired})
				}
				newStorage, refreshErr := refreshAccessToken(ctx, cfg, existing.RefreshToken)
				if refreshErr != nil {
					// The refresh genuinely failed, so mark it failed in the UI.
					// Then degrade gracefully (reuse the still-valid token) or
					// fall through to re-authentication once expired.
					ui.ShowStatus(tui.StatusUpdate{Event: tui.EventRefreshFailed, Err: refreshErr})
					if reuseValid {
						useCached()
					}
				} else {
					storage = newStorage
					flow = "refreshed"
					ui.ShowStatus(tui.StatusUpdate{Event: tui.EventRefreshSuccess})
				}
			}
		}
	} else {
		ui.ShowStatus(tui.StatusUpdate{Event: tui.EventNoExistingTokens})
	}

	// No valid tokens — select and run the appropriate flow.
	if storage == nil {
		storage, flow, err = authenticate(ctx, ui, cfg)
		if err != nil {
			// Error details are already displayed by the UI manager
			// Just exit with error code
			return 1
		}
	}

	// Display token info.
	ui.ShowTokenInfo(toTUITokenStorage(storage, flow, cfg.Store.String()))

	// Verify token and fetch UserInfo in parallel (independent API calls).
	var (
		verifyInfo string
		verifyErr  error
		userInfo   *UserInfo
		userErr    error
		wg         sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		verifyInfo, verifyErr = verifyToken(ctx, cfg, storage.AccessToken)
	}()
	go func() {
		defer wg.Done()
		userInfo, userErr = fetchUserInfo(ctx, cfg, storage.AccessToken)
	}()
	wg.Wait()

	if verifyErr != nil {
		ui.ShowVerification(false, verifyErr.Error())
	} else {
		ui.ShowVerification(true, verifyInfo)
	}

	if userErr != nil {
		ui.ShowUserInfo(false, userErr.Error())
	} else {
		ui.ShowUserInfo(true, formatUserInfo(userInfo))
	}

	// Demonstrate auto-refresh on 401.
	ui.ShowStatus(tui.StatusUpdate{Event: tui.EventAutoRefreshDemo})
	if err := makeAPICallWithAutoRefresh(ctx, cfg, storage, ui); err != nil {
		if errors.Is(err, ErrRefreshTokenExpired) {
			ui.ShowStatus(tui.StatusUpdate{Event: tui.EventRefreshTokenExpired})
			storage, _, err = authenticate(ctx, ui, cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Re-authentication failed: %v\n", err)
				return 1
			}
			if err := makeAPICallWithAutoRefresh(ctx, cfg, storage, ui); err != nil {
				fmt.Fprintf(os.Stderr, "API call failed after re-authentication: %v\n", err)
				return 1
			}
			ui.ShowStatus(tui.StatusUpdate{Event: tui.EventReAuthSuccess})
		} else {
			fmt.Fprintf(os.Stderr, "API call failed: %v\n", err)
		}
	}
	return 0
}
