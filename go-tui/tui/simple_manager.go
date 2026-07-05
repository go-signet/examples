package tui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
)

// SimpleManager implements Manager using simple fmt.Printf output.
// This preserves the current CLI behavior for backwards compatibility
// and is used in CI environments, pipelines, and non-interactive sessions.
type SimpleManager struct{}

// NewSimpleManager creates a new SimplePrintManager.
func NewSimpleManager() *SimpleManager {
	return &SimpleManager{}
}

func (m *SimpleManager) ShowHeader(clientMode, serverURL, clientID string) {
	fmt.Printf("=== Signet Hybrid CLI (Browser + Device Code Flow) ===\n")
	fmt.Printf("Client mode : %s\n", clientMode)
	fmt.Printf("Server URL  : %s\n", serverURL)
	fmt.Printf("Client ID   : %s\n", clientID)
	fmt.Println()
}

func (m *SimpleManager) ShowFlowSelection(method string) {
	fmt.Printf("Auth method : %s\n", method)
}

func (m *SimpleManager) RunBrowserFlow(
	ctx context.Context,
	perform BrowserFlowFunc,
) (*TokenStorage, bool, error) {
	// Create a channel for updates (but we'll ignore them for simple mode)
	updates := make(chan FlowUpdate, 10)

	// Run the flow in a goroutine
	type result struct {
		storage *TokenStorage
		ok      bool
		err     error
	}
	resultCh := make(chan result, 1)

	go func() {
		storage, ok, err := perform(ctx, updates)
		resultCh <- result{storage, ok, err}
		close(updates)
	}()

	// Drain updates and print simple messages
	for {
		select {
		case update, ok := <-updates:
			if !ok {
				// Channel closed, wait for result
				res := <-resultCh
				return res.storage, res.ok, res.err
			}
			m.handleBrowserUpdate(update)

		case res := <-resultCh:
			// Drain remaining updates
			for update := range updates {
				m.handleBrowserUpdate(update)
			}
			return res.storage, res.ok, res.err
		}
	}
}

func (m *SimpleManager) handleBrowserUpdate(update FlowUpdate) {
	switch update.Type {
	case StepStart:
		switch update.Step {
		case 1:
			fmt.Println("Step 1: Opening browser for authorization...")
			if url := update.GetString("url"); url != "" {
				fmt.Printf("\n  %s\n\n", url)
			}
		case 2:
			fmt.Println("Browser opened. Please complete authorization in your browser.")
			port := update.GetInt("port")
			if port == 0 {
				port = 8888 // default
			}
			fmt.Printf("Step 2: Waiting for callback on http://localhost:%d/callback ...\n", port)
		case 3:
			fmt.Println("Step 3: Exchanging authorization code for tokens...")
		}

	case BrowserOpened:
		// Already printed in StepStart for step 2
		return

	case StepError:
		if update.Message != "" {
			m.displayError(update.Message)
		}

	case CallbackReceived:
		// Token exchange message printed in StepStart for step 3
		return

	case StepProgress, StepComplete, TimerTick, DeviceCodeReceived, PollingUpdate, BackoffChanged:
		// Not displayed in simple mode
	}
}

func (m *SimpleManager) RunDeviceFlow(
	ctx context.Context,
	perform DeviceFlowFunc,
) (*TokenStorage, error) {
	// Create a channel for updates
	updates := make(chan FlowUpdate, 10)

	// Run the flow in a goroutine
	type result struct {
		storage *TokenStorage
		err     error
	}
	resultCh := make(chan result, 1)

	go func() {
		storage, err := perform(ctx, updates)
		resultCh <- result{storage, err}
		close(updates)
	}()

	// Drain updates and print simple messages
	for {
		select {
		case update, ok := <-updates:
			if !ok {
				// Channel closed, wait for result
				res := <-resultCh
				return res.storage, res.err
			}
			m.handleDeviceUpdate(update)

		case res := <-resultCh:
			// Drain remaining updates
			for update := range updates {
				m.handleDeviceUpdate(update)
			}
			return res.storage, res.err
		}
	}
}

func (m *SimpleManager) handleDeviceUpdate(update FlowUpdate) {
	switch update.Step {
	case 1:
		if update.Type == StepStart {
			fmt.Println("Step 1: Requesting device code...")
		}
	case 2:
		if update.Type == StepStart {
			fmt.Println("Step 2: Waiting for authorization...")
		}
	}

	switch update.Type {
	case DeviceCodeReceived:
		userCode := update.GetString("user_code")
		verificationURI := update.GetString("verification_uri")
		verificationURIComplete := update.GetString("verification_uri_complete")

		fmt.Printf("\n----------------------------------------\n")
		fmt.Printf("Please open this link to authorize:\n%s\n", verificationURIComplete)
		fmt.Printf("\nOr visit : %s\n", verificationURI)
		fmt.Printf("And enter: %s\n", userCode)
		fmt.Printf("----------------------------------------\n\n")

	case PollingUpdate:
		// Print a dot every 2 seconds (simple progress indicator)
		fmt.Print(".")

	case BackoffChanged:
		// Don't print anything for backoff changes in simple mode
		return

	case StepComplete:
		if update.Step == 2 {
			fmt.Println("\nAuthorization successful!")
		}

	case StepError:
		if update.Message != "" {
			fmt.Println()
			m.displayError(update.Message)
		}

	case StepStart, StepProgress, TimerTick, BrowserOpened, CallbackReceived:
		// Already handled or not displayed in simple mode
	}
}

func (m *SimpleManager) ShowTokenInfo(storage *TokenStorage) {
	fmt.Printf("\n========================================\n")
	fmt.Printf("Current Token Info:\n")
	fmt.Printf("========================================\n")

	// Security notice
	fmt.Printf("🔒 Full tokens stored in: %s\n\n", formatStorageLocation(storage.StorageBackend))

	// Access Token (masked)
	maskedAccess := maskTokenPreview(storage.AccessToken)
	fmt.Printf("Access Token : %s\n", maskedAccess)

	// Refresh Token (masked, if present)
	if storage.RefreshToken != "" {
		maskedRefresh := maskTokenPreview(storage.RefreshToken)
		fmt.Printf("Refresh Token: %s\n", maskedRefresh)
	}

	fmt.Printf("Token Type   : %s\n", storage.TokenType)
	fmt.Printf("Expires In   : %s\n", time.Until(storage.ExpiresAt).Round(time.Second))

	if storage.Flow != "" {
		fmt.Printf("Auth Flow    : %s\n", storage.Flow)
	}
	fmt.Printf("========================================\n")
}

func (m *SimpleManager) ShowVerification(success bool, info string) {
	fmt.Println("\nVerifying token with server...")
	if success {
		fmt.Println("Token verified successfully.")
		if info != "" {
			fmt.Printf("Token Info: %s\n", info)
		}
	} else {
		fmt.Printf("Token verification failed: %s\n", info)
	}
}

func (m *SimpleManager) ShowStatus(update StatusUpdate) {
	switch update.Event {
	case EventExistingTokens:
		fmt.Println("Found existing tokens.")
	case EventTokenStillValid:
		fmt.Println("Access token is still valid, using it.")
	case EventTokenExpired:
		fmt.Println("Access token expired, attempting refresh...")
	case EventTokenRefreshing:
		fmt.Println("Access token nearing expiry, refreshing proactively...")
	case EventRefreshSuccess:
		fmt.Println("Token refreshed successfully.")
	case EventRefreshFailed:
		// No assumption about what happens next: the caller either keeps using
		// the still-valid token (graceful degradation) or proceeds to a new auth
		// flow, which prints its own status.
		fmt.Printf("Refresh failed: %v\n", update.Err)
	case EventNewAuthFlow:
		fmt.Println("Starting authentication flow...")
	case EventNoExistingTokens:
		fmt.Println("No existing tokens found, starting authentication flow...")
	case EventAutoRefreshDemo:
		fmt.Println("\nDemonstrating automatic refresh on API call...")
	case EventAccessTokenRejected:
		fmt.Println("Access token rejected (401), refreshing...")
	case EventTokenRefreshedRetrying:
		fmt.Println("Token refreshed, retrying API call...")
	case EventAPICallSuccess:
		fmt.Println("API call successful!")
	case EventRefreshTokenExpired:
		fmt.Println("Refresh token expired, re-authenticating...")
	case EventReAuthSuccess:
		fmt.Println("API call successful after re-authentication.")
	}
}

func (m *SimpleManager) ShowUserInfo(success bool, info string) {
	fmt.Println("\nFetching OIDC UserInfo claims...")
	if success {
		fmt.Println("UserInfo retrieved successfully.")
		if info != "" {
			fmt.Printf("User Profile:\n%s\n", info)
		}
	} else {
		fmt.Printf("UserInfo request failed: %s\n", info)
	}
}

// displayError formats and displays an error message with recommendations
func (m *SimpleManager) displayError(errMsg string) {
	// Parse the error
	parsed := parseError(errors.New(errMsg))

	// Display error header
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("❌ AUTHENTICATION FAILED")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	// Display user-friendly message
	fmt.Printf("  %s\n", parsed.UserFriendlyMessage)
	fmt.Println()

	// Display details if different from friendly message
	if parsed.Details != "" && parsed.Details != parsed.UserFriendlyMessage {
		fmt.Println(strings.Repeat("-", 70))
		fmt.Println("Technical Details:")
		fmt.Printf("  %s\n", parsed.Details)
		fmt.Println(strings.Repeat("-", 70))
		fmt.Println()
	}

	// Display recommendations
	recs := getErrorRecommendations(parsed)
	if len(recs) > 0 {
		fmt.Println("💡 Suggested Actions:")
		fmt.Println()
		for i, rec := range recs {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
		fmt.Println()
	}

	// Display retry hint
	fmt.Println("↻ You can try authenticating again")
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()

	// Wait for user acknowledgment only in interactive terminals
	if isatty.IsTerminal(os.Stdin.Fd()) {
		fmt.Print("Press Enter to continue...")
		_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
		fmt.Println()
	}
}
