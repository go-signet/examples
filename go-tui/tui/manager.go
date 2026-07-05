package tui

import (
	"context"
	"os"
	"time"

	"github.com/mattn/go-isatty"
	"golang.org/x/term"
)

// StatusEvent identifies a status notification in the UI.
type StatusEvent int

const (
	EventExistingTokens         StatusEvent = iota // Existing tokens were found
	EventTokenStillValid                           // Access token is still valid
	EventTokenExpired                              // Access token expired
	EventTokenRefreshing                           // Access token near expiry, refreshing proactively
	EventRefreshSuccess                            // Token refresh succeeded
	EventRefreshFailed                             // Token refresh failed (see Err)
	EventNewAuthFlow                               // Starting a new authentication flow
	EventNoExistingTokens                          // No existing tokens found
	EventAutoRefreshDemo                           // Starting the auto-refresh demo
	EventAccessTokenRejected                       // Access token was rejected (401)
	EventTokenRefreshedRetrying                    // Token refreshed, retrying API call
	EventAPICallSuccess                            // API call succeeded
	EventRefreshTokenExpired                       // Refresh token expired, need re-auth
	EventReAuthSuccess                             // Re-authentication succeeded
)

// StatusUpdate carries a status notification to the UI layer.
type StatusUpdate struct {
	Event StatusEvent
	Err   error // non-nil for EventRefreshFailed
}

// Manager is the interface for managing UI output in the CLI.
// It abstracts the presentation layer, allowing for different implementations:
//   - SimpleManager: Uses fmt.Printf (current behavior, for CI/pipelines)
//   - BubbleTeaManager: Uses Bubble Tea for interactive TUI
type Manager interface {
	ShowHeader(clientMode, serverURL, clientID string)
	ShowFlowSelection(method string)
	RunBrowserFlow(ctx context.Context, perform BrowserFlowFunc) (*TokenStorage, bool, error)
	RunDeviceFlow(ctx context.Context, perform DeviceFlowFunc) (*TokenStorage, error)
	ShowTokenInfo(storage *TokenStorage)
	ShowVerification(success bool, info string)
	ShowUserInfo(success bool, info string)
	ShowStatus(update StatusUpdate)
}

// BrowserFlowFunc is a function that performs the browser OAuth flow and sends
// progress updates through the provided channel.
type BrowserFlowFunc func(ctx context.Context, updates chan<- FlowUpdate) (*TokenStorage, bool, error)

// DeviceFlowFunc is a function that performs the device code OAuth flow and sends
// progress updates through the provided channel.
type DeviceFlowFunc func(ctx context.Context, updates chan<- FlowUpdate) (*TokenStorage, error)

// TokenStorage represents the stored OAuth tokens.
// This is a placeholder - the actual type should match the one in the main package.
type TokenStorage struct {
	AccessToken    string
	RefreshToken   string
	TokenType      string
	ExpiresAt      time.Time
	ClientID       string
	Flow           string
	StorageBackend string // e.g. "keyring: signet-cli" or "file: .signet-tokens.json"
}

// SelectManager chooses the appropriate UI manager based on environment detection.
// Returns SimplePrintManager for CI/pipelines, BubbleTeaManager for interactive terminals.
func SelectManager() Manager {
	if shouldUseSimpleUI() {
		return NewSimpleManager()
	}
	return NewBubbleTeaManager()
}

// shouldUseSimpleUI determines if we should use simple printf-based UI instead of TUI.
// Returns true for CI environments, non-TTY output, small terminals, or dumb terminals.
func shouldUseSimpleUI() bool {
	// CI environment detection
	if isCIEnvironment() {
		return true
	}

	// Output is not a terminal (piped to file, etc.)
	if !isatty.IsTerminal(os.Stdout.Fd()) && !isatty.IsCygwinTerminal(os.Stdout.Fd()) {
		return true
	}

	// Terminal is too small
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || width < 60 || height < 20 {
		return true
	}

	// TERM is not set or is "dumb"
	termType := os.Getenv("TERM")
	if termType == "" || termType == "dumb" {
		return true
	}

	return false
}

// isCIEnvironment checks if we're running in a CI environment.
func isCIEnvironment() bool {
	ciEnvVars := []string{
		"CI",
		"GITHUB_ACTIONS",
		"GITLAB_CI",
		"CIRCLECI",
		"JENKINS_URL",
		"TRAVIS",
		"BUILDKITE",
		"DRONE",
		"TEAMCITY_VERSION",
		"TF_BUILD", // Azure Pipelines
	}
	for _, envVar := range ciEnvVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}
	return false
}
