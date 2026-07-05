package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// BubbleTeaManager implements Manager using Bubble Tea for interactive TUI.
// This provides a rich, interactive terminal UI with progress indicators,
// timers, and visual feedback.
type BubbleTeaManager struct {
	simple   *SimpleManager
	renderer *FlowRenderer
	stepMap  map[string]int // maps step names to indices for updates
}

// NewBubbleTeaManager creates a new BubbleTeaManager.
func NewBubbleTeaManager() *BubbleTeaManager {
	return &BubbleTeaManager{
		simple:  NewSimpleManager(),
		stepMap: make(map[string]int),
	}
}

// ShowHeader initializes and displays the header
func (m *BubbleTeaManager) ShowHeader(clientMode, serverURL, clientID string) {
	// Initialize flow renderer
	flowType := "OAuth 2.0 Authorization Code Flow"
	m.renderer = NewFlowRenderer(flowType, clientMode, serverURL)

	// Add HTTP warning if needed
	if strings.HasPrefix(strings.ToLower(serverURL), "http://") {
		m.renderer.AddWarning(
			"Using HTTP instead of HTTPS. Tokens will be transmitted in plaintext!",
		)
		m.renderer.AddWarning("This is only safe for local development. Use HTTPS in production.")
	}

	// Add initial steps
	m.addStep("Check existing tokens")

	// Render header
	m.renderer.RenderHeader()
}

func (m *BubbleTeaManager) ShowFlowSelection(method string) {
	m.addStep("Set up authorization flow")
	m.updateStep("Set up authorization flow", StepCompleted, method)
	m.refreshDisplay()
}

// Helper methods for managing steps.
// addStep is idempotent — calling it with the same name twice is a no-op.
func (m *BubbleTeaManager) addStep(name string) {
	if m.renderer != nil {
		if _, exists := m.stepMap[name]; exists {
			return
		}
		idx := m.renderer.AddStep(name)
		m.stepMap[name] = idx
	}
}

func (m *BubbleTeaManager) updateStep(name string, status FlowStepStatus, message string) {
	if m.renderer != nil {
		if idx, ok := m.stepMap[name]; ok {
			m.renderer.UpdateStep(idx, status, message)
		}
	}
}

func (m *BubbleTeaManager) refreshDisplay() {
	if m.renderer != nil {
		m.renderer.UpdateDisplay()
	}
}

// runFlow is the shared event loop for both browser and device flows.
// It launches the flow function in a goroutine, processes updates via the
// provided handler, animates the spinner, and returns the final result.
func (m *BubbleTeaManager) runFlow(
	ctx context.Context,
	startFlow func(ctx context.Context, updates chan<- FlowUpdate) (any, error),
	handleUpdate func(FlowUpdate),
) (any, error) {
	updates := make(chan FlowUpdate, 10)

	flowCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		val any
		err error
	}
	resultCh := make(chan result, 1)

	go func() {
		val, err := startFlow(flowCtx, updates)
		resultCh <- result{val, err}
		close(updates)
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case update, ok := <-updates:
			if !ok {
				res := <-resultCh
				return res.val, res.err
			}
			handleUpdate(update)
			m.refreshDisplay()

		case <-ticker.C:
			m.renderer.NextSpinner()
			m.refreshDisplay()

		case res := <-resultCh:
			for update := range updates {
				handleUpdate(update)
			}
			m.refreshDisplay()
			return res.val, res.err

		case <-ctx.Done():
			// Cancel the flow goroutine and drain updates to prevent leaks.
			cancel()
			for {
				select {
				case _, ok := <-updates:
					if !ok {
						<-resultCh
						return nil, ctx.Err()
					}
				case <-resultCh:
					return nil, ctx.Err()
				}
			}
		}
	}
}

// handleFlowUpdate processes a FlowUpdate using the given step-name mapping
// and flow-specific extra handler. The stepNames map maps step numbers (1-based)
// to step names. The extraHandler processes flow-specific update types.
func (m *BubbleTeaManager) handleFlowUpdate(
	update FlowUpdate,
	stepNames map[int]string,
	extraHandler func(FlowUpdate),
) {
	switch update.Type {
	case StepStart:
		if name, ok := stepNames[update.Step]; ok {
			m.updateStep(name, StepInProgress, "")
		}

	case StepComplete:
		if extraHandler != nil {
			extraHandler(update)
		}

	case StepError:
		parsed := parseError(errors.New(update.Message))
		if name, ok := stepNames[update.Step]; ok {
			m.updateStep(name, StepFailed, parsed.UserFriendlyMessage)
		}

	default:
		if extraHandler != nil {
			extraHandler(update)
		}
	}
}

// RunBrowserFlow executes the browser OAuth flow with unified TUI rendering.
func (m *BubbleTeaManager) RunBrowserFlow(
	ctx context.Context,
	perform BrowserFlowFunc,
) (*TokenStorage, bool, error) {
	if m.renderer == nil {
		return m.simple.RunBrowserFlow(ctx, perform)
	}

	m.addStep("Open browser")
	m.addStep("Wait for browser callback")
	m.addStep("Exchange tokens")

	stepNames := map[int]string{
		1: "Open browser",
		2: "Wait for browser callback",
		3: "Exchange tokens",
	}

	type browserResult struct {
		storage *TokenStorage
		ok      bool
	}

	val, err := m.runFlow(ctx,
		func(flowCtx context.Context, updates chan<- FlowUpdate) (any, error) {
			storage, ok, err := perform(flowCtx, updates)
			return browserResult{storage, ok}, err
		},
		func(update FlowUpdate) {
			m.handleFlowUpdate(update, stepNames, func(u FlowUpdate) {
				switch u.Type {
				case BrowserOpened:
					m.updateStep("Open browser", StepCompleted, "Browser opened")

				case TimerTick:
					elapsed := u.GetDuration("elapsed")
					timeout := u.GetDuration("timeout")
					remaining := max(0, timeout-elapsed)
					m.updateStep("Wait for browser callback", StepInProgress,
						formatRemainingTime(remaining)+" remaining")

				case CallbackReceived:
					m.updateStep(
						"Wait for browser callback",
						StepCompleted,
						"Authorization complete",
					)
					m.updateStep("Exchange tokens", StepInProgress, "")

				case StepComplete:
					if u.Step == 3 {
						m.updateStep("Exchange tokens", StepCompleted, "Tokens retrieved")
					}
				}
			})
		},
	)
	if err != nil {
		return nil, false, err
	}
	res := val.(browserResult)
	return res.storage, res.ok, nil
}

// formatRemainingTime formats a duration as "Xm Ys" or "Xs"
func formatRemainingTime(d time.Duration) string {
	d = d.Round(time.Second)
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60

	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// RunDeviceFlow executes the device code OAuth flow with unified TUI rendering.
func (m *BubbleTeaManager) RunDeviceFlow(
	ctx context.Context,
	perform DeviceFlowFunc,
) (*TokenStorage, error) {
	if m.renderer == nil {
		return m.simple.RunDeviceFlow(ctx, perform)
	}

	m.addStep("Request device code")
	m.addStep("Wait for authorization")
	m.addStep("Exchange tokens")

	stepNames := map[int]string{
		1: "Request device code",
		2: "Wait for authorization",
		3: "Exchange tokens",
	}

	val, err := m.runFlow(ctx,
		func(flowCtx context.Context, updates chan<- FlowUpdate) (any, error) {
			return perform(flowCtx, updates)
		},
		func(update FlowUpdate) {
			m.handleFlowUpdate(update, stepNames, func(u FlowUpdate) {
				switch u.Type {
				case DeviceCodeReceived:
					userCode := u.GetString("user_code")
					verificationURI := u.GetString("verification_uri")
					verificationURIComplete := u.GetString("verification_uri_complete")
					m.updateStep("Request device code", StepCompleted, "Code received")

					if userCode != "" && verificationURI != "" {
						m.renderer.SetDeviceCode(userCode, verificationURI, verificationURIComplete)
						m.updateStep("Wait for authorization", StepInProgress, "")
					}

				case PollingUpdate:
					pollCount := u.GetInt("poll_count")
					m.updateStep("Wait for authorization", StepInProgress,
						fmt.Sprintf("Polling... (attempt %d)", pollCount))

				case StepComplete:
					if u.Step == 2 {
						m.updateStep(
							"Wait for authorization",
							StepCompleted,
							"Authorization complete",
						)
						m.updateStep("Exchange tokens", StepCompleted, "Tokens retrieved")
					}
				}
			})
		},
	)
	if err != nil {
		return nil, err
	}
	return val.(*TokenStorage), nil
}

func (m *BubbleTeaManager) ShowTokenInfo(storage *TokenStorage) {
	if m.renderer == nil {
		m.simple.ShowTokenInfo(storage)
		return
	}
	m.renderer.SetTokenInfo(storage)
	m.refreshDisplay()
}

func (m *BubbleTeaManager) ShowVerification(success bool, info string) {
	if m.renderer == nil {
		m.simple.ShowVerification(success, info)
		return
	}
	m.addStep("Verify token")
	if success {
		m.updateStep("Verify token", StepCompleted, "Token valid")
	} else {
		m.updateStep("Verify token", StepFailed, info)
	}
	m.refreshDisplay()
}

func (m *BubbleTeaManager) ShowStatus(update StatusUpdate) {
	if m.renderer == nil {
		m.simple.ShowStatus(update)
		return
	}

	switch update.Event {
	case EventExistingTokens:
		m.updateStep("Check existing tokens", StepCompleted, "Existing tokens found")

	case EventTokenStillValid:
		// Shown via verification step — no-op

	case EventTokenExpired:
		m.addStep("Refresh token")
		m.updateStep("Refresh token", StepInProgress, "Access token expired")

	case EventTokenRefreshing:
		m.addStep("Refresh token")
		m.updateStep("Refresh token", StepInProgress, "Access token nearing expiry")

	case EventRefreshSuccess:
		m.updateStep("Refresh token", StepCompleted, "Token refreshed")

	case EventRefreshFailed:
		m.updateStep("Refresh token", StepFailed, update.Err.Error())

	case EventNewAuthFlow:
		// Shown via setup step — no-op

	case EventNoExistingTokens:
		m.updateStep("Check existing tokens", StepCompleted, "No existing tokens")

	case EventAutoRefreshDemo:
		m.addStep("API call")
		m.updateStep("API call", StepInProgress, "Testing auto-refresh")

	case EventAccessTokenRejected:
		m.updateStep("API call", StepInProgress, "Access token rejected, refreshing...")

	case EventTokenRefreshedRetrying:
		m.updateStep("API call", StepInProgress, "Token refreshed, retrying...")

	case EventAPICallSuccess:
		m.updateStep("API call", StepCompleted, "API call successful")

	case EventRefreshTokenExpired:
		m.addStep("Re-authenticate")
		m.updateStep("Re-authenticate", StepInProgress, "Refresh token expired")

	case EventReAuthSuccess:
		m.updateStep("Re-authenticate", StepCompleted, "Re-authentication successful")
	}

	m.refreshDisplay()
}

func (m *BubbleTeaManager) ShowUserInfo(success bool, info string) {
	if m.renderer == nil {
		m.simple.ShowUserInfo(success, info)
		return
	}
	m.addStep("OIDC UserInfo")
	if success {
		m.updateStep("OIDC UserInfo", StepCompleted, "Profile retrieved")
	} else {
		m.updateStep("OIDC UserInfo", StepFailed, info)
	}
	m.refreshDisplay()
}

// getTerminalSize returns the width and height of the terminal.
// Returns default values (80, 24) if unable to determine size.
func getTerminalSize() (width, height int) {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		// Default fallback
		return 80, 24
	}
	return width, height
}
