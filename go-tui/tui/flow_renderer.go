package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// ANSI escape sequences for terminal control.
const (
	ansiClearScreen = "\033[H\033[2J"
	ansiClearToEnd  = "\033[J"
	ansiHideCursor  = "\033[999;999H"
)

// FlowRenderer manages rendering of the unified flow view without running a full Bubble Tea program
type FlowRenderer struct {
	model                         *UnifiedFlowModel
	spinnerFrame                  int
	spinnerChars                  []rune
	contentDirty                  bool      // Flag to indicate if content needs redraw
	inProgressStepIdx             int       // Index of the in-progress step for spinner updates, or -1 if none
	deviceUserCode                string    // Device code to display
	deviceVerificationURI         string    // Device verification URL
	deviceVerificationURIComplete string    // Complete URL with user code
	showDeviceCode                bool      // Whether to show device code info
	lastResizeCheck               time.Time // Throttles getTerminalSize syscalls
	headerLines                   int       // Number of lines occupied by the header
}

// NewFlowRenderer creates a new flow renderer
func NewFlowRenderer(flowType, clientMode, serverURL string) *FlowRenderer {
	// Get terminal size
	width, height := getTerminalSize()

	model := NewUnifiedFlowModel(flowType, clientMode, serverURL)
	model.width = width
	model.height = height

	return &FlowRenderer{
		model:             model,
		spinnerFrame:      0,
		spinnerChars:      []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'},
		inProgressStepIdx: -1,
	}
}

// AddWarning adds a warning message
func (r *FlowRenderer) AddWarning(warning string) {
	r.model.AddWarning(warning)
}

// AddStep adds a new step and returns its index
func (r *FlowRenderer) AddStep(name string) int {
	r.contentDirty = true
	return r.model.AddStep(name)
}

// UpdateStep updates a step's status and message
func (r *FlowRenderer) UpdateStep(index int, status FlowStepStatus, message string) {
	r.contentDirty = true
	r.model.UpdateStep(index, status, message)

	// Track if this step is in progress for spinner animation
	if status == StepInProgress {
		r.inProgressStepIdx = index
	} else if r.inProgressStepIdx == index {
		r.inProgressStepIdx = -1
	}
}

// SetTokenInfo sets the token information
func (r *FlowRenderer) SetTokenInfo(storage *TokenStorage) {
	r.contentDirty = true
	r.model.SetTokenInfo(storage)
}

// SetDeviceCode sets the device code information
func (r *FlowRenderer) SetDeviceCode(userCode, verificationURI, verificationURIComplete string) {
	r.contentDirty = true
	r.deviceUserCode = userCode
	r.deviceVerificationURI = verificationURI
	r.deviceVerificationURIComplete = verificationURIComplete
	r.showDeviceCode = true
}

// NextSpinner advances the spinner animation and returns the current frame
func (r *FlowRenderer) NextSpinner() string {
	r.spinnerFrame = (r.spinnerFrame + 1) % len(r.spinnerChars)
	spinnerStyle := lipgloss.NewStyle().Foreground(colorPrimary)
	return spinnerStyle.Render(string(r.spinnerChars[r.spinnerFrame]))
}

// RenderHeader renders and prints the header
func (r *FlowRenderer) RenderHeader() {
	// Clear screen and move to top
	fmt.Print(ansiClearScreen)

	var b strings.Builder

	b.WriteString(
		renderHeaderBox(r.model.flowType, r.model.clientMode, r.model.serverURL, r.model.width),
	)
	b.WriteString("\n\n")

	// Warnings
	if len(r.model.warnings) > 0 {
		b.WriteString(renderWarningList(r.model.warnings))
		b.WriteString("\n")
	}

	header := b.String()
	r.headerLines = strings.Count(header, "\n") + 1
	fmt.Print(header)
}

// resizeCheckInterval limits how often we call getTerminalSize (a syscall).
const resizeCheckInterval = 500 * time.Millisecond

// checkResize detects terminal size changes and marks content dirty so the
// next full redraw uses the new dimensions. The syscall is throttled to at
// most once per resizeCheckInterval. Returns true when the size changed.
func (r *FlowRenderer) checkResize() bool {
	now := time.Now()
	if now.Sub(r.lastResizeCheck) < resizeCheckInterval {
		return false
	}
	r.lastResizeCheck = now

	w, h := getTerminalSize()
	if w == r.model.width && h == r.model.height {
		return false
	}
	r.model.width = w
	r.model.height = h
	r.contentDirty = true
	return true
}

// UpdateDisplay updates the display with current state
func (r *FlowRenderer) UpdateDisplay() {
	// Detect terminal resize — promotes to a full redraw when size changed.
	resized := r.checkResize()

	// If only spinner changed (not content), do a minimal update
	if !r.contentDirty && r.inProgressStepIdx >= 0 {
		r.updateSpinnerOnly()
		return
	}

	// Skip if nothing changed
	if !r.contentDirty {
		return
	}

	// Re-render header when the terminal was resized so widths stay in sync.
	if resized {
		r.RenderHeader()
	}

	// Build current content
	var b strings.Builder

	// Steps
	if len(r.model.steps) > 0 {
		inProgressIcon := string(r.spinnerChars[r.spinnerFrame])
		b.WriteString(renderStepList(r.model.steps, inProgressIcon))
		b.WriteString("\n")
	}

	// Device code info (for device flow)
	if r.showDeviceCode {
		b.WriteString(r.renderDeviceCodeInfo())
		b.WriteString("\n")
	}

	// Token info
	if r.model.showToken && r.model.tokenStorage != nil {
		b.WriteString(renderTokenInfoBox(r.model.tokenStorage, r.model.width))
		b.WriteString("\n")
	}

	currentContent := b.String()

	// Move to position after header
	fmt.Printf("\033[%d;0H", r.headerLines)
	// Clear from cursor to end of screen
	fmt.Print(ansiClearToEnd)

	// Print new content
	fmt.Print(currentContent)

	r.contentDirty = false
}

// updateSpinnerOnly updates only the spinner character without redrawing everything
func (r *FlowRenderer) updateSpinnerOnly() {
	if r.inProgressStepIdx < 0 {
		return
	}

	// Calculate the line number for the in-progress step
	stepLine := r.headerLines + r.inProgressStepIdx

	// Render the spinner character
	spinnerStyle := lipgloss.NewStyle().Foreground(colorPrimary)
	spinnerChar := spinnerStyle.Render(string(r.spinnerChars[r.spinnerFrame]))

	// Move cursor to the spinner position (after "  ")
	fmt.Printf("\033[%d;3H", stepLine)
	// Print just the spinner character
	fmt.Print(spinnerChar)
	// Move cursor back to end (to avoid cursor showing)
	fmt.Print(ansiHideCursor)
}

// renderDeviceCodeInfo renders the device code information box
func (r *FlowRenderer) renderDeviceCodeInfo() string {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorInfo).
		Padding(1, 2).
		Width(min(r.model.width-4, 80))

	var content strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(colorInfo)
	content.WriteString(titleStyle.Render("Device Authorization"))
	content.WriteString("\n\n")

	// User Code - Make it very prominent
	userCodeLabelStyle := lipgloss.NewStyle().
		Foreground(colorInfo).
		Bold(true)
	userCodeStyle := lipgloss.NewStyle().
		Foreground(colorBright).
		Bold(true).
		Background(lipgloss.Color("#1a1a1a")).
		Padding(0, 1)

	content.WriteString(userCodeLabelStyle.Render("User Code: "))
	content.WriteString(userCodeStyle.Render(r.deviceUserCode))
	content.WriteString("\n\n")

	// URL styles
	urlLabelStyle := lipgloss.NewStyle().
		Foreground(colorInfo).
		Bold(true)
	urlStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#29B6F6")).
		Underline(true)

	// Show complete URL if available (with user_code parameter)
	if r.deviceVerificationURIComplete != "" {
		content.WriteString(urlLabelStyle.Render("Complete URL (click to open): "))
		content.WriteString("\n")
		content.WriteString(urlStyle.Render(r.deviceVerificationURIComplete))
		content.WriteString("\n\n")

		// Also show basic URL as fallback
		content.WriteString(urlLabelStyle.Render("Or visit: "))
		content.WriteString(urlStyle.Render(r.deviceVerificationURI))
		content.WriteString("\n")
		content.WriteString(
			lipgloss.NewStyle().Foreground(colorSubtle).Render(
				"(and enter code: " + r.deviceUserCode + ")",
			),
		)
	} else {
		// Only basic URL available
		content.WriteString(urlLabelStyle.Render("URL: "))
		content.WriteString(urlStyle.Render(r.deviceVerificationURI))
		content.WriteString("\n\n")

		// Instructions
		instructionStyle := lipgloss.NewStyle().
			Foreground(colorSubtle).
			Italic(true)
		content.WriteString(
			instructionStyle.Render(
				"Visit the URL above and enter the user code to authorize this device.",
			),
		)
	}

	return boxStyle.Render(content.String())
}
