package tui

import "time"

// FlowUpdateType represents the type of progress update from an OAuth flow.
type FlowUpdateType int

const (
	StepStart FlowUpdateType = iota
	StepProgress
	StepComplete
	StepError
	TimerTick          // For countdown/elapsed time updates
	BrowserOpened      // Browser successfully opened
	CallbackReceived   // Callback received from browser
	DeviceCodeReceived // Device code received from server
	PollingUpdate      // Polling status update
	BackoffChanged     // Slow_down interval changed
)

// FlowUpdate represents a progress update message from an OAuth flow.
//
// For StepError updates, the Fallback field distinguishes between two
// classes of failure:
//
//   - Fallback == true  → soft error (browser unavailable, user timeout).
//     The caller should silently retry with the Device Code Flow.
//
//   - Fallback == false → hard error (CSRF mismatch, token exchange failure,
//     OAuth server rejection, etc.).
//     The caller should surface the error to the user and exit.
type FlowUpdate struct {
	Type       FlowUpdateType
	Step       int     // Current step number (1-indexed)
	TotalSteps int     // Total number of steps
	Message    string  // Human-readable message
	Progress   float64 // Progress percentage (0.0 to 1.0)
	// Fallback is only meaningful when Type == StepError.
	// When true, the error is recoverable and the caller should fall back
	// to the Device Code Flow instead of reporting a failure.
	Fallback bool
	Data     map[string]any // Additional data for specific update types
}

// Helper functions to extract data from FlowUpdate.Data

// GetString safely extracts a string value from Data.
func (u *FlowUpdate) GetString(key string) string {
	if u.Data == nil {
		return ""
	}
	if val, ok := u.Data[key].(string); ok {
		return val
	}
	return ""
}

// GetInt safely extracts an int value from Data.
func (u *FlowUpdate) GetInt(key string) int {
	if u.Data == nil {
		return 0
	}
	if val, ok := u.Data[key].(int); ok {
		return val
	}
	return 0
}

// GetDuration safely extracts a time.Duration value from Data.
func (u *FlowUpdate) GetDuration(key string) time.Duration {
	if u.Data == nil {
		return 0
	}
	if val, ok := u.Data[key].(time.Duration); ok {
		return val
	}
	return 0
}
