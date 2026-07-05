package tui

import (
	"fmt"
	"time"

	"charm.land/lipgloss/v2"
)

// Color palette
var (
	// Primary colors
	colorPrimary = lipgloss.Color("#7D56F4")
	colorSuccess = lipgloss.Color("#00C853")
	colorError   = lipgloss.Color("#D32F2F")
	colorWarning = lipgloss.Color("#FFA726")
	colorInfo    = lipgloss.Color("#29B6F6")

	// Neutral colors
	colorSubtle = lipgloss.Color("#888888")
	colorMuted  = lipgloss.Color("#666666")
	colorBright = lipgloss.Color("#FFFFFF")
)

// FormatDurationHuman formats a duration in human-readable format (e.g., "1h 30m", "5m", "30s").
func FormatDurationHuman(d time.Duration) string {
	if d < 0 {
		return "expired"
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours >= 24 {
		days := hours / 24
		hours %= 24
		return fmt.Sprintf("%dd %dh", days, hours)
	}

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}

	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}

	seconds := int(d.Seconds())
	return fmt.Sprintf("%ds", seconds)
}

// maskTokenPreview masks token for preview display (shows first 8 and last 4 chars)
func maskTokenPreview(token string) string {
	if len(token) <= 16 {
		if len(token) <= 8 {
			return token[:min(len(token), 4)] + "..."
		}
		return token[:4] + "..." + token[len(token)-4:]
	}
	return token[:8] + "..." + token[len(token)-4:]
}
