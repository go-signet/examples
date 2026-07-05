package tui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// renderHeaderBox builds the header box with flow type, client mode, and server URL.
func renderHeaderBox(flowType, clientMode, serverURL string, width int) string {
	headerStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorPrimary).
		Padding(0, 2).
		Width(min(width-4, 70))

	var content strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(colorPrimary)
	content.WriteString(titleStyle.Render(flowType))
	content.WriteString("\n")

	infoStyle := lipgloss.NewStyle().
		Foreground(colorSubtle)
	info := fmt.Sprintf("Mode: %s         Server: %s", clientMode, serverURL)
	content.WriteString(infoStyle.Render(info))

	return headerStyle.Render(content.String())
}

// renderWarningList renders a list of warning messages.
func renderWarningList(warnings []string) string {
	var b strings.Builder

	warningStyle := lipgloss.NewStyle().
		Foreground(colorWarning).
		Bold(true)

	for _, warning := range warnings {
		b.WriteString("  ")
		b.WriteString(warningStyle.Render("WARNING: "))
		b.WriteString(warning)
		b.WriteString("\n")
	}

	return b.String()
}

// renderStepList renders a list of flow steps with the given icon for in-progress steps.
func renderStepList(steps []*FlowStep, inProgressIcon string) string {
	var b strings.Builder

	for _, step := range steps {
		b.WriteString("  ")

		var icon string
		iconStyle := lipgloss.NewStyle()

		switch step.Status {
		case StepCompleted:
			icon = "✓"
			iconStyle = iconStyle.Foreground(colorSuccess).Bold(true)
		case StepFailed:
			icon = "✗"
			iconStyle = iconStyle.Foreground(colorError).Bold(true)
		case StepInProgress:
			icon = inProgressIcon
			iconStyle = iconStyle.Foreground(colorPrimary)
		case StepSkipped:
			icon = "○"
			iconStyle = iconStyle.Foreground(colorSubtle)
		default: // StepPending
			icon = "○"
			iconStyle = iconStyle.Foreground(colorMuted)
		}

		b.WriteString(iconStyle.Render(icon))
		b.WriteString(" ")

		nameStyle := lipgloss.NewStyle()
		if step.Status == StepInProgress {
			nameStyle = nameStyle.Bold(true)
		}
		b.WriteString(nameStyle.Render(step.Name))

		if step.Message != "" {
			messageStyle := lipgloss.NewStyle().
				Foreground(colorSubtle)
			b.WriteString("  ")
			b.WriteString(messageStyle.Render(step.Message))
		}

		b.WriteString("\n")
	}

	return b.String()
}

// renderTokenInfoBox renders the token information box.
func renderTokenInfoBox(storage *TokenStorage, width int) string {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(colorSuccess).
		Padding(1, 2).
		Width(min(width-4, 60))

	var content strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(colorSuccess)
	content.WriteString(titleStyle.Render("Token Info"))
	content.WriteString("\n\n")

	noticeStyle := lipgloss.NewStyle().
		Foreground(colorWarning).
		Italic(true).
		Width(55)
	content.WriteString(noticeStyle.Render(
		"🔒 Full tokens stored in: " + formatStorageLocation(storage.StorageBackend),
	))
	content.WriteString("\n\n")

	labelStyle := lipgloss.NewStyle().
		Foreground(colorInfo).
		Width(18)
	valueStyle := lipgloss.NewStyle().
		Foreground(colorBright)

	content.WriteString(labelStyle.Render("Access Token:"))
	content.WriteString(" ")
	content.WriteString(valueStyle.Render(maskTokenPreview(storage.AccessToken)))
	content.WriteString("\n")

	content.WriteString(labelStyle.Render("Token Type:"))
	content.WriteString(" ")
	content.WriteString(valueStyle.Render(storage.TokenType))
	content.WriteString("\n")

	if !storage.ExpiresAt.IsZero() {
		remaining := time.Until(storage.ExpiresAt)
		content.WriteString(labelStyle.Render("Expires In:"))
		content.WriteString(" ")
		content.WriteString(valueStyle.Render(FormatDurationHuman(remaining)))
	}

	return boxStyle.Render(content.String())
}
