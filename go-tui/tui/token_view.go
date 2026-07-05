package tui

import (
	"strings"
)

// formatStorageLocation returns a human-readable storage location from the backend string.
// The backend string is in the form "keyring: <service>" or "file: <path>".
func formatStorageLocation(backend string) string {
	if service, ok := strings.CutPrefix(backend, "keyring:"); ok {
		return "OS keyring (service: " + strings.TrimSpace(service) + ")"
	}
	if path, ok := strings.CutPrefix(backend, "file:"); ok {
		return strings.TrimSpace(path)
	}
	if backend != "" {
		return backend
	}
	return ".signet-tokens.json"
}
