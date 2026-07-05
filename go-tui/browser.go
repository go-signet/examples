package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

// browserCommand returns the executable name and arguments for opening a URL
// on the given OS. This is extracted for testability.
func browserCommand(goos, url string) (name string, args []string) {
	switch goos {
	case "darwin":
		return "open", []string{url}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return "xdg-open", []string{url}
	}
}

// openBrowser attempts to open url in the user's default browser.
// Returns an error if launching the browser fails, but callers should
// always print the URL as a fallback regardless of the error.
func openBrowser(ctx context.Context, url string) error {
	name, args := browserCommand(runtime.GOOS, url)
	cmd := exec.CommandContext(ctx, name, args...)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}

	// Detach — we don't wait for the browser to close.
	go func() { _ = cmd.Wait() }()

	return nil
}
