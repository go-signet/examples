package main

import "testing"

func TestBrowserCommand(t *testing.T) {
	tests := []struct {
		goos     string
		url      string
		wantName string
		wantArgs []string
	}{
		{
			goos:     "darwin",
			url:      "https://example.com/auth",
			wantName: "open",
			wantArgs: []string{"https://example.com/auth"},
		},
		{
			goos:     "windows",
			url:      "https://example.com/auth",
			wantName: "rundll32",
			wantArgs: []string{"url.dll,FileProtocolHandler", "https://example.com/auth"},
		},
		{
			goos:     "linux",
			url:      "https://example.com/auth",
			wantName: "xdg-open",
			wantArgs: []string{"https://example.com/auth"},
		},
		{
			goos:     "windows",
			url:      "https://example.com/auth?foo=bar&baz=qux",
			wantName: "rundll32",
			wantArgs: []string{
				"url.dll,FileProtocolHandler",
				"https://example.com/auth?foo=bar&baz=qux",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			name, args := browserCommand(tt.goos, tt.url)
			if name != tt.wantName {
				t.Errorf("name: got %q, want %q", name, tt.wantName)
			}
			if len(args) != len(tt.wantArgs) {
				t.Fatalf("args length: got %d, want %d", len(args), len(tt.wantArgs))
			}
			for i, arg := range args {
				if arg != tt.wantArgs[i] {
					t.Errorf("args[%d]: got %q, want %q", i, arg, tt.wantArgs[i])
				}
			}
		})
	}
}
