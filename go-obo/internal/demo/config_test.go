package demo

import (
	"strings"
	"testing"
)

func TestSafeURL(t *testing.T) {
	for _, raw := range []string{"https://auth.example.com", "http://127.0.0.1:8090", "http://localhost:8090", "http://[::1]:8090"} {
		if _, err := safeURL(raw); err != nil {
			t.Errorf("valid URL rejected: %s", raw)
		}
	}
	for _, raw := range []string{"", "/relative", "http://auth.example.com", "https://user:secret@auth.example.com", "https://auth.example.com?token=x", "https://auth.example.com?", "https://auth.example.com#", "file:///tmp/example"} {
		if _, err := safeURL(raw); err == nil {
			t.Errorf("unsafe URL accepted: %s", raw)
		}
	}
}

func TestRoleConfiguration(t *testing.T) {
	for _, key := range []string{"WEB_CLIENT_ID", "WEB_CLIENT_SECRET", "CLI_CLIENT_ID", "API_A_CLIENT_ID", "API_A_CLIENT_SECRET", "API_B_CLIENT_ID", "API_B_CLIENT_SECRET", "API_A_AUDIENCE", "API_B_AUDIENCE", "API_A_URL", "API_B_URL", "WEB_REDIRECT_URL", "CLI_CALLBACK_ADDR"} {
		t.Setenv(key, "")
	}
	t.Setenv("SIGNET_URL", "https://auth.example.com")
	t.Setenv("CLI_CLIENT_ID", "cli")
	if _, err := LoadConfig("cli"); err != nil {
		t.Fatal("CLI should not require secrets", err)
	}
	t.Setenv("API_A_CLIENT_SECRET", "do-not-use")
	c, err := LoadConfig("cli")
	if err != nil || c.ASecret != "" {
		t.Fatal("CLI loaded unrelated credentials")
	}
	if _, err := LoadConfig("web"); err == nil {
		t.Fatal("web accepted missing confidential credentials")
	}
	t.Setenv("WEB_CLIENT_ID", "web")
	t.Setenv("WEB_CLIENT_SECRET", "secret")
	if _, err := LoadConfig("web"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLI_CALLBACK_ADDR", "0.0.0.0:8093")
	if _, err := LoadConfig("cli"); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatal("public listener accepted")
	}
	t.Setenv("API_B_AUDIENCE", "https://api-a.example.com")
	if _, err := LoadConfig("web"); err == nil {
		t.Fatal("identical audiences accepted")
	}
}
