package main

import (
	"strings"
	"testing"
	"time"

	"github.com/go-signet/sdk-go/credstore"
)

func TestNewTokenStore(t *testing.T) {
	tmpFile := t.TempDir() + "/tokens.json"

	tests := []struct {
		name      string
		mode      string
		wantType  string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "file mode returns FileStore",
			mode:     "file",
			wantType: "*credstore.FileStore[credstore.Token]",
		},
		{
			name:     "keyring mode returns EncryptedFileStore",
			mode:     "keyring",
			wantType: "*credstore.EncryptedFileStore[credstore.Token]",
		},
		{
			name:     "auto mode returns SecureStore",
			mode:     "auto",
			wantType: "*credstore.SecureStore[credstore.Token]",
		},
		{
			name:      "invalid mode returns error",
			mode:      "invalid",
			wantErr:   true,
			errSubstr: "invalid token store mode",
		},
		{
			name:      "empty mode returns error",
			mode:      "",
			wantErr:   true,
			errSubstr: "invalid token store mode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := newTokenStore(tc.mode, tmpFile, "test-service")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q should contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var gotType string
			switch store.(type) {
			case *credstore.FileStore[credstore.Token]:
				gotType = "*credstore.FileStore[credstore.Token]"
			case *credstore.EncryptedFileStore[credstore.Token]:
				gotType = "*credstore.EncryptedFileStore[credstore.Token]"
			case *credstore.SecureStore[credstore.Token]:
				gotType = "*credstore.SecureStore[credstore.Token]"
			default:
				gotType = "unknown"
			}
			if gotType != tc.wantType {
				t.Errorf("got type %s, want %s", gotType, tc.wantType)
			}
		})
	}
}

func TestGetDurationConfig(t *testing.T) {
	tests := []struct {
		name   string
		flag   string
		envVal string
		def    time.Duration
		want   time.Duration
	}{
		{"default when empty", "", "", 10 * time.Second, 10 * time.Second},
		{"flag value", "30s", "", 10 * time.Second, 30 * time.Second},
		{"env value", "", "1m", 10 * time.Second, 1 * time.Minute},
		{"flag takes precedence over env", "5s", "1m", 10 * time.Second, 5 * time.Second},
		{"invalid falls back to default", "notaduration", "", 10 * time.Second, 10 * time.Second},
		{"negative falls back to default", "-5s", "", 10 * time.Second, 10 * time.Second},
		{"zero falls back to default", "0s", "", 10 * time.Second, 10 * time.Second},
		{"exceeds max capped", "20m", "", 10 * time.Second, maxDurationConfig},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envVal != "" {
				t.Setenv("TEST_DUR_CFG", tc.envVal)
			} else {
				t.Setenv("TEST_DUR_CFG", "")
			}
			got := getDurationConfig(tc.flag, "TEST_DUR_CFG", tc.def)
			if got != tc.want {
				t.Errorf("getDurationConfig() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRefreshThresholdConfig(t *testing.T) {
	if defaultRefreshThreshold != 5*time.Minute {
		t.Errorf("defaultRefreshThreshold = %v, want 5m", defaultRefreshThreshold)
	}

	t.Run("default when unset", func(t *testing.T) {
		t.Setenv("REFRESH_THRESHOLD", "")
		got := getRefreshThresholdConfig("")
		if got != defaultRefreshThreshold {
			t.Errorf("got %v, want %v", got, defaultRefreshThreshold)
		}
	})

	t.Run("env override", func(t *testing.T) {
		t.Setenv("REFRESH_THRESHOLD", "10m")
		got := getRefreshThresholdConfig("")
		if got != 10*time.Minute {
			t.Errorf("got %v, want 10m", got)
		}
	})

	t.Run("flag takes precedence over env", func(t *testing.T) {
		t.Setenv("REFRESH_THRESHOLD", "10m")
		got := getRefreshThresholdConfig("30s")
		if got != 30*time.Second {
			t.Errorf("got %v, want 30s", got)
		}
	})

	t.Run("not capped at maxDurationConfig", func(t *testing.T) {
		// Unlike timeouts, a threshold above 10m is legitimate and must not be
		// capped (it only makes the CLI refresh sooner).
		t.Setenv("REFRESH_THRESHOLD", "1h")
		got := getRefreshThresholdConfig("")
		if got != time.Hour {
			t.Errorf("got %v, want 1h (uncapped)", got)
		}
	})

	t.Run("invalid falls back to default", func(t *testing.T) {
		t.Setenv("REFRESH_THRESHOLD", "")
		got := getRefreshThresholdConfig("nonsense")
		if got != defaultRefreshThreshold {
			t.Errorf("got %v, want default %v", got, defaultRefreshThreshold)
		}
	})
}

func TestGetInt64Config(t *testing.T) {
	tests := []struct {
		name   string
		flag   string
		envVal string
		def    int64
		want   int64
	}{
		{"default when empty", "", "", 1024, 1024},
		{"flag value", "2048", "", 1024, 2048},
		{"env value", "", "4096", 1024, 4096},
		{"flag takes precedence", "512", "4096", 1024, 512},
		{"invalid falls back to default", "abc", "", 1024, 1024},
		{"negative falls back to default", "-100", "", 1024, 1024},
		{"zero falls back to default", "0", "", 1024, 1024},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envVal != "" {
				t.Setenv("TEST_INT_CFG", tc.envVal)
			} else {
				t.Setenv("TEST_INT_CFG", "")
			}
			got := getInt64Config(tc.flag, "TEST_INT_CFG", tc.def)
			if got != tc.want {
				t.Errorf("getInt64Config() = %v, want %v", got, tc.want)
			}
		})
	}
}
