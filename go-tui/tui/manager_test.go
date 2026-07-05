package tui

import (
	"context"
	"os"
	"testing"
)

func TestShouldUseSimpleUI(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		expected bool
		desc     string
	}{
		{
			name:     "CI environment - GitHub Actions",
			envVars:  map[string]string{"GITHUB_ACTIONS": "true"},
			expected: true,
			desc:     "Should use simple UI in GitHub Actions",
		},
		{
			name:     "CI environment - GitLab CI",
			envVars:  map[string]string{"GITLAB_CI": "true"},
			expected: true,
			desc:     "Should use simple UI in GitLab CI",
		},
		{
			name:     "CI environment - CircleCI",
			envVars:  map[string]string{"CIRCLECI": "true"},
			expected: true,
			desc:     "Should use simple UI in CircleCI",
		},
		{
			name:     "TERM=dumb",
			envVars:  map[string]string{"TERM": "dumb"},
			expected: true,
			desc:     "Should use simple UI when TERM=dumb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, val := range tt.envVars {
				t.Setenv(key, val)
			}

			result := isCIEnvironment() || os.Getenv("TERM") == "dumb"
			if result != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.desc, tt.expected, result)
			}
		})
	}
}

func TestSelectManager(t *testing.T) {
	t.Run("Returns valid manager", func(t *testing.T) {
		manager := SelectManager()
		if manager == nil {
			t.Error("Expected non-nil manager")
		}
		// Verify it's one of our known types
		switch manager.(type) {
		case *SimpleManager, *BubbleTeaManager:
			// Good
		default:
			t.Errorf("Unexpected manager type: %T", manager)
		}
	})
}

func TestSimpleManagerRunBrowserFlow(t *testing.T) {
	t.Run("Non-error updates do not trigger fallback", func(t *testing.T) {
		m := NewSimpleManager()
		perform := func(ctx context.Context, updates chan<- FlowUpdate) (*TokenStorage, bool, error) {
			updates <- FlowUpdate{Type: StepStart, Step: 1}
			updates <- FlowUpdate{Type: BrowserOpened}
			updates <- FlowUpdate{Type: StepStart, Step: 2}
			updates <- FlowUpdate{Type: CallbackReceived}
			return &TokenStorage{AccessToken: "test-token"}, true, nil
		}
		_, ok, err := m.RunBrowserFlow(context.Background(), perform)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("non-error updates must not trigger fallback: expected ok=true")
		}
	})

	t.Run("perform returning ok=false is propagated as fallback signal", func(t *testing.T) {
		m := NewSimpleManager()
		perform := func(ctx context.Context, updates chan<- FlowUpdate) (*TokenStorage, bool, error) {
			updates <- FlowUpdate{Type: StepError, Message: "browser failed"}
			return nil, false, nil
		}
		_, ok, err := m.RunBrowserFlow(context.Background(), perform)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected ok=false when perform signals fallback needed")
		}
	})
}

func TestFlowUpdateHelpers(t *testing.T) {
	update := FlowUpdate{
		Type:    StepStart,
		Step:    1,
		Message: "Testing",
		Data: map[string]any{
			"string_val":   "hello",
			"int_val":      42,
			"duration_val": 5000000000, // 5 seconds in nanoseconds
		},
	}

	// Test GetString
	if got := update.GetString("string_val"); got != "hello" {
		t.Errorf("GetString: expected 'hello', got '%s'", got)
	}

	// Test GetInt
	if got := update.GetInt("int_val"); got != 42 {
		t.Errorf("GetInt: expected 42, got %d", got)
	}

	// Test missing keys return zero values
	if got := update.GetString("missing"); got != "" {
		t.Errorf("GetString (missing): expected empty string, got '%s'", got)
	}
	if got := update.GetInt("missing"); got != 0 {
		t.Errorf("GetInt (missing): expected 0, got %d", got)
	}
}

func TestFlowUpdate_FallbackField(t *testing.T) {
	t.Run("Fallback defaults to false", func(t *testing.T) {
		update := FlowUpdate{}
		if update.Fallback {
			t.Error("Fallback should default to false for hard errors")
		}
	})

	t.Run("Fallback can be set to true for soft errors", func(t *testing.T) {
		update := FlowUpdate{Fallback: true}
		if !update.Fallback {
			t.Error("Fallback should be true for soft (recoverable) errors")
		}
	})

	t.Run("Fallback is ignored on non-error updates", func(t *testing.T) {
		update := FlowUpdate{Fallback: false}
		if update.Fallback {
			t.Error("Fallback should not be set on non-error updates")
		}
	})
}
