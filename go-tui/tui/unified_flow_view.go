package tui

// No external imports needed — rendering is handled by FlowRenderer via shared_render.go.

// FlowStepStatus represents the status of a flow step
type FlowStepStatus int

const (
	StepPending FlowStepStatus = iota
	StepInProgress
	StepCompleted
	StepFailed
	StepSkipped
)

// FlowStep represents a single step in the auth flow
type FlowStep struct {
	Name    string
	Status  FlowStepStatus
	Message string // Additional message shown after step name
}

// UnifiedFlowModel is the main model for the unified TUI flow
type UnifiedFlowModel struct {
	// Header info
	flowType   string // "OAuth 2.0 Authorization Code Flow"
	clientMode string // "confidential" or "public"
	serverURL  string

	// Warnings
	warnings []string

	// Steps
	steps []*FlowStep

	// Token info (shown at the end)
	tokenStorage *TokenStorage
	showToken    bool

	// Layout
	width  int
	height int
}

// NewUnifiedFlowModel creates a new unified flow model
func NewUnifiedFlowModel(flowType, clientMode, serverURL string) *UnifiedFlowModel {
	return &UnifiedFlowModel{
		flowType:   flowType,
		clientMode: clientMode,
		serverURL:  serverURL,
		warnings:   []string{},
		steps:      []*FlowStep{},
		width:      80,
		height:     24,
	}
}

// AddWarning adds a warning message
func (m *UnifiedFlowModel) AddWarning(warning string) {
	m.warnings = append(m.warnings, warning)
}

// AddStep adds a new step to the flow
func (m *UnifiedFlowModel) AddStep(name string) int {
	step := &FlowStep{
		Name:   name,
		Status: StepPending,
	}
	m.steps = append(m.steps, step)
	return len(m.steps) - 1
}

// UpdateStep updates a step's status and message
func (m *UnifiedFlowModel) UpdateStep(index int, status FlowStepStatus, message string) {
	if index >= 0 && index < len(m.steps) {
		m.steps[index].Status = status
		m.steps[index].Message = message
	}
}

// SetTokenInfo sets the token information to display
func (m *UnifiedFlowModel) SetTokenInfo(storage *TokenStorage) {
	m.tokenStorage = storage
	m.showToken = true
}
