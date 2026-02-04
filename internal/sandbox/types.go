package sandbox

// HarnessOutput is the JSON schema emitted by the Node.js harness script.
type HarnessOutput struct {
	Success      bool              `json:"success"`
	Error        string            `json:"error,omitempty"`
	LoadPhase    PhaseResult       `json:"loadPhase"`
	InstallPhase PhaseResult       `json:"installPhase"`
	Intercepted  InterceptedCalls  `json:"intercepted"`
	Environment  EnvironmentInfo   `json:"environment"`
}

// PhaseResult reports the outcome of a phase (install, load).
type PhaseResult struct {
	Completed bool   `json:"completed"`
	Error     string `json:"error,omitempty"`
	Duration  int    `json:"duration"` // milliseconds
}

// InterceptedCalls holds all calls intercepted by the harness.
type InterceptedCalls struct {
	ChildProcess []CallRecord `json:"childProcess"`
	FileSystem   []CallRecord `json:"fileSystem"`
	Network      []CallRecord `json:"network"`
	DNS          []CallRecord `json:"dns"`
	Crypto       []CallRecord `json:"crypto"`
	ProcessEnv   []CallRecord `json:"processEnv"`
	OS           []CallRecord `json:"os"`
}

// CallRecord represents a single intercepted call.
type CallRecord struct {
	Method    string   `json:"method"`
	Args      []string `json:"args"`
	Timestamp string   `json:"timestamp"`
	Stack     string   `json:"stack,omitempty"`
}

// EnvironmentInfo captures what the package observed about its environment.
type EnvironmentInfo struct {
	NodeVersion string `json:"nodeVersion"`
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
}
