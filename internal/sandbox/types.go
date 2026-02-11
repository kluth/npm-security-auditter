package sandbox

// HarnessOutput is the JSON schema emitted by the Node.js harness script.
type HarnessOutput struct {
	Success        bool             `json:"success"`
	Error          string           `json:"error,omitempty"`
	HarnessVersion string           `json:"harnessVersion,omitempty"`
	LoadPhase      PhaseResult      `json:"loadPhase"`
	InstallPhase   PhaseResult      `json:"installPhase"`
	Intercepted    InterceptedCalls `json:"intercepted"`
	Environment    EnvironmentInfo  `json:"environment"`
	PatchErrors    []PatchError     `json:"patchErrors,omitempty"`
}

// PhaseResult reports the outcome of a phase (install, load).
type PhaseResult struct {
	Completed bool   `json:"completed"`
	Error     string `json:"error,omitempty"`
	Duration  int    `json:"duration"` // milliseconds
}

// InterceptedCalls holds all calls intercepted by the harness.
// Covers 15+ Node.js core modules for comprehensive behavioral monitoring.
type InterceptedCalls struct {
	ChildProcess []CallRecord `json:"childProcess"` // exec, spawn, fork, etc.
	FileSystem   []CallRecord `json:"fileSystem"`   // fs read/write operations
	Network      []CallRecord `json:"network"`      // http, https, net, http2
	DNS          []CallRecord `json:"dns"`          // DNS lookups
	Crypto       []CallRecord `json:"crypto"`       // Cryptographic operations
	ProcessEnv   []CallRecord `json:"processEnv"`   // Environment variable access
	OS           []CallRecord `json:"os"`           // OS information gathering
	VM           []CallRecord `json:"vm"`           // vm module (sandbox escape risk)
	Worker       []CallRecord `json:"worker"`       // worker_threads (parallel execution)
	Cluster      []CallRecord `json:"cluster"`      // cluster module (process forking)
	Dgram        []CallRecord `json:"dgram"`        // UDP sockets
	TLS          []CallRecord `json:"tls"`          // TLS/SSL connections
	Eval         []CallRecord `json:"eval"`         // eval() and Function constructor
}

// CallRecord represents a single intercepted call.
type CallRecord struct {
	Method    string            `json:"method"`
	Args      []string          `json:"args"`
	Timestamp string            `json:"timestamp"`
	Stack     string            `json:"stack,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"` // Additional context (e.g., operation type)
}

// PatchError records failures when patching modules.
type PatchError struct {
	Module string `json:"module"`
	Error  string `json:"error"`
}

// EnvironmentInfo captures what the package observed about its environment.
type EnvironmentInfo struct {
	NodeVersion string `json:"nodeVersion"`
	Platform    string `json:"platform"`
	Arch        string `json:"arch"`
}

// HasDangerousActivity returns true if any critical security indicators were detected.
func (h *HarnessOutput) HasDangerousActivity() bool {
	return len(h.Intercepted.ChildProcess) > 0 ||
		len(h.Intercepted.Network) > 0 ||
		len(h.Intercepted.DNS) > 0 ||
		len(h.Intercepted.Worker) > 0 ||
		len(h.Intercepted.Cluster) > 0 ||
		len(h.Intercepted.Eval) > 0
}

// TotalInterceptions returns the total count of all intercepted calls.
func (h *HarnessOutput) TotalInterceptions() int {
	return len(h.Intercepted.ChildProcess) +
		len(h.Intercepted.FileSystem) +
		len(h.Intercepted.Network) +
		len(h.Intercepted.DNS) +
		len(h.Intercepted.Crypto) +
		len(h.Intercepted.ProcessEnv) +
		len(h.Intercepted.OS) +
		len(h.Intercepted.VM) +
		len(h.Intercepted.Worker) +
		len(h.Intercepted.Cluster) +
		len(h.Intercepted.Dgram) +
		len(h.Intercepted.TLS) +
		len(h.Intercepted.Eval)
}
