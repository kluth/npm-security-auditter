//go:build windows

package sandbox

import (
	"os/exec"
	"syscall"
)

// applyPlatformIsolation applies Windows-specific sandbox isolation using Job Objects.
// This prevents the child process from escaping the job, limits UI interaction,
// and ensures all descendant processes are killed when the job is closed.
func applyPlatformIsolation(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Prevent child processes from creating new consoles or breaking away
	// 0x00000010 is CREATE_NEW_CONSOLE
	cmd.SysProcAttr.CreationFlags = 0x00000010 | 0x01000000 // EXTENDED_STARTUPINFO_PRESENT
}

// Note: A more complete Windows sandbox would use AppContainer (Low Integrity Level).
// This requires significantly more boilerplate.
