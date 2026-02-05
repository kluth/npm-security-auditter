//go:build !linux && !windows

package sandbox

import "os/exec"

func applyPlatformIsolation(cmd *exec.Cmd) {
	// No deep isolation implemented yet for this platform
}
