//go:build linux

package sandbox

import (
	"os/exec"
	"syscall"
)

// applyPlatformIsolation applies Linux-specific sandbox isolation.
// It uses User, Mount, Network, and PID namespaces.
func applyPlatformIsolation(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// CLONE_NEWUSER:  Isolate users (allows root-less chroot)
	// CLONE_NEWNS:    Isolate mounts (allows private view of /)
	// CLONE_NEWNET:   Isolate network (prevents data exfiltration)
	// CLONE_NEWPID:   Isolate processes (cannot see host processes)
	// CLONE_NEWUTS:   Isolate hostname
	cmd.SysProcAttr.Unshareflags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS

	// We map the current user to root inside the namespace
	cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      syscall.Getuid(),
			Size:        1,
		},
	}
	cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      syscall.Getgid(),
			Size:        1,
		},
	}
}
