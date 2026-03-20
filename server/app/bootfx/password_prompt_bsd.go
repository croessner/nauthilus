//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package bootfx

import "golang.org/x/sys/unix"

const (
	passwordPromptReadTermiosRequest  = unix.TIOCGETA
	passwordPromptWriteTermiosRequest = unix.TIOCSETA
)
