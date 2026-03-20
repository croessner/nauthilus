//go:build linux

package bootfx

import "golang.org/x/sys/unix"

const (
	passwordPromptReadTermiosRequest  = unix.TCGETS
	passwordPromptWriteTermiosRequest = unix.TCSETS
)
