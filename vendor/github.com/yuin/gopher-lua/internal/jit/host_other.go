//go:build !((linux || darwin) && (amd64 || arm64))

package jit

// HostSupported reports whether native code generation is available for
// the machine the program runs on.
func HostSupported() bool { return false }

// NewHostAsm returns nil on platforms without a native backend.
func NewHostAsm() MacroAsm { return nil }
