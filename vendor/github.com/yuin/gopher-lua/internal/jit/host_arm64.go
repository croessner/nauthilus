//go:build (linux || darwin) && arm64

package jit

// HostSupported reports whether native code generation is available for
// the machine the program runs on.
func HostSupported() bool { return true }

// NewHostAsm returns a macro assembler for the host architecture.
func NewHostAsm() MacroAsm { return NewARM64() }
