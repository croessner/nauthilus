//go:build (linux || darwin) && amd64

package jit

// cpuid executes the CPUID instruction.
func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// hasSSE41 reports whether the CPU supports SSE4.1 (ROUNDSD).
var hasSSE41 = func() bool {
	_, _, ecx, _ := cpuid(1, 0)
	return ecx&(1<<19) != 0
}()

// HostSupported reports whether native code generation is available for
// the machine the program runs on.
func HostSupported() bool { return hasSSE41 }

// NewHostAsm returns a macro assembler for the host architecture.
func NewHostAsm() MacroAsm { return NewAMD64() }
