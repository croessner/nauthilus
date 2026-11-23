// Package codecache manages executable memory for JIT compiled code and
// provides the trampoline used to enter it from Go.
//
// # Runtime safety contract
//
// Native code entered through Call runs on the calling goroutine's stack
// inside the frame of an assembly trampoline. To stay compatible with the
// Go runtime it must obey the following rules (the JIT backends are
// written to satisfy them):
//
//   - It never moves the stack pointer and never uses stack memory, so no
//     stack growth check is needed and the goroutine stack layout stays
//     exactly as the runtime expects.
//   - It never calls Go functions. Everything that needs the Go runtime
//     (allocation, write barriers, table growth, calls, errors) is done by
//     returning to Go with an exit code.
//   - It never writes pointers into Go heap memory and never keeps the
//     only reference to a Go object: it may only read Go memory that is
//     kept alive by GC-visible roots for the duration of the call, and it
//     may write non-pointer words. No write barriers are therefore needed.
//   - It preserves the registers the Go runtime relies on while a signal
//     may arrive: the stack pointer, the frame pointer, the g register
//     (R14 on amd64, R28 on arm64), the platform register (R18 on arm64)
//     and the link register on arm64.
//   - It returns to Go in bounded time (compiled loops count down a fuel
//     counter), because a goroutine executing native code cannot be
//     preempted asynchronously and would otherwise delay stop-the-world
//     phases of the garbage collector.
//
// Memory is mapped read/write, filled, and then switched to read/execute
// (W^X); it is never writable and executable at the same time. A block is
// never modified after it became executable.
package codecache
