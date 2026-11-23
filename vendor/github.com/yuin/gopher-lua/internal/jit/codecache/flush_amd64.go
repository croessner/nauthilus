//go:build (linux || darwin) && amd64

package codecache

// flushICache is a no-op on x86-64, whose instruction cache is coherent.
func flushICache(addr, size uintptr) {}
