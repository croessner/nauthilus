//go:build (linux || darwin) && arm64

package codecache

// flushICache makes freshly written code visible to instruction fetch.
// AArch64 has separate instruction and data caches that are not kept
// coherent automatically.
func flushICache(addr, size uintptr) {
	flushICacheASM(addr, addr+size, dataCacheLine, instCacheLine)
}

//go:noescape
func flushICacheASM(start, end, dline, iline uintptr)
