package codecache

// Cache line sizes in bytes. macOS does not let user space read CTR_EL0
// (the access traps), so the sizes are fixed like in the system's own
// sys_icache_invalidate, which steps through the range in 64-byte lines.
// A step smaller than the real line size is harmless.
const (
	dataCacheLine uintptr = 64
	instCacheLine uintptr = 64
)
