package codecache

// Cache line sizes in bytes, taken from the cache type register.
var dataCacheLine, instCacheLine = cacheLineSizes(readCTR())

// cacheLineSizes decodes the minimum data and instruction cache line
// sizes from a CTR_EL0 value (DminLine and IminLine hold the binary
// logarithm of the size in four-byte words).
func cacheLineSizes(ctr uint64) (dline, iline uintptr) {
	return 4 << ((ctr >> 16) & 15), 4 << (ctr & 15)
}

// readCTR returns the cache type register CTR_EL0, which Linux makes
// readable for user space.
func readCTR() uint64
