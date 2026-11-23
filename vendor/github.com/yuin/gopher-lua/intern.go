package lua

import "sync"

// String constants of compiled chunks are interned: equal constants of
// different functions share one string, so that JIT compiled code can
// recognize a table key by the address of its bytes. Interning is only
// an optimization; the table is bounded and long strings are left alone.

const (
	// maxInternedStrings bounds the intern table, which is never emptied.
	maxInternedStrings = 1 << 16
	// maxInternedLen is the length up to which constants are interned
	// (identifiers used as field names are short).
	maxInternedLen = 48
)

var internedStrings = struct {
	sync.RWMutex
	m map[string]string
}{m: make(map[string]string)}

// internConstant returns the canonical copy of the string constant s.
func internConstant(s string) string {
	if len(s) == 0 || len(s) > maxInternedLen {
		return s
	}
	internedStrings.RLock()
	c, ok := internedStrings.m[s]
	internedStrings.RUnlock()
	if ok {
		return c
	}
	internedStrings.Lock()
	defer internedStrings.Unlock()
	if c, ok := internedStrings.m[s]; ok {
		return c
	}
	if len(internedStrings.m) < maxInternedStrings {
		internedStrings.m[s] = s
	}
	return s
}
