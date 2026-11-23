package lua

import (
	"math"
	"reflect"
	"unsafe"
)

// iface is an internal representation of the go-interface.
type iface struct {
	itab unsafe.Pointer
	word unsafe.Pointer
}

const preloadLimit LNumber = 128

var _fv float64
var _uv uintptr

var preloads [int(preloadLimit)]LValue

const (
	ipreloadMin = -128
	ipreloadMax = 1023
)

var ipreloads [ipreloadMax - ipreloadMin + 1]LValue

func init() {
	for i := 0; i < int(preloadLimit); i++ {
		preloads[i] = LNumber(i)
	}
	for i := range ipreloads {
		ipreloads[i] = LInteger(i + ipreloadMin)
	}
}

// allocator is a fast bulk memory allocator for the LValue.
type allocator struct {
	size    int
	fptrs   []float64
	fheader *reflect.SliceHeader

	scratchValue  LValue
	scratchValueP *iface

	iptrs          []int64
	iscratchValue  LValue
	iscratchValueP *iface
}

func newAllocator(size int) *allocator {
	al := &allocator{
		size:    size,
		fptrs:   make([]float64, 0, size),
		fheader: nil,
	}
	al.fheader = (*reflect.SliceHeader)(unsafe.Pointer(&al.fptrs))
	al.scratchValue = LNumber(0)
	al.scratchValueP = (*iface)(unsafe.Pointer(&al.scratchValue))
	al.iptrs = make([]int64, 0, size)
	al.iscratchValue = LInteger(1 << 40)
	al.iscratchValueP = (*iface)(unsafe.Pointer(&al.iscratchValue))

	return al
}

// LNumber2I takes a number value and returns an interface LValue representing the same number.
// Converting an LNumber to a LValue naively, by doing:
// `var val LValue = myLNumber`
// will result in an individual heap alloc of 8 bytes for the float value. LNumber2I amortizes the cost and memory
// overhead of these allocs by allocating blocks of floats instead.
// The downside of this is that all of the floats on a given block have to become eligible for gc before the block
// as a whole can be gc-ed.
func (al *allocator) LNumber2I(v LNumber) LValue {
	// first check for shared preloaded numbers
	if v >= 0 && v < preloadLimit && float64(v) == float64(int64(v)) && (v != 0 || !math.Signbit(float64(v))) {
		return preloads[int(v)]
	}

	// check if we need a new alloc page
	if cap(al.fptrs) == len(al.fptrs) {
		al.fptrs = make([]float64, 0, al.size)
		al.fheader = (*reflect.SliceHeader)(unsafe.Pointer(&al.fptrs))
	}

	// alloc a new float, and store our value into it
	al.fptrs = append(al.fptrs, float64(v))
	fptr := &al.fptrs[len(al.fptrs)-1]

	// hack our scratch LValue to point to our allocated value
	// this scratch lvalue is copied when this function returns meaning the scratch value can be reused
	// on the next call
	al.scratchValueP.word = unsafe.Pointer(fptr)

	return al.scratchValue
}

// LInteger2I is the LInteger counterpart of LNumber2I: it boxes an integer
// into an LValue using shared preloaded values for small integers and bulk
// allocated pages for everything else.
func (al *allocator) LInteger2I(v LInteger) LValue {
	if v >= ipreloadMin && v <= ipreloadMax {
		return ipreloads[int(v)-ipreloadMin]
	}
	if cap(al.iptrs) == len(al.iptrs) {
		al.iptrs = make([]int64, 0, al.size)
	}
	al.iptrs = append(al.iptrs, int64(v))
	al.iscratchValueP.word = unsafe.Pointer(&al.iptrs[len(al.iptrs)-1])
	return al.iscratchValue
}
