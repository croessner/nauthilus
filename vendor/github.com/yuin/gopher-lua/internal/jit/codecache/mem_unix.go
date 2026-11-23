//go:build (linux || darwin) && (amd64 || arm64)

package codecache

import (
	"errors"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// Supported reports whether native code can be executed on this platform.
const Supported = true

// Block is a region of executable memory holding one piece of code.
type Block struct {
	mem  []byte
	size int
}

var (
	liveBytes  atomic.Int64
	liveBlocks atomic.Int64
)

// pageSize is the allocation granularity of executable memory.
var pageSize = syscall.Getpagesize()

// MappedSize returns the number of bytes Alloc maps for n bytes of code.
func MappedSize(n int) int {
	return (n + pageSize - 1) &^ (pageSize - 1)
}

// Alloc copies code into freshly mapped memory and makes it executable.
// The memory is writable only while it is being filled (W^X).
func Alloc(code []byte) (*Block, error) {
	if len(code) == 0 {
		return nil, errors.New("codecache: empty code")
	}
	size := MappedSize(len(code))

	mem, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	copy(mem, code)
	if err := syscall.Mprotect(mem, syscall.PROT_READ|syscall.PROT_EXEC); err != nil {
		_ = syscall.Munmap(mem)
		return nil, err
	}
	flushICache(uintptr(unsafe.Pointer(&mem[0])), uintptr(len(code)))
	liveBytes.Add(int64(size))
	liveBlocks.Add(1)
	return &Block{mem: mem, size: size}, nil
}

// Addr returns the address of the first byte of the block.
func (b *Block) Addr() uintptr {
	return uintptr(unsafe.Pointer(&b.mem[0]))
}

// Size returns the number of bytes mapped for the block.
func (b *Block) Size() int { return b.size }

// Free unmaps the block. The code must not be executing or be entered
// again.
func (b *Block) Free() error {
	if b.mem == nil {
		return nil
	}
	mem := b.mem
	b.mem = nil
	liveBytes.Add(-int64(b.size))
	liveBlocks.Add(-1)
	return syscall.Munmap(mem)
}

// LiveBytes returns the number of bytes of executable memory currently
// mapped by this package in the whole process.
func LiveBytes() int64 { return liveBytes.Load() }

// LiveBlocks returns the number of live blocks in the whole process.
func LiveBlocks() int64 { return liveBlocks.Load() }

// Call enters native code at entry with ctx in the context register
// (R15 on amd64, R19 on arm64) and returns when the code executes its
// return instruction. See the package documentation for the rules the
// code must follow.
func Call(entry uintptr, ctx unsafe.Pointer) {
	callJIT(entry, ctx)
}

//go:noescape
func callJIT(entry uintptr, ctx unsafe.Pointer)
