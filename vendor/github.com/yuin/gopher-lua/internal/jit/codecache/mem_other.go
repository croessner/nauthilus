//go:build !((linux || darwin) && (amd64 || arm64))

package codecache

import (
	"errors"
	"unsafe"
)

// Supported reports whether native code can be executed on this platform.
const Supported = false

// Block is a region of executable memory holding one piece of code.
type Block struct{}

var errUnsupported = errors.New("codecache: native code is not supported on this platform")

// MappedSize returns the number of bytes Alloc maps for n bytes of code.
func MappedSize(n int) int { return n }

// Alloc always fails on unsupported platforms.
func Alloc(code []byte) (*Block, error) { return nil, errUnsupported }

// Addr returns the address of the first byte of the block.
func (b *Block) Addr() uintptr { return 0 }

// Size returns the number of bytes mapped for the block.
func (b *Block) Size() int { return 0 }

// Free unmaps the block.
func (b *Block) Free() error { return nil }

// LiveBytes returns the number of bytes of executable memory in use.
func LiveBytes() int64 { return 0 }

// LiveBlocks returns the number of live blocks.
func LiveBlocks() int64 { return 0 }

// Call panics on unsupported platforms; callers must check Supported.
func Call(entry uintptr, ctx unsafe.Pointer) {
	panic(errUnsupported)
}
