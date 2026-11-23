//go:build linux || darwin

#include "textflag.h"

// func callJIT(entry uintptr, ctx unsafe.Pointer)
//
// The native code is entered with BLR and returns with RET (to R30). It
// preserves R18, R28, R29, R30 and SP. The assembler generated prologue
// and epilogue save and restore the link register of this function.
TEXT ·callJIT(SB), NOSPLIT, $16-16
	MOVD entry+0(FP), R0
	MOVD ctx+8(FP), R19
	CALL (R0)
	RET

// func flushICacheASM(start, end, dline, iline uintptr)
//
// Synchronizes the instruction cache with the data cache for the address
// range [start, end): DC CVAU for every data cache line of dline bytes
// and IC IVAU for every instruction cache line of iline bytes (both
// powers of two), followed by the required barriers.
TEXT ·flushICacheASM(SB), NOSPLIT, $0-32
	MOVD start+0(FP), R0
	MOVD end+8(FP), R1
	MOVD dline+16(FP), R2
	SUB  $1, R2, R3
	BIC  R3, R0, R4
dloop:
	WORD $0xd50b7b24     // dc cvau, x4
	ADD  R2, R4
	CMP  R1, R4
	BLO  dloop
	WORD $0xd5033b9f     // dsb ish
	MOVD iline+24(FP), R2
	SUB  $1, R2, R3
	BIC  R3, R0, R4
iloop:
	WORD $0xd50b7524     // ic ivau, x4
	ADD  R2, R4
	CMP  R1, R4
	BLO  iloop
	WORD $0xd5033b9f     // dsb ish
	WORD $0xd5033fdf     // isb
	RET
