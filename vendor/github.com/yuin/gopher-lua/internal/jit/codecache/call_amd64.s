//go:build linux || darwin

#include "textflag.h"

// func callJIT(entry uintptr, ctx unsafe.Pointer)
//
// The native code is entered with CALL and returns with RET. It does not
// touch SP, BP or R14, so the frame of this function stays intact for the
// whole duration of the call.
TEXT ·callJIT(SB), NOSPLIT, $0-16
	MOVQ entry+0(FP), AX
	MOVQ ctx+8(FP), R15
	CALL AX
	RET
