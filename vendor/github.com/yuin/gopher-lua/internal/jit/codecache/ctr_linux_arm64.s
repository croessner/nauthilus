#include "textflag.h"

// func readCTR() uint64
TEXT ·readCTR(SB), NOSPLIT, $0-8
	MRS  CTR_EL0, R0
	MOVD R0, ret+0(FP)
	RET
