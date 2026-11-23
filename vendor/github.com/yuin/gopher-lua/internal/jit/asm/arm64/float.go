package arm64

// Opcodes of the scalar double precision (ftype=01) floating point
// instructions with all operand fields zero.
const (
	opFmovDD  = 0x1E604000 // fmov dd, dn
	opFmovDX  = 0x9E670000 // fmov dd, xn
	opFmovXD  = 0x9E660000 // fmov xd, dn
	opFaddD   = 0x1E602800
	opFsubD   = 0x1E603800
	opFmulD   = 0x1E600800
	opFdivD   = 0x1E601800
	opFsqrtD  = 0x1E61C000
	opFabsD   = 0x1E60C000
	opFnegD   = 0x1E614000
	opFrintmD = 0x1E654000 // round toward minus infinity
	opFrintpD = 0x1E64C000 // round toward plus infinity
	opFrintzD = 0x1E65C000 // round toward zero
	opFcmpD   = 0x1E602000 // fcmp dn, dm
	opScvtfDX = 0x9E620000 // scvtf dd, xn
	opFcvtzsX = 0x9E780000 // fcvtzs xd, dn
	opFcvtmsX = 0x9E700000 // fcvtms xd, dn
)

// FmovDD emits fmov dd, dn (register copy).
func (a *Assembler) FmovDD(dst, src VReg) {
	a.regs3("FmovDD", opFmovDD, uint8(dst), uint8(src), 0)
}

// FmovDR emits fmov dd, xn: a raw 64-bit move without conversion. Register 31
// is XZR for src.
func (a *Assembler) FmovDR(dst VReg, src Reg) {
	a.regs3("FmovDR", opFmovDX, uint8(dst), uint8(src), 0)
}

// FmovRD emits fmov xd, dn: a raw 64-bit move without conversion. Register 31
// is XZR for dst.
func (a *Assembler) FmovRD(dst Reg, src VReg) {
	a.regs3("FmovRD", opFmovXD, uint8(dst), uint8(src), 0)
}

// FaddD emits fadd dd, dn, dm.
func (a *Assembler) FaddD(dst, n, m VReg) {
	a.regs3("FaddD", opFaddD, uint8(dst), uint8(n), uint8(m))
}

// FsubD emits fsub dd, dn, dm (dst = n - m).
func (a *Assembler) FsubD(dst, n, m VReg) {
	a.regs3("FsubD", opFsubD, uint8(dst), uint8(n), uint8(m))
}

// FmulD emits fmul dd, dn, dm.
func (a *Assembler) FmulD(dst, n, m VReg) {
	a.regs3("FmulD", opFmulD, uint8(dst), uint8(n), uint8(m))
}

// FdivD emits fdiv dd, dn, dm (dst = n / m).
func (a *Assembler) FdivD(dst, n, m VReg) {
	a.regs3("FdivD", opFdivD, uint8(dst), uint8(n), uint8(m))
}

// FsqrtD emits fsqrt dd, dn.
func (a *Assembler) FsqrtD(dst, src VReg) {
	a.regs3("FsqrtD", opFsqrtD, uint8(dst), uint8(src), 0)
}

// FabsD emits fabs dd, dn.
func (a *Assembler) FabsD(dst, src VReg) {
	a.regs3("FabsD", opFabsD, uint8(dst), uint8(src), 0)
}

// FnegD emits fneg dd, dn.
func (a *Assembler) FnegD(dst, src VReg) {
	a.regs3("FnegD", opFnegD, uint8(dst), uint8(src), 0)
}

// FrintmD emits frintm dd, dn: round to an integral double toward minus
// infinity (floor).
func (a *Assembler) FrintmD(dst, src VReg) {
	a.regs3("FrintmD", opFrintmD, uint8(dst), uint8(src), 0)
}

// FrintpD emits frintp dd, dn: round to an integral double toward plus
// infinity (ceil).
func (a *Assembler) FrintpD(dst, src VReg) {
	a.regs3("FrintpD", opFrintpD, uint8(dst), uint8(src), 0)
}

// FrintzD emits frintz dd, dn: round to an integral double toward zero
// (truncate).
func (a *Assembler) FrintzD(dst, src VReg) {
	a.regs3("FrintzD", opFrintzD, uint8(dst), uint8(src), 0)
}

// FcmpDD emits fcmp dn, dm, setting NZCV from comparing n with m.
func (a *Assembler) FcmpDD(n, m VReg) {
	a.regs3("FcmpDD", opFcmpD, 0, uint8(n), uint8(m))
}

// ScvtfDR emits scvtf dd, xn: signed 64-bit integer to double. Register 31 is
// XZR for src.
func (a *Assembler) ScvtfDR(dst VReg, src Reg) {
	a.regs3("ScvtfDR", opScvtfDX, uint8(dst), uint8(src), 0)
}

// FcvtzsRD emits fcvtzs xd, dn: double to signed 64-bit integer, rounding
// toward zero. Register 31 is XZR for dst.
func (a *Assembler) FcvtzsRD(dst Reg, src VReg) {
	a.regs3("FcvtzsRD", opFcvtzsX, uint8(dst), uint8(src), 0)
}

// FcvtmsRD emits fcvtms xd, dn: double to signed 64-bit integer, rounding
// toward minus infinity. Register 31 is XZR for dst.
func (a *Assembler) FcvtmsRD(dst Reg, src VReg) {
	a.regs3("FcvtmsRD", opFcvtmsX, uint8(dst), uint8(src), 0)
}

// LdrDM emits a 64-bit floating point load: ldr dt, [base, #off], or ldur.
// off must satisfy MemOffOK64. Register 31 is SP for base.
func (a *Assembler) LdrDM(dst VReg, base Reg, off int32) {
	a.memOff("LdrDM", opLdrD, opLdurD, scaleQuad, uint8(dst), base, off)
}

// StrDM emits a 64-bit floating point store: str dt, [base, #off], or stur.
// off must satisfy MemOffOK64. Register 31 is SP for base.
func (a *Assembler) StrDM(src VReg, base Reg, off int32) {
	a.memOff("StrDM", opStrD, opSturD, scaleQuad, uint8(src), base, off)
}

// LdrDMIdx emits ldr dt, [base, index, lsl #3] if scaled, else
// ldr dt, [base, index]. Register 31 is SP for base and XZR for index.
func (a *Assembler) LdrDMIdx(dst VReg, base, index Reg, scaled bool) {
	a.memIdx("LdrDMIdx", opLdrDRR, uint8(dst), base, index, scaled)
}

// StrDMIdx emits str dt, [base, index, lsl #3] if scaled, else
// str dt, [base, index]. Register 31 is SP for base and XZR for index.
func (a *Assembler) StrDMIdx(src VReg, base, index Reg, scaled bool) {
	a.memIdx("StrDMIdx", opStrDRR, uint8(src), base, index, scaled)
}
