package lua

import (
	"math"
	"math/bits"
	"math/rand"
	"time"
)

func OpenMath(L *LState) int {
	if L.is55() {
		return openMath55(L)
	}
	mod := L.RegisterModule(MathLibName, mathFuncs).(*LTable)
	mod.RawSetString("pi", LNumber(math.Pi))
	mod.RawSetString("huge", LNumber(math.MaxFloat64))
	L.Push(mod)
	return 1
}

var mathFuncs = map[string]LGFunction{
	"abs":        mathAbs,
	"acos":       mathAcos,
	"asin":       mathAsin,
	"atan":       mathAtan,
	"atan2":      mathAtan2,
	"ceil":       mathCeil,
	"cos":        mathCos,
	"cosh":       mathCosh,
	"deg":        mathDeg,
	"exp":        mathExp,
	"floor":      mathFloor,
	"fmod":       mathFmod,
	"frexp":      mathFrexp,
	"ldexp":      mathLdexp,
	"log":        mathLog,
	"log10":      mathLog10,
	"max":        mathMax,
	"min":        mathMin,
	"mod":        mathMod,
	"modf":       mathModf,
	"pow":        mathPow,
	"rad":        mathRad,
	"random":     mathRandom,
	"randomseed": mathRandomseed,
	"sin":        mathSin,
	"sinh":       mathSinh,
	"sqrt":       mathSqrt,
	"tan":        mathTan,
	"tanh":       mathTanh,
}

func mathAbs(L *LState) int {
	L.Push(LNumber(math.Abs(float64(L.CheckNumber(1)))))
	return 1
}

func mathAcos(L *LState) int {
	L.Push(LNumber(math.Acos(float64(L.CheckNumber(1)))))
	return 1
}

func mathAsin(L *LState) int {
	L.Push(LNumber(math.Asin(float64(L.CheckNumber(1)))))
	return 1
}

func mathAtan(L *LState) int {
	L.Push(LNumber(math.Atan(float64(L.CheckNumber(1)))))
	return 1
}

func mathAtan2(L *LState) int {
	L.Push(LNumber(math.Atan2(float64(L.CheckNumber(1)), float64(L.CheckNumber(2)))))
	return 1
}

func mathCeil(L *LState) int {
	L.Push(LNumber(math.Ceil(float64(L.CheckNumber(1)))))
	return 1
}

func mathCos(L *LState) int {
	L.Push(LNumber(math.Cos(float64(L.CheckNumber(1)))))
	return 1
}

func mathCosh(L *LState) int {
	L.Push(LNumber(math.Cosh(float64(L.CheckNumber(1)))))
	return 1
}

func mathDeg(L *LState) int {
	L.Push(LNumber(float64(L.CheckNumber(1)) * 180 / math.Pi))
	return 1
}

func mathExp(L *LState) int {
	L.Push(LNumber(math.Exp(float64(L.CheckNumber(1)))))
	return 1
}

func mathFloor(L *LState) int {
	L.Push(LNumber(math.Floor(float64(L.CheckNumber(1)))))
	return 1
}

func mathFmod(L *LState) int {
	L.Push(LNumber(math.Mod(float64(L.CheckNumber(1)), float64(L.CheckNumber(2)))))
	return 1
}

func mathFrexp(L *LState) int {
	v1, v2 := math.Frexp(float64(L.CheckNumber(1)))
	L.Push(LNumber(v1))
	L.Push(LNumber(v2))
	return 2
}

func mathLdexp(L *LState) int {
	L.Push(LNumber(math.Ldexp(float64(L.CheckNumber(1)), L.CheckInt(2))))
	return 1
}

func mathLog(L *LState) int {
	L.Push(LNumber(math.Log(float64(L.CheckNumber(1)))))
	return 1
}

func mathLog10(L *LState) int {
	L.Push(LNumber(math.Log10(float64(L.CheckNumber(1)))))
	return 1
}

func mathMax(L *LState) int {
	if L.GetTop() == 0 {
		L.RaiseError("wrong number of arguments")
	}
	max := L.CheckNumber(1)
	top := L.GetTop()
	for i := 2; i <= top; i++ {
		v := L.CheckNumber(i)
		if v > max {
			max = v
		}
	}
	L.Push(max)
	return 1
}

func mathMin(L *LState) int {
	if L.GetTop() == 0 {
		L.RaiseError("wrong number of arguments")
	}
	min := L.CheckNumber(1)
	top := L.GetTop()
	for i := 2; i <= top; i++ {
		v := L.CheckNumber(i)
		if v < min {
			min = v
		}
	}
	L.Push(min)
	return 1
}

func mathMod(L *LState) int {
	lhs := L.CheckNumber(1)
	rhs := L.CheckNumber(2)
	L.Push(luaModulo(lhs, rhs))
	return 1
}

func mathModf(L *LState) int {
	v1, v2 := math.Modf(float64(L.CheckNumber(1)))
	L.Push(LNumber(v1))
	L.Push(LNumber(v2))
	return 2
}

func mathPow(L *LState) int {
	L.Push(LNumber(math.Pow(float64(L.CheckNumber(1)), float64(L.CheckNumber(2)))))
	return 1
}

func mathRad(L *LState) int {
	L.Push(LNumber(float64(L.CheckNumber(1)) * math.Pi / 180))
	return 1
}

func mathRandom(L *LState) int {
	switch L.GetTop() {
	case 0:
		L.Push(LNumber(rand.Float64()))
	case 1:
		n := L.CheckInt(1)
		L.Push(LNumber(rand.Intn(n) + 1))
	default:
		min := L.CheckInt(1)
		max := L.CheckInt(2) + 1
		L.Push(LNumber(rand.Intn(max-min) + min))
	}
	return 1
}

func mathRandomseed(L *LState) int {
	rand.Seed(L.CheckInt64(1))
	return 0
}

func mathSin(L *LState) int {
	L.Push(LNumber(math.Sin(float64(L.CheckNumber(1)))))
	return 1
}

func mathSinh(L *LState) int {
	L.Push(LNumber(math.Sinh(float64(L.CheckNumber(1)))))
	return 1
}

func mathSqrt(L *LState) int {
	L.Push(LNumber(math.Sqrt(float64(L.CheckNumber(1)))))
	return 1
}

func mathTan(L *LState) int {
	L.Push(LNumber(math.Tan(float64(L.CheckNumber(1)))))
	return 1
}

func mathTanh(L *LState) int {
	L.Push(LNumber(math.Tanh(float64(L.CheckNumber(1)))))
	return 1
}

/* Lua 5.5 profile {{{ */

// openMath55 registers the math library of the Lua 5.5 profile.
func openMath55(L *LState) int {
	mod := L.RegisterModule(MathLibName, math55Funcs).(*LTable)
	mod.RawSetString("pi", LNumber(math.Pi))
	mod.RawSetString("huge", LNumber(math.Inf(1)))
	mod.RawSetString("maxinteger", LInteger(maxInteger))
	mod.RawSetString("mininteger", LInteger(minInteger))
	gen := &xoshiro256{}
	gen.seed(uint64(time.Now().UnixNano()), rand.Uint64())
	state := L.NewUserData()
	state.Value = gen
	mod.RawSetString("random", L.NewClosure(math55Random, state))
	mod.RawSetString("randomseed", L.NewClosure(math55Randomseed, state))
	L.Push(mod)
	return 1
}

var math55Funcs = map[string]LGFunction{
	"abs":       math55Abs,
	"acos":      mathAcos,
	"asin":      mathAsin,
	"atan":      math55Atan,
	"ceil":      math55Ceil,
	"cos":       mathCos,
	"deg":       math55Deg,
	"exp":       mathExp,
	"floor":     math55Floor,
	"fmod":      math55Fmod,
	"frexp":     math55Frexp,
	"ldexp":     math55Ldexp,
	"log":       math55Log,
	"max":       math55Max,
	"min":       math55Min,
	"modf":      math55Modf,
	"rad":       math55Rad,
	"sin":       mathSin,
	"sqrt":      mathSqrt,
	"tan":       mathTan,
	"tointeger": math55ToInteger,
	"type":      math55Type,
	"ult":       math55Ult,
}

// pushFloatAsInt pushes f as an integer if it fits, else as a float.
func pushFloatAsInt(L *LState, f float64) {
	if i, ok := floatToInteger(f); ok {
		L.Push(LInteger(i))
	} else {
		L.Push(LNumber(f))
	}
}

// math55Abs implements math.abs; integers stay integers (wrapping around
// for the minimum integer).
func math55Abs(L *LState) int {
	if i, ok := L.Get(1).(LInteger); ok {
		if i < 0 {
			i = -i
		}
		L.Push(i)
		return 1
	}
	L.Push(LNumber(math.Abs(float64(L.CheckNumber(1)))))
	return 1
}

// math55Atan implements math.atan(y [, x]).
func math55Atan(L *LState) int {
	y := float64(L.CheckNumber(1))
	x := 1.0
	if L.Get(2) != LNil {
		x = float64(L.CheckNumber(2))
	}
	L.Push(LNumber(math.Atan2(y, x)))
	return 1
}

// math55Ceil implements math.ceil with an integer result when it fits.
func math55Ceil(L *LState) int {
	if i, ok := L.Get(1).(LInteger); ok {
		L.Push(i)
		return 1
	}
	pushFloatAsInt(L, math.Ceil(float64(L.CheckNumber(1))))
	return 1
}

// math55Floor implements math.floor with an integer result when it fits.
func math55Floor(L *LState) int {
	if i, ok := L.Get(1).(LInteger); ok {
		L.Push(i)
		return 1
	}
	pushFloatAsInt(L, math.Floor(float64(L.CheckNumber(1))))
	return 1
}

// math55Deg implements math.deg.
func math55Deg(L *LState) int {
	L.Push(LNumber(float64(L.CheckNumber(1)) * (180.0 / math.Pi)))
	return 1
}

// math55Rad implements math.rad.
func math55Rad(L *LState) int {
	L.Push(LNumber(float64(L.CheckNumber(1)) * (math.Pi / 180.0)))
	return 1
}

// math55Fmod implements math.fmod: C remainder semantics (the result has
// the sign of the dividend) with an integer result for integer operands.
func math55Fmod(L *LState) int {
	a, aok := L.Get(1).(LInteger)
	b, bok := L.Get(2).(LInteger)
	if aok && bok {
		switch b {
		case 0:
			L.ArgError(2, "zero")
		case -1:
			L.Push(LInteger(0)) // avoids the overflow of mininteger % -1
		default:
			L.Push(a % b)
		}
		return 1
	}
	x := float64(L.CheckNumber(1))
	y := float64(L.CheckNumber(2))
	L.Push(LNumber(math.Mod(x, y)))
	return 1
}

// math55Frexp implements math.frexp.
func math55Frexp(L *LState) int {
	frac, exp := math.Frexp(float64(L.CheckNumber(1)))
	L.Push(LNumber(frac))
	L.Push(LInteger(exp))
	return 2
}

// math55Ldexp implements math.ldexp; like the reference implementation
// the exponent is truncated to a C int.
func math55Ldexp(L *LState) int {
	x := float64(L.CheckNumber(1))
	exp := L.CheckInt64(2)
	L.Push(LNumber(math.Ldexp(x, int(int32(exp)))))
	return 1
}

// math55Log implements math.log(x [, base]).
func math55Log(L *LState) int {
	x := float64(L.CheckNumber(1))
	if L.Get(2) == LNil {
		L.Push(LNumber(math.Log(x)))
		return 1
	}
	switch base := float64(L.CheckNumber(2)); base {
	case 2.0:
		L.Push(LNumber(math.Log2(x)))
	case 10.0:
		L.Push(LNumber(math.Log10(x)))
	default:
		L.Push(LNumber(math.Log(x) / math.Log(base)))
	}
	return 1
}

// mathSelect returns the argument selected by repeated comparisons; pick
// reports whether candidate replaces the current selection. Like the
// reference implementation it compares the original values (including
// metamethods) and returns the selected argument unchanged.
func mathSelect(L *LState, pick func(candidate, current LValue) bool) int {
	top := L.GetTop()
	if top < 1 {
		L.ArgError(1, "value expected")
	}
	sel := L.Get(1)
	for i := 2; i <= top; i++ {
		if v := L.Get(i); pick(v, sel) {
			sel = v
		}
	}
	L.Push(sel)
	return 1
}

// math55Max implements math.max.
func math55Max(L *LState) int {
	return mathSelect(L, func(candidate, current LValue) bool {
		return L.LessThan(current, candidate)
	})
}

// math55Min implements math.min.
func math55Min(L *LState) int {
	return mathSelect(L, func(candidate, current LValue) bool {
		return L.LessThan(candidate, current)
	})
}

// math55Modf implements math.modf: the integral part (as an integer when
// it fits) and the fractional part (always a float).
func math55Modf(L *LState) int {
	if i, ok := L.Get(1).(LInteger); ok {
		L.Push(i)
		L.Push(LNumber(0))
		return 2
	}
	n := float64(L.CheckNumber(1))
	ip := math.Floor(n)
	if n < 0 {
		ip = math.Ceil(n)
	}
	pushFloatAsInt(L, ip)
	if n == ip {
		L.Push(LNumber(0))
	} else {
		L.Push(LNumber(n - ip))
	}
	return 2
}

// math55ToInteger implements math.tointeger: numbers and numeric strings
// with an exact integer value are converted, anything else yields nil.
func math55ToInteger(L *LState) int {
	L.CheckAny(1)
	if num, ok := L.toNumberValue(L.Get(1)); ok {
		if i, ok := LVAsInteger(num); ok {
			L.Push(LInteger(i))
			return 1
		}
	}
	L.Push(LNil)
	return 1
}

// math55Type implements math.type.
func math55Type(L *LState) int {
	switch L.CheckAny(1).(type) {
	case LInteger:
		L.Push(LString("integer"))
	case LNumber:
		L.Push(LString("float"))
	default:
		L.Push(LNil)
	}
	return 1
}

// math55Ult implements math.ult (unsigned integer comparison).
func math55Ult(L *LState) int {
	a := L.CheckInt64(1)
	b := L.CheckInt64(2)
	L.Push(LBool(uint64(a) < uint64(b)))
	return 1
}

// xoshiro256 is the xoshiro256** pseudo-random generator used by the
// reference Lua implementation.
type xoshiro256 struct {
	s [4]uint64
}

// next advances the generator and returns the next 64 random bits.
func (g *xoshiro256) next() uint64 {
	s0, s1, s2, s3 := g.s[0], g.s[1], g.s[2]^g.s[0], g.s[3]^g.s[1]
	res := bits.RotateLeft64(s1*5, 7) * 9
	g.s[0] = s0 ^ s3
	g.s[1] = s1 ^ s2
	g.s[2] = s2 ^ (s1 << 17)
	g.s[3] = bits.RotateLeft64(s3, 45)
	return res
}

// seed initializes the state from two seed components and discards the
// first values to spread the seed, like the reference implementation.
func (g *xoshiro256) seed(n1, n2 uint64) {
	g.s = [4]uint64{n1, 0xff, n2, 0}
	for i := 0; i < 16; i++ {
		g.next()
	}
}

// project maps a random value into the interval [0, n] without bias,
// drawing new values from the generator when needed.
func (g *xoshiro256) project(ran, n uint64) uint64 {
	lim := n
	for sh := uint(1); lim&(lim+1) != 0; sh *= 2 {
		lim |= lim >> sh // spread the top bit to get the next 2^b - 1
	}
	for ran &= lim; ran > n; ran &= lim {
		ran = g.next()
	}
	return ran
}

// mathGenerator returns the random generator shared by math.random and
// math.randomseed of this state.
func mathGenerator(L *LState) *xoshiro256 {
	return L.Get(UpvalueIndex(1)).(*LUserData).Value.(*xoshiro256)
}

// math55Random implements math.random([m [, n]]).
func math55Random(L *LState) int {
	g := mathGenerator(L)
	rv := g.next()
	var low, up int64
	switch L.GetTop() {
	case 0:
		L.Push(LNumber(float64(rv>>11) * (0.5 / (1 << 52))))
		return 1
	case 1:
		low = 1
		up = L.CheckInt64(1)
		if up == 0 { // a single zero asks for a full random integer
			L.Push(LInteger(int64(rv)))
			return 1
		}
	case 2:
		low = L.CheckInt64(1)
		up = L.CheckInt64(2)
	default:
		L.RaiseError("wrong number of arguments")
	}
	if low > up {
		L.ArgError(1, "interval is empty")
	}
	p := g.project(rv, uint64(up)-uint64(low))
	L.Push(LInteger(int64(p + uint64(low))))
	return 1
}

// math55Randomseed implements math.randomseed([x [, y]]); it returns the
// two seed components that were effectively used.
func math55Randomseed(L *LState) int {
	g := mathGenerator(L)
	var n1, n2 uint64
	if L.GetTop() == 0 {
		n1 = uint64(time.Now().UnixNano())
		n2 = g.next()
	} else {
		n1 = uint64(L.CheckInt64(1))
		n2 = uint64(L.OptInt64(2, 0))
	}
	g.seed(n1, n2)
	L.Push(LInteger(int64(n1)))
	L.Push(LInteger(int64(n2)))
	return 2
}

/* }}} */

//
