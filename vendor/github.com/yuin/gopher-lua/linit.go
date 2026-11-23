package lua

const (
	// BaseLibName is here for consistency; the base functions have no namespace/library.
	BaseLibName = ""
	// LoadLibName is here for consistency; the loading system has no namespace/library.
	LoadLibName = "package"
	// TabLibName is the name of the table Library.
	TabLibName = "table"
	// IoLibName is the name of the io Library.
	IoLibName = "io"
	// OsLibName is the name of the os Library.
	OsLibName = "os"
	// StringLibName is the name of the string Library.
	StringLibName = "string"
	// MathLibName is the name of the math Library.
	MathLibName = "math"
	// DebugLibName is the name of the debug Library.
	DebugLibName = "debug"
	// ChannelLibName is the name of the channel Library.
	ChannelLibName = "channel"
	// CoroutineLibName is the name of the coroutine Library.
	CoroutineLibName = "coroutine"
	// Utf8LibName is the name of the utf8 Library (Lua 5.5 profile only).
	Utf8LibName = "utf8"
)

type luaLib struct {
	libName string
	libFunc LGFunction
	// only55 marks a library that OpenLibs opens in the Lua 5.5 language
	// profile only.
	only55 bool
}

var luaLibs = []luaLib{
	luaLib{libName: LoadLibName, libFunc: OpenPackage},
	luaLib{libName: BaseLibName, libFunc: OpenBase},
	luaLib{libName: TabLibName, libFunc: OpenTable},
	luaLib{libName: IoLibName, libFunc: OpenIo},
	luaLib{libName: OsLibName, libFunc: OpenOs},
	luaLib{libName: StringLibName, libFunc: OpenString},
	luaLib{libName: MathLibName, libFunc: OpenMath},
	luaLib{libName: DebugLibName, libFunc: OpenDebug},
	luaLib{libName: ChannelLibName, libFunc: OpenChannel},
	luaLib{libName: CoroutineLibName, libFunc: OpenCoroutine},
	luaLib{libName: Utf8LibName, libFunc: OpenUtf8, only55: true},
}

// OpenLibs loads the built-in libraries. It is equivalent to running OpenLoad,
// then OpenBase, then iterating over the other OpenXXX functions in any order.
func (ls *LState) OpenLibs() {
	// NB: Map iteration order in Go is deliberately randomised, so must open Load/Base
	// prior to iterating.
	for _, lib := range luaLibs {
		if lib.only55 && !ls.is55() {
			continue
		}
		ls.Push(ls.NewFunction(lib.libFunc))
		ls.Push(LString(lib.libName))
		ls.Call(1, 0)
	}
}
