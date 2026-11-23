package lua

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

/* load lib {{{ */

var loLoaders = []LGFunction{loLoaderPreload, loLoaderLua}

func loGetPath(env string, defpath string) string {
	path := os.Getenv(env)
	if len(path) == 0 {
		path = defpath
	}
	path = strings.Replace(path, ";;", ";"+defpath+";", -1)
	return loExpandExecDir(path)
}

// loExpandExecDir replaces the executable directory mark in a path on
// systems that use it (Windows).
func loExpandExecDir(path string) string {
	if os.PathSeparator != '/' {
		dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			panic(err)
		}
		path = strings.Replace(path, "!", dir, -1)
	}
	return path
}

func loFindFile(L *LState, name, pname string) (string, string) {
	name = strings.Replace(name, ".", string(os.PathSeparator), -1)
	lv := L.GetField(L.GetField(L.Get(EnvironIndex), "package"), pname)
	path, ok := lv.(LString)
	if !ok {
		L.RaiseError("package.%s must be a string", pname)
	}
	messages := []string{}
	for _, pattern := range strings.Split(string(path), ";") {
		luapath := strings.Replace(pattern, "?", name, -1)
		if _, err := os.Stat(luapath); err == nil {
			return luapath, ""
		} else {
			messages = append(messages, err.Error())
		}
	}
	return "", strings.Join(messages, "\n\t")
}

func OpenPackage(L *LState) int {
	if L.is55() {
		return openPackage55(L)
	}
	packagemod := L.RegisterModule(LoadLibName, loFuncs)

	L.SetField(packagemod, "preload", L.NewTable())

	loaders := L.CreateTable(len(loLoaders), 0)
	for i, loader := range loLoaders {
		L.RawSetInt(loaders, i+1, L.NewFunction(loader))
	}
	L.SetField(packagemod, "loaders", loaders)
	L.SetField(L.Get(RegistryIndex), "_LOADERS", loaders)

	loaded := L.NewTable()
	L.SetField(packagemod, "loaded", loaded)
	L.SetField(L.Get(RegistryIndex), "_LOADED", loaded)

	L.SetField(packagemod, "path", LString(loGetPath(LuaPath, LuaPathDefault)))
	L.SetField(packagemod, "cpath", emptyLString)

	L.SetField(packagemod, "config", LString(LuaDirSep+"\n"+LuaPathSep+
		"\n"+LuaPathMark+"\n"+LuaExecDir+"\n"+LuaIgMark+"\n"))

	L.Push(packagemod)
	return 1
}

var loFuncs = map[string]LGFunction{
	"loadlib": loLoadLib,
	"seeall":  loSeeAll,
}

func loLoaderPreload(L *LState) int {
	name := L.CheckString(1)
	preload := L.GetField(L.GetField(L.Get(EnvironIndex), "package"), "preload")
	if _, ok := preload.(*LTable); !ok {
		L.RaiseError("package.preload must be a table")
	}
	lv := L.GetField(preload, name)
	if lv == LNil {
		L.Push(LString(fmt.Sprintf("no field package.preload['%s']", name)))
		return 1
	}
	L.Push(lv)
	return 1
}

func loLoaderLua(L *LState) int {
	name := L.CheckString(1)
	path, msg := loFindFile(L, name, "path")
	if len(path) == 0 {
		L.Push(LString(msg))
		return 1
	}
	fn, err1 := L.LoadFile(path)
	if err1 != nil {
		L.RaiseError(err1.Error())
	}
	L.Push(fn)
	return 1
}

func loLoadLib(L *LState) int {
	L.RaiseError("loadlib is not supported")
	return 0
}

func loSeeAll(L *LState) int {
	mod := L.CheckTable(1)
	mt := L.GetMetatable(mod)
	if mt == LNil {
		mt = L.CreateTable(0, 1)
		L.SetMetatable(mod, mt)
	}
	L.SetField(mt, "__index", L.Get(GlobalsIndex))
	return 0
}

/* }}} */

/* Lua 5.5 profile {{{ */

// lo55PackageKey is the registry key of the package table used by
// require.
const lo55PackageKey = "_PACKAGE"

// lo55PathEnv is the versioned environment variable that overrides
// LUA_PATH.
const lo55PathEnv = "LUA_PATH_5_5"

// lo55NoDynLibs is the message of the reference implementation built
// without support for dynamic libraries.
const lo55NoDynLibs = "dynamic libraries not enabled; check your Lua installation"

// lo55DefaultPath returns the default value of package.path.
func lo55DefaultPath() string {
	if os.PathSeparator == '/' {
		const ldir, cdir = "/usr/local/share/lua/5.5/", "/usr/local/lib/lua/5.5/"
		return ldir + "?.lua;" + ldir + "?/init.lua;" + cdir + "?.lua;" + cdir + "?/init.lua;./?.lua;./?/init.lua"
	}
	const ldir, cdir, shrdir = "!\\lua\\", "!\\", "!\\..\\share\\lua\\5.5\\"
	return ldir + "?.lua;" + ldir + "?\\init.lua;" + cdir + "?.lua;" + cdir + "?\\init.lua;" +
		shrdir + "?.lua;" + shrdir + "?\\init.lua;.\\?.lua;.\\?\\init.lua"
}

// lo55Path computes package.path from the environment: the first ";;" of
// the variable is replaced by the default path.
func lo55Path() string {
	def := lo55DefaultPath()
	path, ok := os.LookupEnv(lo55PathEnv)
	if !ok {
		path, ok = os.LookupEnv(LuaPath)
	}
	if !ok {
		return loExpandExecDir(def)
	}
	if i := strings.Index(path, ";;"); i >= 0 {
		prefix, suffix := path[:i], path[i+2:]
		path = def
		if prefix != "" {
			path = prefix + ";" + path
		}
		if suffix != "" {
			path += ";" + suffix
		}
	}
	return loExpandExecDir(path)
}

// lo55Readable reports whether the file can be opened for reading.
func lo55Readable(filename string) bool {
	f, err := os.Open(filename)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// lo55FindInPath searches the templates of path for name, after replacing
// the separator sep in name by rep. It returns the file name, or an empty
// string and the list of the files tried.
func lo55FindInPath(name, path, sep, rep string) (string, string) {
	if sep != "" {
		name = strings.ReplaceAll(name, sep, rep)
	}
	candidates := strings.ReplaceAll(path, LuaPathMark, name)
	if candidates != "" {
		for _, filename := range strings.Split(candidates, LuaPathSep) {
			if lo55Readable(filename) {
				return filename, ""
			}
		}
	}
	return "", "no file '" + strings.ReplaceAll(candidates, LuaPathSep, "'\n\tno file '") + "'"
}

// openPackage55 creates the package table of the Lua 5.5 profile.
func openPackage55(L *LState) int {
	registry := L.Get(RegistryIndex).(*LTable)
	pkg := L.RegisterModule(LoadLibName, lo55Funcs).(*LTable)
	registry.RawSetString(lo55PackageKey, pkg)

	preload := L.NewTable()
	pkg.RawSetString("preload", preload)

	searchers := L.CreateTable(4, 0)
	searchers.RawSetInt(1, L.NewFunction(func(L *LState) int { return lo55SearcherPreload(L, preload) }))
	searchers.RawSetInt(2, L.NewFunction(func(L *LState) int { return lo55SearcherLua(L, pkg) }))
	searchers.RawSetInt(3, L.NewFunction(func(L *LState) int { return lo55SearcherC(L, pkg, false) }))
	searchers.RawSetInt(4, L.NewFunction(func(L *LState) int { return lo55SearcherC(L, pkg, true) }))
	pkg.RawSetString("searchers", searchers)

	pkg.RawSetString("loaded", L.FindTable(registry, "_LOADED", 1))
	pkg.RawSetString("path", LString(lo55Path()))
	pkg.RawSetString("cpath", emptyLString)
	pkg.RawSetString("config", LString(LuaDirSep+"\n"+LuaPathSep+
		"\n"+LuaPathMark+"\n"+LuaExecDir+"\n"+LuaIgMark+"\n"))

	L.Push(pkg)
	return 1
}

var lo55Funcs = map[string]LGFunction{
	"loadlib":    lo55LoadLib,
	"searchpath": lo55SearchPath,
}

// lo55SearcherPreload is the searcher for package.preload.
func lo55SearcherPreload(L *LState, preload *LTable) int {
	name := base55CheckString(L, 1)
	loader := L.GetField(preload, name)
	if loader == LNil {
		L.Push(LString(fmt.Sprintf("no field package.preload['%s']", name)))
		return 1
	}
	L.Push(loader)
	L.Push(LString(":preload:"))
	return 2
}

// lo55FindFile searches the path stored in field pname of the package
// table for the module name. It returns the file name, or an empty string
// and the list of the files tried.
func lo55FindFile(L *LState, pkg *LTable, name, pname string) (string, string) {
	path, ok := L.GetField(pkg, pname).(LString)
	if !ok {
		base55Raise(L, "'package.%s' must be a string", pname)
	}
	return lo55FindInPath(name, string(path), ".", LuaDirSep)
}

// lo55SearcherLua is the searcher for Lua files found through
// package.path.
func lo55SearcherLua(L *LState, pkg *LTable) int {
	name := base55CheckString(L, 1)
	filename, tried := lo55FindFile(L, pkg, name, "path")
	if filename == "" {
		L.Push(LString(tried))
		return 1
	}
	fn, msg := base55CompileFile(L, filename, "bt")
	if fn == nil {
		base55Raise(L, "error loading module '%s' from file '%s':\n\t%s", name, filename, msg.String())
	}
	L.Push(fn)
	L.Push(LString(filename))
	return 2
}

// lo55SearcherC stands in for the searchers of C libraries: it looks for
// the library through package.cpath like the reference implementation
// and, since C libraries cannot be loaded, fails if a candidate file
// exists. With root set it searches for the root of a submodule name.
func lo55SearcherC(L *LState, pkg *LTable, root bool) int {
	name := base55CheckString(L, 1)
	libname := name
	if root {
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return 0
		}
		libname = name[:dot]
	}
	filename, tried := lo55FindFile(L, pkg, libname, "cpath")
	if filename == "" {
		L.Push(LString(tried))
		return 1
	}
	base55Raise(L, "error loading module '%s' from file '%s':\n\t%s", name, filename, lo55NoDynLibs)
	return 0
}

// lo55LoadLib reports that C libraries cannot be loaded, using the result
// convention of the reference implementation built without dynamic
// library support.
func lo55LoadLib(L *LState) int {
	base55CheckString(L, 1)
	base55CheckString(L, 2)
	L.Push(LNil)
	L.Push(LString(lo55NoDynLibs))
	L.Push(LString("absent"))
	return 3
}

// lo55SearchPath implements package.searchpath(name, path [, sep [, rep]]).
func lo55SearchPath(L *LState) int {
	name := base55CheckString(L, 1)
	path := base55CheckString(L, 2)
	sep := base55OptString(L, 3, ".")
	rep := base55OptString(L, 4, LuaDirSep)
	filename, tried := lo55FindInPath(name, path, sep, rep)
	if filename == "" {
		L.Push(LNil)
		L.Push(LString(tried))
		return 2
	}
	L.Push(LString(filename))
	return 1
}

// lo55FindLoader asks the searchers for a loader of the module. It
// returns the loader function and the loader data.
func lo55FindLoader(L *LState, name string) (LValue, LValue) {
	var searchers *LTable
	if pkg, ok := L.G.Registry.RawGetString(lo55PackageKey).(*LTable); ok {
		searchers, _ = L.GetField(pkg, "searchers").(*LTable)
	}
	if searchers == nil {
		base55Raise(L, "'package.searchers' must be a table")
	}
	var tried strings.Builder
	for i := 1; ; i++ {
		searcher := searchers.RawGetInt(i)
		if searcher == LNil {
			base55Raise(L, "module '%s' not found:%s", name, tried.String())
		}
		L.Push(searcher)
		L.Push(LString(name))
		L.Call(1, 2)
		loader, data := L.Get(-2), L.Get(-1)
		L.Pop(2)
		switch v := loader.(type) {
		case *LFunction:
			return loader, data
		case LString:
			tried.WriteString("\n\t" + string(v))
		case LNumber, LInteger:
			tried.WriteString("\n\t" + L.numToString(v))
		}
	}
}

// loRequire55 implements require: it returns the module value and, when the module was
// loaded by this call, the loader data.
func loRequire55(L *LState) int {
	name := base55CheckString(L, 1)
	loaded := L.GetField(L.Get(RegistryIndex), "_LOADED")
	if lv := L.GetField(loaded, name); LVAsBool(lv) {
		L.Push(lv)
		return 1
	}
	loader, data := lo55FindLoader(L, name)
	L.Push(loader)
	L.Push(LString(name))
	L.Push(data)
	L.Call(2, 1)
	ret := L.Get(-1)
	L.Pop(1)
	if ret != LNil {
		L.SetField(loaded, name, ret)
	}
	result := L.GetField(loaded, name)
	if result == LNil {
		result = LTrue
		L.SetField(loaded, name, result)
	}
	L.Push(result)
	L.Push(data)
	return 2
}

/* }}} */

//
