package lualib

import (
	"sync"

	"github.com/tengattack/gluacrypto"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

type LuaStatePool struct {
	m     sync.Mutex
	saved []*lua.LState
}

func NewLuaStatePool() *LuaStatePool {
	return &LuaStatePool{saved: make([]*lua.LState, 0, 4)}
}

func (pl *LuaStatePool) Get() *lua.LState {
	pl.m.Lock()

	defer pl.m.Unlock()

	n := len(pl.saved)
	if n == 0 {
		return pl.New()
	}

	x := pl.saved[n-1]
	pl.saved = pl.saved[0 : n-1]

	return x
}

func (pl *LuaStatePool) New() *lua.LState {
	L := lua.NewState()

	libs.Preload(L)
	gluacrypto.Preload(L)

	return L
}

func (pl *LuaStatePool) Put(L *lua.LState) {
	pl.m.Lock()

	defer pl.m.Unlock()

	pl.saved = append(pl.saved, L)
}

func (pl *LuaStatePool) Shutdown() {
	for _, L := range pl.saved {
		L.Close()
	}
}
