package lua

func OpenCoroutine(L *LState) int {
	if L.is55() {
		return openCoroutine55(L)
	}
	// TODO: Tie module name to contents of linit.go?
	mod := L.RegisterModule(CoroutineLibName, coFuncs)
	L.Push(mod)
	return 1
}

var coFuncs = map[string]LGFunction{
	"create":  coCreate,
	"yield":   coYield,
	"resume":  coResume,
	"running": coRunning,
	"status":  coStatus,
	"wrap":    coWrap,
}

// coNewThread creates a thread whose call stack holds the not yet started
// body function fn.
func coNewThread(L *LState, fn *LFunction) *LState {
	newthread, _ := L.NewThread()
	base := 0
	newthread.stack.Push(callFrame{
		Fn:         fn,
		Pc:         0,
		Base:       base,
		LocalBase:  base + 1,
		ReturnBase: base,
		NArgs:      0,
		NRet:       MultRet,
		Parent:     nil,
		TailCall:   0,
	})
	return newthread
}

func coCreate(L *LState) int {
	L.Push(coNewThread(L, L.CheckFunction(1)))
	return 1
}

func coYield(L *LState) int {
	return -1
}

func coResume(L *LState) int {
	th := L.CheckThread(1)
	if L.G.CurrentThread == th {
		msg := "can not resume a running thread"
		if th.wrapped {
			L.RaiseError(msg)
			return 0
		}
		L.Push(LFalse)
		L.Push(LString(msg))
		return 2
	}
	if th.Dead {
		msg := "can not resume a dead thread"
		if th.wrapped {
			L.RaiseError(msg)
			return 0
		}
		L.Push(LFalse)
		L.Push(LString(msg))
		return 2
	}
	coTransfer(L, th, L.GetTop()-1)
	top := L.GetTop()
	threadRun(th)
	return L.GetTop() - top
}

// coTransfer makes th the running thread with L as its parent and moves
// the top nargs values of L to it. A thread that has not run yet gets its
// body function set up with these values as arguments.
func coTransfer(L *LState, th *LState, nargs int) {
	th.Parent = L
	L.G.CurrentThread = th
	if !th.isStarted() {
		cf := th.stack.Last()
		th.currentFrame = cf
		th.SetTop(0)
		L.XMoveTo(th, nargs)
		cf.NArgs = nargs
		th.initCallFrame(cf)
		th.Panic = panicWithoutTraceback
	} else {
		L.XMoveTo(th, nargs)
	}
}

func coRunning(L *LState) int {
	if L.G.MainThread == L {
		L.Push(LNil)
		return 1
	}
	L.Push(L.G.CurrentThread)
	return 1
}

func coStatus(L *LState) int {
	L.Push(LString(L.Status(L.CheckThread(1))))
	return 1
}

func wrapaux(L *LState) int {
	L.Insert(L.ToThread(UpvalueIndex(1)), 1)
	return coResume(L)
}

func coWrap(L *LState) int {
	coCreate(L)
	L.CheckThread(L.GetTop()).wrapped = true
	v := L.Get(L.GetTop())
	L.Pop(1)
	L.Push(L.NewClosure(wrapaux, v))
	return 1
}

/* Lua 5.5 profile {{{ */

const (
	co55Running   = "running"
	co55Suspended = "suspended"
	co55Normal    = "normal"
	co55Dead      = "dead"
)

// co55Info tracks how many main loops of a coroutine are active. A value
// above one means that the coroutine runs inside a nested Go call (a
// protected call, a metamethod, an iterator, ...) which cannot be
// suspended.
type co55Info struct {
	depth int
}

// co55CloseSignal is the error value used to unwind a coroutine that
// closes itself.
type co55CloseSignal struct {
	err    LValue
	failed bool
}

// co55ErrMarker marks the registry slot of a dead coroutine that holds the
// error it died with (see co55StashError).
var co55ErrMarker = &LUserData{}

// openCoroutine55 registers the coroutine library of the Lua 5.5 profile.
func openCoroutine55(L *LState) int {
	st := base55StateOf(L)
	mod := L.RegisterModule(CoroutineLibName, map[string]LGFunction{
		"close":       co55Close,
		"create":      co55Create,
		"isyieldable": func(L *LState) int { return co55IsYieldable(L, st) },
		"resume":      co55Resume,
		"running":     co55RunningThread,
		"status":      co55StatusOf,
		"wrap":        co55Wrap,
		"yield":       func(L *LState) int { return co55Yield(L, st) },
	})
	L.Push(mod)
	return 1
}

// co55MainLoop wraps the main loop of a coroutine to record which
// coroutine is executing and how deeply its main loops are nested.
func co55MainLoop(st *base55State, info *co55Info, loop func(*LState, *callFrame)) func(*LState, *callFrame) {
	return func(L *LState, baseframe *callFrame) {
		prevInfo, prevThread := st.coInfo, st.coThread
		st.coInfo, st.coThread = info, L
		info.depth++
		defer func() {
			info.depth--
			st.coInfo, st.coThread = prevInfo, prevThread
		}()
		loop(L, baseframe)
	}
}

// co55NewThread creates a coroutine for fn with nesting tracking.
func co55NewThread(L *LState, fn *LFunction) *LState {
	th := coNewThread(L, fn)
	th.mainLoop = co55MainLoop(base55StateOf(L), &co55Info{}, th.mainLoop)
	return th
}

// co55IsCloseSignal reports whether v is the error value of a coroutine
// closing itself.
func co55IsCloseSignal(v LValue) bool {
	ud, ok := v.(*LUserData)
	if !ok {
		return false
	}
	_, ok = ud.Value.(*co55CloseSignal)
	return ok
}

// co55Propagate keeps unwinding if err, caught by a protected call, is
// the signal of a coroutine closing itself: such a coroutine must not
// continue to run.
func co55Propagate(err error) {
	if aerr, ok := err.(*ApiError); ok && aerr.Object != nil && co55IsCloseSignal(aerr.Object) {
		panic(aerr)
	}
}

// co55IsAncestor reports whether th resumed, directly or indirectly, the
// running thread L.
func co55IsAncestor(L *LState, th *LState) bool {
	for p := L.Parent; p != nil; p = p.Parent {
		if p == th {
			return true
		}
	}
	return false
}

// co55Status returns the status of th as seen from the running thread L.
func co55Status(L *LState, th *LState) string {
	switch {
	case th == L:
		return co55Running
	case th.Dead:
		return co55Dead
	case th.Parent != nil || th == L.G.MainThread || co55IsAncestor(L, th):
		return co55Normal
	}
	return co55Suspended
}

// co55StashError keeps the error a coroutine died with on its registry so
// that coroutine.close can report it.
func co55StashError(th *LState, errObj LValue) {
	th.reg.Push(errObj)
	th.reg.Push(co55ErrMarker)
}

// co55PendingError returns the error stashed by co55StashError, if any.
func co55PendingError(th *LState) (LValue, bool) {
	top := th.reg.Top()
	if !th.Dead || top < 2 || th.reg.Get(top-1) != LValue(co55ErrMarker) {
		return LNil, false
	}
	return th.reg.Get(top - 2), true
}

// co55Finish completes a coroutine whose body is a Go function: the VM
// leaves its results on the coroutine's stack without switching back to
// the parent thread.
func co55Finish(L *LState, th *LState) {
	n := th.reg.Top()
	L.Push(LTrue)
	for i := 0; i < n; i++ {
		L.Push(th.reg.Get(i))
	}
	th.reg.SetTop(0)
	th.Parent = nil
	L.G.CurrentThread = L
	th.kill()
}

// co55Run resumes th with the top nargs values of L as arguments. It
// reports whether the coroutine yielded or returned (true) or failed
// (false). The results, or the error value, are left on top of the stack
// of L; their number is returned.
func co55Run(L *LState, th *LState, nargs int) (bool, int) {
	if status := co55Status(L, th); status != co55Suspended {
		msg := "cannot resume non-suspended coroutine"
		if status == co55Dead {
			msg = "cannot resume dead coroutine"
		}
		L.Push(LString(msg))
		return false, 1
	}
	if th.stack.IsEmpty() {
		// The coroutine yielded from a tail call of its body function (or
		// its body is the yield function itself): the values passed to
		// this resume are the results of the coroutine.
		th.kill()
		return true, nargs
	}
	coTransfer(L, th, nargs)
	top := L.GetTop()
	threadRun(th)
	if L.G.CurrentThread == th {
		co55Finish(L, th)
	}
	ok := L.Get(top+1) == LTrue
	L.Remove(top + 1)
	if ok {
		return true, L.GetTop() - top
	}
	errObj := L.Get(-1)
	L.SetTop(top)
	if ud, isud := errObj.(*LUserData); isud {
		if sig, issig := ud.Value.(*co55CloseSignal); issig {
			if !sig.failed {
				return true, 0
			}
			L.Push(sig.err)
			return false, 1
		}
	}
	if errObj == LNil {
		errObj = LString(base55NoErrorObject)
	}
	co55StashError(th, errObj)
	L.Push(errObj)
	return false, 1
}

// co55CloseThread closes the pending to-be-closed variables of a
// suspended or dead coroutine and marks it dead. It returns the error
// the coroutine died with or the error raised while closing, if any.
func co55CloseThread(L *LState, th *LState) (LValue, bool) {
	var aerr *ApiError
	if errObj, ok := co55PendingError(th); ok {
		th.reg.SetTop(th.reg.Top() - 2)
		aerr = newApiError(ApiErrorRun, errObj)
	}
	if len(th.tbc) > 0 {
		current := L.G.CurrentThread
		aerr = th.closeTBCOnError(0, aerr)
		L.G.CurrentThread = current
	}
	if !th.Dead {
		th.kill()
	}
	if aerr != nil {
		return base55ErrorObject(aerr), true
	}
	return LNil, false
}

// co55OptThread returns the thread given as argument 1, or the running
// thread if there is no argument.
func co55OptThread(L *LState) *LState {
	if L.GetTop() < 1 {
		return L
	}
	return L.CheckThread(1)
}

// co55Close implements coroutine.close([co]).
func co55Close(L *LState) int {
	th := co55OptThread(L)
	switch co55Status(L, th) {
	case co55Normal:
		base55Raise(L, "cannot close a normal coroutine")
	case co55Running:
		if L.Parent == nil {
			base55Raise(L, "cannot close main thread")
		}
		sig := &co55CloseSignal{err: LNil}
		if len(L.tbc) > 0 {
			if aerr := L.closeTBCOnError(0, nil); aerr != nil {
				sig.err, sig.failed = base55ErrorObject(aerr), true
			}
		}
		ud := L.NewUserData()
		ud.Value = sig
		L.Error(ud, 0)
	}
	if errObj, failed := co55CloseThread(L, th); failed {
		L.Push(LFalse)
		L.Push(errObj)
		return 2
	}
	L.Push(LTrue)
	return 1
}

// co55Create implements coroutine.create.
func co55Create(L *LState) int {
	L.Push(co55NewThread(L, L.CheckFunction(1)))
	return 1
}

// co55IsYieldable implements coroutine.isyieldable([co]).
func co55IsYieldable(L *LState, st *base55State) int {
	th := co55OptThread(L)
	yieldable := th != L.G.MainThread
	switch {
	case th == L:
		yieldable = L.Parent != nil && !(st.coThread == L && st.coInfo.depth > 1)
	case th.Parent == nil && co55IsAncestor(L, th):
		yieldable = false
	}
	L.Push(LBool(yieldable))
	return 1
}

// co55Resume implements coroutine.resume.
func co55Resume(L *LState) int {
	th := L.CheckThread(1)
	ok, n := co55Run(L, th, L.GetTop()-1)
	L.Insert(LBool(ok), L.GetTop()-n+1)
	return n + 1
}

// co55RunningThread implements coroutine.running: the running thread and whether it is the
// main one.
func co55RunningThread(L *LState) int {
	L.Push(L)
	L.Push(LBool(L.Parent == nil))
	return 2
}

// co55StatusOf implements coroutine.status.
func co55StatusOf(L *LState) int {
	L.Push(LString(co55Status(L, L.CheckThread(1))))
	return 1
}

// co55WrapAux is the function returned by coroutine.wrap (the coroutine is upvalue 1).
// Errors of the coroutine are propagated; a coroutine that died with an
// error is closed first.
func co55WrapAux(L *LState) int {
	th := L.ToThread(UpvalueIndex(1))
	ok, n := co55Run(L, th, L.GetTop())
	if ok {
		return n
	}
	errObj := L.Get(-1)
	if _, pending := co55PendingError(th); pending {
		if closeErr, failed := co55CloseThread(L, th); failed {
			errObj = closeErr
		}
	}
	base55Throw(L, errObj, 1)
	return 0
}

// co55Wrap implements coroutine.wrap.
func co55Wrap(L *LState) int {
	L.Push(L.NewClosure(co55WrapAux, co55NewThread(L, L.CheckFunction(1))))
	return 1
}

// co55Yield implements coroutine.yield. The VM performs the switch when a Go function
// returns a negative count.
func co55Yield(L *LState, st *base55State) int {
	// A coroutine without a parent is running a close handler on behalf
	// of coroutine.close; it cannot be suspended either.
	if st.coThread == L && (L.Parent == nil || st.coInfo.depth > 1) {
		L.Error(LString("attempt to yield across a C-call boundary"), 0)
	}
	if L.Parent == nil {
		L.Error(LString("attempt to yield from outside a coroutine"), 0)
	}
	return -1
}

/* }}} */

//
