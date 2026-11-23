package lua

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

var startedAt time.Time

func init() {
	startedAt = time.Now()
}

func getIntField(L *LState, tb *LTable, key string, v int) int {
	ret := tb.RawGetString(key)

	switch lv := ret.(type) {
	case LNumber:
		return int(lv)
	case LString:
		slv := string(lv)
		slv = strings.TrimLeft(slv, " ")
		if strings.HasPrefix(slv, "0") && !strings.HasPrefix(slv, "0x") && !strings.HasPrefix(slv, "0X") {
			// Standard lua interpreter only support decimal and hexadecimal
			slv = strings.TrimLeft(slv, "0")
			if slv == "" {
				return 0
			}
		}
		if num, err := parseNumber(slv); err == nil {
			return int(num)
		}
	default:
		return v
	}

	return v
}

func getBoolField(L *LState, tb *LTable, key string, v bool) bool {
	ret := tb.RawGetString(key)
	if lb, ok := ret.(LBool); ok {
		return bool(lb)
	}
	return v
}

func OpenOs(L *LState) int {
	if L.is55() {
		return openOs55(L)
	}
	osmod := L.RegisterModule(OsLibName, osFuncs)
	L.Push(osmod)
	return 1
}

var osFuncs = map[string]LGFunction{
	"clock":     osClock,
	"difftime":  osDiffTime,
	"execute":   osExecute,
	"exit":      osExit,
	"date":      osDate,
	"getenv":    osGetEnv,
	"remove":    osRemove,
	"rename":    osRename,
	"setenv":    osSetEnv,
	"setlocale": osSetLocale,
	"time":      osTime,
	"tmpname":   osTmpname,
}

func osClock(L *LState) int {
	L.Push(LNumber(float64(time.Now().Sub(startedAt)) / float64(time.Second)))
	return 1
}

func osDiffTime(L *LState) int {
	L.Push(LNumber(L.CheckInt64(1) - L.CheckInt64(2)))
	return 1
}

func osExecute(L *LState) int {
	var procAttr os.ProcAttr
	procAttr.Files = []*os.File{os.Stdin, os.Stdout, os.Stderr}
	cmd, args := popenArgs(L.CheckString(1))
	args = append([]string{cmd}, args...)
	process, err := os.StartProcess(cmd, args, &procAttr)
	if err != nil {
		L.Push(LNumber(1))
		return 1
	}

	ps, err := process.Wait()
	if err != nil || !ps.Success() {
		L.Push(LNumber(1))
		return 1
	}
	L.Push(LNumber(0))
	return 1
}

func osExit(L *LState) int {
	L.Close()
	os.Exit(L.OptInt(1, 0))
	return 1
}

func osDate(L *LState) int {
	t := time.Now()
	isUTC := false
	cfmt := "%c"
	if L.GetTop() >= 1 {
		cfmt = L.CheckString(1)
		if strings.HasPrefix(cfmt, "!") {
			cfmt = strings.TrimLeft(cfmt, "!")
			isUTC = true
		}
		if L.GetTop() >= 2 {
			t = time.Unix(L.CheckInt64(2), 0)
		}
		if isUTC {
			t = t.UTC()
		}
		if strings.HasPrefix(cfmt, "*t") {
			ret := L.NewTable()
			ret.RawSetString("year", LNumber(t.Year()))
			ret.RawSetString("month", LNumber(t.Month()))
			ret.RawSetString("day", LNumber(t.Day()))
			ret.RawSetString("hour", LNumber(t.Hour()))
			ret.RawSetString("min", LNumber(t.Minute()))
			ret.RawSetString("sec", LNumber(t.Second()))
			ret.RawSetString("wday", LNumber(t.Weekday()+1))
			// TODO yday & dst
			ret.RawSetString("yday", LNumber(0))
			ret.RawSetString("isdst", LFalse)
			L.Push(ret)
			return 1
		}
	}
	L.Push(LString(strftime(t, cfmt)))
	return 1
}

func osGetEnv(L *LState) int {
	v := os.Getenv(L.CheckString(1))
	if len(v) == 0 {
		L.Push(LNil)
	} else {
		L.Push(LString(v))
	}
	return 1
}

func osRemove(L *LState) int {
	err := os.Remove(L.CheckString(1))
	if err != nil {
		L.Push(LNil)
		L.Push(LString(err.Error()))
		return 2
	} else {
		L.Push(LTrue)
		return 1
	}
}

func osRename(L *LState) int {
	err := os.Rename(L.CheckString(1), L.CheckString(2))
	if err != nil {
		L.Push(LNil)
		L.Push(LString(err.Error()))
		return 2
	} else {
		L.Push(LTrue)
		return 1
	}
}

func osSetLocale(L *LState) int {
	// setlocale is not supported
	L.Push(LFalse)
	return 1
}

func osSetEnv(L *LState) int {
	err := os.Setenv(L.CheckString(1), L.CheckString(2))
	if err != nil {
		L.Push(LNil)
		L.Push(LString(err.Error()))
		return 2
	} else {
		L.Push(LTrue)
		return 1
	}
}

func osTime(L *LState) int {
	if L.GetTop() == 0 {
		L.Push(LNumber(time.Now().Unix()))
	} else {
		lv := L.CheckAny(1)
		if lv == LNil {
			L.Push(LNumber(time.Now().Unix()))
		} else {
			tbl, ok := lv.(*LTable)
			if !ok {
				L.TypeError(1, LTTable)
			}
			sec := getIntField(L, tbl, "sec", 0)
			min := getIntField(L, tbl, "min", 0)
			hour := getIntField(L, tbl, "hour", 12)
			day := getIntField(L, tbl, "day", -1)
			month := getIntField(L, tbl, "month", -1)
			year := getIntField(L, tbl, "year", -1)
			isdst := getBoolField(L, tbl, "isdst", false)
			t := time.Date(year, time.Month(month), day, hour, min, sec, 0, time.Local)
			// TODO dst
			if false {
				print(isdst)
			}
			L.Push(LNumber(t.Unix()))
		}
	}
	return 1
}

func osTmpname(L *LState) int {
	file, err := os.CreateTemp("", "")
	if err != nil {
		L.RaiseError("unable to generate a unique filename")
	}
	file.Close()
	os.Remove(file.Name()) // ignore errors
	L.Push(LString(file.Name()))
	return 1
}

/* Lua 5.5 profile {{{ */

// openOs55 registers the os library of the Lua 5.5 profile.
func openOs55(L *LState) int {
	mod := L.RegisterModule(OsLibName, os55Funcs).(*LTable)
	locales := L.NewTable()
	mod.RawSetString("setlocale", L.NewClosure(os55SetLocale, locales))
	L.Push(mod)
	return 1
}

var os55Funcs = map[string]LGFunction{
	"clock":    osClock,
	"date":     os55Date,
	"difftime": os55DiffTime,
	"execute":  os55Execute,
	"exit":     os55Exit,
	"getenv":   os55GetEnv,
	"remove":   os55Remove,
	"rename":   os55Rename,
	"time":     os55Time,
	"tmpname":  os55Tmpname,
}

// Messages for times that the C library of the reference implementation
// cannot represent (the year must fit a C int counted from 1900).
const (
	errDateRange = "date result cannot be represented in this installation"
	errTimeRange = "time result cannot be represented in this installation"
)

// timeRangeLimit bounds the seconds accepted before a time is broken
// down; it keeps the arithmetic of package time far from overflowing.
const timeRangeLimit = 1 << 57

// cErrorInfo extracts the C library view of an error: the strerror-like
// message and the errno value (0 if unknown).
func cErrorInfo(err error) (string, int) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		msg := errno.Error()
		if msg != "" {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		return msg, int(errno)
	}
	return err.Error(), 0
}

// pushFileResult pushes the conventional result of a file operation:
// true on success, else nil, an error message (prefixed with the file
// name if given) and the errno value. It returns the number of results.
func pushFileResult(L *LState, err error, filename string) int {
	if err == nil {
		L.Push(LTrue)
		return 1
	}
	msg, errno := cErrorInfo(err)
	if filename != "" {
		msg = filename + ": " + msg
	}
	L.Push(LNil)
	L.Push(LString(msg))
	L.Push(LInteger(errno))
	return 3
}

// pushExecResult pushes the result triple of a finished command: true or
// nil, "exit" or "signal", and the exit code or signal number.
func pushExecResult(L *LState, err error) int {
	what, code := "exit", 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			what, code = "signal", int(ws.Signal())
		}
	default:
		return pushFileResult(L, err, "")
	}
	if what == "exit" && code == 0 {
		L.Push(LTrue)
	} else {
		L.Push(LNil)
	}
	L.Push(LString(what))
	L.Push(LInteger(code))
	return 3
}

// checkStringArg returns argument n as a string; numbers are converted
// with the number format of the language profile.
func checkStringArg(L *LState, n int) string {
	switch v := L.Get(n).(type) {
	case LString:
		return string(v)
	case LNumber, LInteger:
		return L.numToString(v)
	}
	L.TypeError(n, LTString)
	return ""
}

// optStringArg returns argument n as a string (numbers are converted),
// or d if the argument is absent or nil.
func optStringArg(L *LState, n int, d string) string {
	if L.Get(n) == LNil {
		return d
	}
	return checkStringArg(L, n)
}

// checkOptionArg returns the index of argument n in options, raising an
// argument error for unknown names. An absent argument selects d, unless
// d is empty (then the argument is mandatory).
func checkOptionArg(L *LState, n int, d string, options []string) int {
	var name string
	if d != "" {
		name = optStringArg(L, n, d)
	} else {
		name = checkStringArg(L, n)
	}
	for i, option := range options {
		if option == name {
			return i
		}
	}
	L.ArgError(n, fmt.Sprintf("invalid option '%s'", name))
	return 0
}

// os55DiffTime implements os.difftime(t2, t1).
func os55DiffTime(L *LState) int {
	t1 := L.CheckInt64(1)
	t2 := L.CheckInt64(2)
	L.Push(LNumber(float64(t1) - float64(t2)))
	return 1
}

// os55Execute implements os.execute([command]).
func os55Execute(L *LState) int {
	if L.Get(1) == LNil {
		shell, _ := popenArgs("")
		_, err := os.Stat(shell)
		L.Push(LBool(err == nil))
		return 1
	}
	name, args := popenArgs(checkStringArg(L, 1))
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return pushExecResult(L, cmd.Run())
}

// os55Exit implements os.exit([code [, close]]).
func os55Exit(L *LState) int {
	status := 0
	switch v := L.Get(1).(type) {
	case LBool:
		if !v {
			status = 1
		}
	default:
		status = int(L.OptInt64(1, 0))
	}
	closeState := LVAsBool(L.Get(2))
	if closeState && L == L.G.MainThread {
		// Closing the state closes the pending to-be-closed variables of
		// the main thread; errors of the handlers are ignored.
		L.closeTBCOnError(0, nil)
	}
	flushStandardFiles(L)
	if closeState {
		L.Close()
	}
	os.Exit(status)
	return 0
}

// os55GetEnv implements os.getenv(varname).
func os55GetEnv(L *LState) int {
	if v, ok := os.LookupEnv(checkStringArg(L, 1)); ok {
		L.Push(LString(v))
	} else {
		L.Push(LNil)
	}
	return 1
}

// os55Remove implements os.remove(filename).
func os55Remove(L *LState) int {
	filename := checkStringArg(L, 1)
	return pushFileResult(L, os.Remove(filename), filename)
}

// os55Rename implements os.rename(oldname, newname).
func os55Rename(L *LState) int {
	from := checkStringArg(L, 1)
	to := checkStringArg(L, 2)
	return pushFileResult(L, os.Rename(from, to), "")
}

// createTempFile creates a temporary file named like those of the
// reference implementation ("/tmp/lua_XXXXXX" on POSIX systems).
func createTempFile() (*os.File, error) {
	if LuaOS != "windows" {
		if file, err := os.CreateTemp("/tmp", "lua_"); err == nil {
			return file, nil
		}
	}
	return os.CreateTemp("", "lua_")
}

// os55Tmpname implements os.tmpname(); like the POSIX build of the
// reference implementation it creates the (empty) file.
func os55Tmpname(L *LState) int {
	file, err := createTempFile()
	if err != nil {
		L.RaiseError("unable to generate a unique filename")
	}
	file.Close()
	L.Push(LString(file.Name()))
	return 1
}

// os55LocaleCategories lists the categories accepted by os.setlocale.
var os55LocaleCategories = []string{"all", "collate", "ctype", "monetary", "numeric", "time"}

// os55SetLocale implements os.setlocale([locale [, category]]). Only the
// "C" locale (also known as "POSIX", and selected by "") is available.
// The current name of every category is kept in the upvalue table.
func os55SetLocale(L *LState) int {
	names := L.Get(UpvalueIndex(1)).(*LTable)
	var locale LValue = LNil
	if L.Get(1) != LNil {
		locale = LString(checkStringArg(L, 1))
	}
	category := os55LocaleCategories[checkOptionArg(L, 2, "all", os55LocaleCategories)]
	current := func(cat string) LValue {
		if name := names.RawGetString(cat); name != LNil {
			return name
		}
		return LString("C")
	}
	switch locale {
	case LNil:
	case LString(""):
		locale = LString("C")
		fallthrough
	case LString("C"), LString("POSIX"):
		if category == "all" {
			for _, cat := range os55LocaleCategories {
				names.RawSetString(cat, locale)
			}
		} else {
			names.RawSetString(category, locale)
		}
	default:
		L.Push(LNil)
		return 1
	}
	L.Push(current(category))
	return 1
}

// brokenTime builds the time for the seconds since the epoch t in the
// local or UTC zone. ok is false if the reference implementation cannot
// represent the broken-down time.
func brokenTime(t int64, utc bool) (tm time.Time, ok bool) {
	if t <= -timeRangeLimit || t >= timeRangeLimit {
		return tm, false
	}
	tm = time.Unix(t, 0)
	if utc {
		tm = tm.UTC()
	}
	return tm, tmYearFits(tm)
}

// tmYearFits reports whether the year of tm fits the tm_year field of a
// C struct tm (an int counted from 1900).
func tmYearFits(tm time.Time) bool {
	year := int64(tm.Year()) - 1900
	return year >= -1<<31 && year <= 1<<31-1
}

// setDateFields stores the broken-down time tm in the fields of tbl.
func setDateFields(L *LState, tbl LValue, tm time.Time) {
	L.SetField(tbl, "year", LInteger(tm.Year()))
	L.SetField(tbl, "month", LInteger(tm.Month()))
	L.SetField(tbl, "day", LInteger(tm.Day()))
	L.SetField(tbl, "hour", LInteger(tm.Hour()))
	L.SetField(tbl, "min", LInteger(tm.Minute()))
	L.SetField(tbl, "sec", LInteger(tm.Second()))
	L.SetField(tbl, "yday", LInteger(tm.YearDay()))
	L.SetField(tbl, "wday", LInteger(tm.Weekday()+1))
	L.SetField(tbl, "isdst", LBool(tm.IsDST()))
}

// Conversion specifiers accepted by os.date (those of ISO C99): the
// single character ones and the ones with an E or O modifier.
const (
	dateSpecs  = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%"
	dateSpecsE = "cCxXyY"
	dateSpecsO = "deHImMSuUVwWy"
)

// dateSpecLen returns the length of the valid conversion specifier at
// the start of conv (the text after a '%'), or 0 if there is none.
func dateSpecLen(conv string) int {
	if conv == "" {
		return 0
	}
	if strings.IndexByte(dateSpecs, conv[0]) >= 0 {
		return 1
	}
	if len(conv) >= 2 {
		if (conv[0] == 'E' && strings.IndexByte(dateSpecsE, conv[1]) >= 0) ||
			(conv[0] == 'O' && strings.IndexByte(dateSpecsO, conv[1]) >= 0) {
			return 2
		}
	}
	return 0
}

// weekOfYear returns the week number of tm where weeks start on the
// given weekday (days before the first such weekday are in week 0).
func weekOfYear(tm time.Time, first time.Weekday) int {
	wday := (int(tm.Weekday()) - int(first) + 7) % 7
	return (tm.YearDay() + 6 - wday) / 7
}

// appendDateSpec appends the expansion of the conversion specifier c for
// tm in the "C" locale.
func appendDateSpec(buf []byte, tm time.Time, c byte) []byte {
	num := func(format string, v int) []byte { return fmt.Appendf(buf, format, v) }
	list := func(specs string) []byte {
		for i := 0; i < len(specs); i++ {
			if specs[i] == '%' {
				i++
				buf = appendDateSpec(buf, tm, specs[i])
			} else {
				buf = append(buf, specs[i])
			}
		}
		return buf
	}
	switch c {
	case 'a':
		return append(buf, tm.Weekday().String()[:3]...)
	case 'A':
		return append(buf, tm.Weekday().String()...)
	case 'b', 'h':
		return append(buf, tm.Month().String()[:3]...)
	case 'B':
		return append(buf, tm.Month().String()...)
	case 'c':
		return list("%a %b %e %H:%M:%S %Y")
	case 'C':
		return num("%02d", tm.Year()/100)
	case 'd':
		return num("%02d", tm.Day())
	case 'D', 'x':
		return list("%m/%d/%y")
	case 'e':
		return num("%2d", tm.Day())
	case 'F':
		return list("%Y-%m-%d")
	case 'g':
		year, _ := tm.ISOWeek()
		return num("%02d", ((year%100)+100)%100)
	case 'G':
		year, _ := tm.ISOWeek()
		return num("%04d", year)
	case 'H':
		return num("%02d", tm.Hour())
	case 'I':
		return num("%02d", (tm.Hour()+11)%12+1)
	case 'j':
		return num("%03d", tm.YearDay())
	case 'm':
		return num("%02d", int(tm.Month()))
	case 'M':
		return num("%02d", tm.Minute())
	case 'n':
		return append(buf, '\n')
	case 'p':
		if tm.Hour() < 12 {
			return append(buf, "AM"...)
		}
		return append(buf, "PM"...)
	case 'r':
		return list("%I:%M:%S %p")
	case 'R':
		return list("%H:%M")
	case 'S':
		return num("%02d", tm.Second())
	case 't':
		return append(buf, '\t')
	case 'T', 'X':
		return list("%H:%M:%S")
	case 'u':
		return num("%d", (int(tm.Weekday())+6)%7+1)
	case 'U':
		return num("%02d", weekOfYear(tm, time.Sunday))
	case 'V':
		_, week := tm.ISOWeek()
		return num("%02d", week)
	case 'w':
		return num("%d", int(tm.Weekday()))
	case 'W':
		return num("%02d", weekOfYear(tm, time.Monday))
	case 'y':
		return num("%02d", ((tm.Year()%100)+100)%100)
	case 'Y':
		return num("%04d", tm.Year())
	case 'z':
		_, offset := tm.Zone()
		sign := byte('+')
		if offset < 0 {
			sign, offset = '-', -offset
		}
		buf = append(buf, sign)
		return fmt.Appendf(buf, "%02d%02d", offset/3600, offset%3600/60)
	case 'Z':
		name, _ := tm.Zone()
		return append(buf, name...)
	}
	return append(buf, c) // '%'
}

// os55Date implements os.date([format [, time]]).
func os55Date(L *LState) int {
	format := optStringArg(L, 1, "%c")
	var t int64
	if L.Get(2) == LNil {
		t = time.Now().Unix()
	} else {
		t = L.CheckInt64(2)
	}
	utc := strings.HasPrefix(format, "!")
	if utc {
		format = format[1:]
	}
	tm, ok := brokenTime(t, utc)
	if !ok {
		L.RaiseError(errDateRange)
	}
	if format == "*t" {
		tbl := L.CreateTable(0, 9)
		setDateFields(L, tbl, tm)
		L.Push(tbl)
		return 1
	}
	buf := make([]byte, 0, len(format)+32)
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			buf = append(buf, format[i])
			continue
		}
		conv := format[i+1:]
		n := dateSpecLen(conv)
		if n == 0 {
			L.ArgError(1, fmt.Sprintf("invalid conversion specifier '%%%s'", conv))
		}
		buf = appendDateSpec(buf, tm, conv[n-1]) // E and O modifiers are no-ops in the "C" locale
		i += n
	}
	L.Push(LString(buf))
	return 1
}

// dateField reads the integer field key of a date table. d is the
// default for an absent field (negative: the field is mandatory) and
// delta is subtracted from the value, which must then fit a C int.
func dateField(L *LState, tbl LValue, key string, d int64, delta int64) int {
	v := L.GetField(tbl, key)
	var res int64
	ok := false
	if num, isnum := L.toNumberValue(v); isnum {
		res, ok = LVAsInteger(num)
	}
	if !ok {
		if v != LNil {
			L.RaiseError("field '%s' is not an integer", key)
		} else if d < 0 {
			L.RaiseError("field '%s' missing in date table", key)
		}
		return int(d)
	}
	if res >= 0 {
		ok = res-delta <= 1<<31-1
	} else {
		ok = -1<<31+delta <= res
	}
	if !ok {
		L.RaiseError("field '%s' is out-of-bound", key)
	}
	return int(res - delta)
}

// otherZoneOffset returns the UTC offset of the daylight saving (dst
// true) or standard variant of the zone of tm. ok is false if the
// location has no such variant around tm.
func otherZoneOffset(tm time.Time, dst bool) (offset int, ok bool) {
	start, end := tm.ZoneBounds()
	for _, neighbor := range []time.Time{end, start.Add(-time.Second)} {
		if !neighbor.IsZero() && neighbor.IsDST() == dst {
			_, offset = neighbor.Zone()
			return offset, true
		}
	}
	return 0, false
}

// os55Time implements os.time([table]).
func os55Time(L *LState) int {
	if L.Get(1) == LNil {
		L.Push(LInteger(time.Now().Unix()))
		return 1
	}
	tbl := L.CheckTable(1)
	year := dateField(L, tbl, "year", -1, 1900)
	month := dateField(L, tbl, "month", -1, 1)
	day := dateField(L, tbl, "day", -1, 0)
	hour := dateField(L, tbl, "hour", 12, 0)
	min := dateField(L, tbl, "min", 0, 0)
	sec := dateField(L, tbl, "sec", 0, 0)
	isdst := L.GetField(tbl, "isdst")
	tm := time.Date(year+1900, time.Month(month+1), day, hour, min, sec, 0, time.Local)
	if isdst != LNil {
		// The fields are given in a specific variant (daylight saving or
		// standard) of the local zone: apply the offset of that variant.
		_, offset := tm.Zone()
		ok := LVAsBool(isdst) == tm.IsDST()
		if !ok {
			offset, ok = otherZoneOffset(tm, LVAsBool(isdst))
		}
		if ok {
			wall := time.Date(year+1900, time.Month(month+1), day, hour, min, sec, 0, time.UTC)
			tm = time.Unix(wall.Unix()-int64(offset), 0)
		}
	}
	// Like the C library, -1 signals a time that cannot be represented.
	if !tmYearFits(tm) || tm.Unix() == -1 {
		L.RaiseError(errTimeRange)
	}
	setDateFields(L, tbl, tm) // update fields with normalized values
	L.Push(LInteger(tm.Unix()))
	return 1
}

/* }}} */

//
