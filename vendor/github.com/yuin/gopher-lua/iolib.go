package lua

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

var ioFuncs = map[string]LGFunction{
	"close":   ioClose,
	"flush":   ioFlush,
	"lines":   ioLines,
	"input":   ioInput,
	"output":  ioOutput,
	"open":    ioOpenFile,
	"popen":   ioPopen,
	"read":    ioRead,
	"type":    ioType,
	"tmpfile": ioTmpFile,
	"write":   ioWrite,
}

const lFileClass = "FILE*"

type lFile struct {
	fp     *os.File
	pp     *exec.Cmd
	writer io.Writer
	reader *bufio.Reader
	stdout io.ReadCloser
	closed bool

	// The fields below are only used by the Lua 5.5 profile.
	out     io.Writer // unbuffered destination of writer (nil: not writable)
	pipe    io.Closer // our end of the pipe of a process
	std     bool      // standard file: cannot be closed
	lineBuf bool      // flush the buffered writer after each line
}

type lFileType int

const (
	lFileFile lFileType = iota
	lFileProcess
)

const fileDefOutIndex = 1
const fileDefInIndex = 2
const fileDefaultWriteBuffer = 4096
const fileDefaultReadBuffer = 4096

func checkFile(L *LState) *lFile {
	ud := L.CheckUserData(1)
	if file, ok := ud.Value.(*lFile); ok {
		return file
	}
	L.ArgError(1, "file expected")
	return nil
}

func errorIfFileIsClosed(L *LState, file *lFile) {
	if file.closed {
		L.ArgError(1, "file is closed")
	}
}

func newFile(L *LState, file *os.File, path string, flag int, perm os.FileMode, writable, readable bool) (*LUserData, error) {
	ud := L.NewUserData()
	var err error
	if file == nil {
		file, err = os.OpenFile(path, flag, perm)
		if err != nil {
			return nil, err
		}
	}
	lfile := &lFile{fp: file, pp: nil, writer: nil, reader: nil, stdout: nil, closed: false}
	ud.Value = lfile
	if writable {
		lfile.writer = file
	}
	if readable {
		lfile.reader = bufio.NewReaderSize(file, fileDefaultReadBuffer)
	}
	L.SetMetatable(ud, L.GetTypeMetatable(lFileClass))
	return ud, nil
}

func newProcess(L *LState, cmd string, writable, readable bool) (*LUserData, error) {
	ud := L.NewUserData()
	c, args := popenArgs(cmd)
	pp := exec.Command(c, args...)
	lfile := &lFile{fp: nil, pp: pp, writer: nil, reader: nil, stdout: nil, closed: false}
	ud.Value = lfile

	var err error
	if writable {
		lfile.writer, err = pp.StdinPipe()
	}
	if readable {
		lfile.stdout, err = pp.StdoutPipe()
		lfile.reader = bufio.NewReaderSize(lfile.stdout, fileDefaultReadBuffer)
	}
	if err != nil {
		return nil, err
	}
	err = pp.Start()
	if err != nil {
		return nil, err
	}

	L.SetMetatable(ud, L.GetTypeMetatable(lFileClass))
	return ud, nil
}

func (file *lFile) Type() lFileType {
	if file.fp == nil {
		return lFileProcess
	}
	return lFileFile
}

func (file *lFile) Name() string {
	switch file.Type() {
	case lFileFile:
		return fmt.Sprintf("file %s", file.fp.Name())
	case lFileProcess:
		return fmt.Sprintf("process %s", file.pp.Path)
	}
	return ""
}

func (file *lFile) AbandonReadBuffer() error {
	if file.Type() == lFileFile && file.reader != nil {
		_, err := file.fp.Seek(-int64(file.reader.Buffered()), 1)
		if err != nil {
			return err
		}
		file.reader = bufio.NewReaderSize(file.fp, fileDefaultReadBuffer)
	}
	return nil
}

func fileDefOut(L *LState) *LUserData {
	return L.Get(UpvalueIndex(1)).(*LTable).RawGetInt(fileDefOutIndex).(*LUserData)
}

func fileDefIn(L *LState) *LUserData {
	return L.Get(UpvalueIndex(1)).(*LTable).RawGetInt(fileDefInIndex).(*LUserData)
}

func fileIsWritable(L *LState, file *lFile) int {
	if file.writer == nil {
		L.Push(LNil)
		L.Push(LString(fmt.Sprintf("%s is opened for only reading.", file.Name())))
		L.Push(LNumber(1)) // C-Lua compatibility: Original Lua pushes errno to the stack
		return 3
	}
	return 0
}

func fileIsReadable(L *LState, file *lFile) int {
	if file.reader == nil {
		L.Push(LNil)
		L.Push(LString(fmt.Sprintf("%s is opened for only writing.", file.Name())))
		L.Push(LNumber(1)) // C-Lua compatibility: Original Lua pushes errno to the stack
		return 3
	}
	return 0
}

var stdFiles = []struct {
	name     string
	file     *os.File
	writable bool
	readable bool
}{
	{"stdout", os.Stdout, true, false},
	{"stdin", os.Stdin, false, true},
	{"stderr", os.Stderr, true, false},
}

func OpenIo(L *LState) int {
	if L.is55() {
		return openIo55(L)
	}
	mod := L.RegisterModule(IoLibName, map[string]LGFunction{}).(*LTable)
	mt := L.NewTypeMetatable(lFileClass)
	mt.RawSetString("__index", mt)
	L.SetFuncs(mt, fileMethods)
	mt.RawSetString("lines", L.NewClosure(fileLines, L.NewFunction(fileLinesIter)))

	for _, finfo := range stdFiles {
		file, _ := newFile(L, finfo.file, "", 0, os.FileMode(0), finfo.writable, finfo.readable)
		mod.RawSetString(finfo.name, file)
	}
	uv := L.CreateTable(2, 0)
	uv.RawSetInt(fileDefOutIndex, mod.RawGetString("stdout"))
	uv.RawSetInt(fileDefInIndex, mod.RawGetString("stdin"))
	for name, fn := range ioFuncs {
		mod.RawSetString(name, L.NewClosure(fn, uv))
	}
	mod.RawSetString("lines", L.NewClosure(ioLines, uv, L.NewClosure(ioLinesIter, uv)))
	// Modifications are being made in-place rather than returned?
	L.Push(mod)
	return 1
}

var fileMethods = map[string]LGFunction{
	"__tostring": fileToString,
	"write":      fileWrite,
	"close":      fileClose,
	"flush":      fileFlush,
	"lines":      fileLines,
	"read":       fileRead,
	"seek":       fileSeek,
	"setvbuf":    fileSetVBuf,
}

func fileToString(L *LState) int {
	file := checkFile(L)
	if file.Type() == lFileFile {
		if file.closed {
			L.Push(LString("file (closed)"))
		} else {
			L.Push(LString("file"))
		}
	} else {
		if file.closed {
			L.Push(LString("process (closed)"))
		} else {
			L.Push(LString("process"))
		}
	}
	return 1
}

func fileWriteAux(L *LState, file *lFile, idx int) int {
	if n := fileIsWritable(L, file); n != 0 {
		return n
	}
	errorIfFileIsClosed(L, file)
	top := L.GetTop()
	out := file.writer
	var err error
	for i := idx; i <= top; i++ {
		L.CheckTypes(i, LTNumber, LTString)
		s := LVAsString(L.Get(i))
		if _, err = out.Write(unsafeFastStringToReadOnlyBytes(s)); err != nil {
			goto errreturn
		}
	}

	file.AbandonReadBuffer()
	L.Push(LTrue)
	return 1
errreturn:

	file.AbandonReadBuffer()
	L.Push(LNil)
	L.Push(LString(err.Error()))
	L.Push(LNumber(1)) // C-Lua compatibility: Original Lua pushes errno to the stack
	return 3
}

func fileCloseAux(L *LState, file *lFile) int {
	file.closed = true
	var err error
	if file.writer != nil {
		if bwriter, ok := file.writer.(*bufio.Writer); ok {
			if err = bwriter.Flush(); err != nil {
				goto errreturn
			}
		}
	}
	file.AbandonReadBuffer()

	switch file.Type() {
	case lFileFile:
		if err = file.fp.Close(); err != nil {
			goto errreturn
		}
		L.Push(LTrue)
		return 1
	case lFileProcess:
		if file.stdout != nil {
			file.stdout.Close() // ignore errors
		}
		err = file.pp.Wait()
		var exitStatus int // Initialised to zero value = 0
		if err != nil {
			if e2, ok := err.(*exec.ExitError); ok {
				if s, ok := e2.Sys().(syscall.WaitStatus); ok {
					exitStatus = s.ExitStatus()
				} else {
					err = errors.New("Unimplemented for system where exec.ExitError.Sys() is not syscall.WaitStatus.")
				}
			}
		} else {
			exitStatus = 0
		}
		L.Push(LNumber(exitStatus))
		return 1
	}

errreturn:
	L.RaiseError(err.Error())
	return 0
}

func fileFlushAux(L *LState, file *lFile) int {
	if n := fileIsWritable(L, file); n != 0 {
		return n
	}
	errorIfFileIsClosed(L, file)

	if bwriter, ok := file.writer.(*bufio.Writer); ok {
		if err := bwriter.Flush(); err != nil {
			L.Push(LNil)
			L.Push(LString(err.Error()))
			return 2
		}
	}
	L.Push(LTrue)
	return 1
}

func fileReadAux(L *LState, file *lFile, idx int) int {
	if n := fileIsReadable(L, file); n != 0 {
		return n
	}
	errorIfFileIsClosed(L, file)
	if L.GetTop() == idx-1 {
		L.Push(LString("*l"))
	}
	var err error
	top := L.GetTop()
	for i := idx; i <= top; i++ {
		switch lv := L.Get(i).(type) {
		case LNumber:
			size := int64(lv)
			if size == 0 {
				_, err = file.reader.ReadByte()
				if err == io.EOF {
					L.Push(LNil)
					goto normalreturn
				}
				file.reader.UnreadByte()
			}
			var buf []byte
			var iseof bool
			buf, err, iseof = readBufioSize(file.reader, size)
			if iseof {
				L.Push(LNil)
				goto normalreturn
			}
			if err != nil {
				goto errreturn
			}
			L.Push(LString(string(buf)))
		case LString:
			options := L.CheckString(i)
			if len(options) > 0 && options[0] != '*' {
				L.ArgError(2, "invalid options:"+options)
			}
			for _, opt := range options[1:] {
				switch opt {
				case 'n':
					var v LNumber
					_, err = fmt.Fscanf(file.reader, LNumberScanFormat, &v)
					if err == io.EOF {
						L.Push(LNil)
						goto normalreturn
					}
					if err != nil {
						goto errreturn
					}
					L.Push(v)
				case 'a':
					var buf []byte
					buf, err = io.ReadAll(file.reader)
					if err == io.EOF {
						L.Push(emptyLString)
						goto normalreturn
					}
					if err != nil {
						goto errreturn
					}
					L.Push(LString(string(buf)))
				case 'l':
					var buf []byte
					var iseof bool
					buf, err, iseof = readBufioLine(file.reader)
					if iseof {
						L.Push(LNil)
						goto normalreturn
					}
					if err != nil {
						goto errreturn
					}
					L.Push(LString(string(buf)))
				default:
					L.ArgError(2, "invalid options:"+string(opt))
				}
			}
		}
	}
normalreturn:
	return L.GetTop() - top

errreturn:
	L.Push(LNil)
	L.Push(LString(err.Error()))
	L.Push(LNumber(1)) // C-Lua compatibility: Original Lua pushes errno to the stack
	return 3
}

var fileSeekOptions = []string{"set", "cur", "end"}

func fileSeek(L *LState) int {
	file := checkFile(L)
	if file.Type() != lFileFile {
		L.Push(LNil)
		L.Push(LString("can not seek a process."))
		return 2
	}

	top := L.GetTop()
	if top == 1 {
		L.Push(LString("cur"))
		L.Push(LNumber(0))
	} else if top == 2 {
		L.Push(LNumber(0))
	}

	var pos int64
	var err error

	err = file.AbandonReadBuffer()
	if err != nil {
		goto errreturn
	}

	pos, err = file.fp.Seek(L.CheckInt64(3), L.CheckOption(2, fileSeekOptions))
	if err != nil {
		goto errreturn
	}

	L.Push(LNumber(pos))
	return 1

errreturn:
	L.Push(LNil)
	L.Push(LString(err.Error()))
	return 2
}

func fileWrite(L *LState) int {
	return fileWriteAux(L, checkFile(L), 2)
}

func fileClose(L *LState) int {
	return fileCloseAux(L, checkFile(L))
}

func fileFlush(L *LState) int {
	return fileFlushAux(L, checkFile(L))
}

func fileLinesIter(L *LState) int {
	var file *lFile
	if ud, ok := L.Get(1).(*LUserData); ok {
		file = ud.Value.(*lFile)
	} else {
		file = L.Get(UpvalueIndex(2)).(*LUserData).Value.(*lFile)
	}
	buf, _, err := file.reader.ReadLine()
	if err != nil {
		if err == io.EOF {
			L.Push(LNil)
			return 1
		}
		L.RaiseError(err.Error())
	}
	L.Push(LString(string(buf)))
	return 1
}

func fileLines(L *LState) int {
	file := checkFile(L)
	ud := L.CheckUserData(1)
	if n := fileIsReadable(L, file); n != 0 {
		return 0
	}
	L.Push(L.NewClosure(fileLinesIter, L.Get(UpvalueIndex(1)), ud))
	return 1
}

func fileRead(L *LState) int {
	return fileReadAux(L, checkFile(L), 2)
}

var filebufOptions = []string{"no", "full"}

func fileSetVBuf(L *LState) int {
	var err error
	var writer io.Writer
	file := checkFile(L)
	if n := fileIsWritable(L, file); n != 0 {
		return n
	}
	switch filebufOptions[L.CheckOption(2, filebufOptions)] {
	case "no":
		switch file.Type() {
		case lFileFile:
			file.writer = file.fp
		case lFileProcess:
			file.writer, err = file.pp.StdinPipe()
			if err != nil {
				goto errreturn
			}
		}
	case "full", "line": // TODO line buffer not supported
		bufsize := L.OptInt(3, fileDefaultWriteBuffer)
		switch file.Type() {
		case lFileFile:
			file.writer = bufio.NewWriterSize(file.fp, bufsize)
		case lFileProcess:
			writer, err = file.pp.StdinPipe()
			if err != nil {
				goto errreturn
			}
			file.writer = bufio.NewWriterSize(writer, bufsize)
		}
	}
	L.Push(LTrue)
	return 1
errreturn:
	L.Push(LNil)
	L.Push(LString(err.Error()))
	return 2
}

func ioInput(L *LState) int {
	if L.GetTop() == 0 {
		L.Push(fileDefIn(L))
		return 1
	}
	switch lv := L.Get(1).(type) {
	case LString:
		file, err := newFile(L, nil, string(lv), os.O_RDONLY, 0600, false, true)
		if err != nil {
			L.RaiseError(err.Error())
		}
		L.Get(UpvalueIndex(1)).(*LTable).RawSetInt(fileDefInIndex, file)
		L.Push(file)
		return 1
	case *LUserData:
		if _, ok := lv.Value.(*lFile); ok {
			L.Get(UpvalueIndex(1)).(*LTable).RawSetInt(fileDefInIndex, lv)
			L.Push(lv)
			return 1
		}

	}
	L.ArgError(1, "string or file expedted, but got "+L.Get(1).Type().String())
	return 0
}

func ioClose(L *LState) int {
	if L.GetTop() == 0 {
		return fileCloseAux(L, fileDefOut(L).Value.(*lFile))
	}
	return fileClose(L)
}

func ioFlush(L *LState) int {
	return fileFlushAux(L, fileDefOut(L).Value.(*lFile))
}

func ioLinesIter(L *LState) int {
	var file *lFile
	toclose := false
	if ud, ok := L.Get(1).(*LUserData); ok {
		file = ud.Value.(*lFile)
	} else {
		file = L.Get(UpvalueIndex(2)).(*LUserData).Value.(*lFile)
		toclose = true
	}
	buf, _, err := file.reader.ReadLine()
	if err != nil {
		if err == io.EOF {
			if toclose {
				fileCloseAux(L, file)
			}
			L.Push(LNil)
			return 1
		}
		L.RaiseError(err.Error())
	}
	L.Push(LString(string(buf)))
	return 1
}

func ioLines(L *LState) int {
	if L.GetTop() == 0 {
		L.Push(L.Get(UpvalueIndex(2)))
		L.Push(fileDefIn(L))
		return 2
	}

	path := L.CheckString(1)
	ud, err := newFile(L, nil, path, os.O_RDONLY, os.FileMode(0600), false, true)
	if err != nil {
		return 0
	}
	L.Push(L.NewClosure(ioLinesIter, L.Get(UpvalueIndex(1)), ud))
	return 1
}

var ioOpenOpions = []string{"r", "rb", "w", "wb", "a", "ab", "r+", "rb+", "w+", "wb+", "a+", "ab+"}

func ioOpenFile(L *LState) int {
	path := L.CheckString(1)
	if L.GetTop() == 1 {
		L.Push(LString("r"))
	}
	mode := os.O_RDONLY
	perm := 0600
	writable := true
	readable := true
	switch ioOpenOpions[L.CheckOption(2, ioOpenOpions)] {
	case "r", "rb":
		mode = os.O_RDONLY
		writable = false
	case "w", "wb":
		mode = os.O_WRONLY | os.O_TRUNC | os.O_CREATE
		readable = false
	case "a", "ab":
		mode = os.O_WRONLY | os.O_APPEND | os.O_CREATE
	case "r+", "rb+":
		mode = os.O_RDWR
	case "w+", "wb+":
		mode = os.O_RDWR | os.O_TRUNC | os.O_CREATE
	case "a+", "ab+":
		mode = os.O_APPEND | os.O_RDWR | os.O_CREATE
	}
	file, err := newFile(L, nil, path, mode, os.FileMode(perm), writable, readable)
	if err != nil {
		L.Push(LNil)
		L.Push(LString(err.Error()))
		L.Push(LNumber(1)) // C-Lua compatibility: Original Lua pushes errno to the stack
		return 3
	}
	L.Push(file)
	return 1

}

var ioPopenOptions = []string{"r", "w"}

func ioPopen(L *LState) int {
	cmd := L.CheckString(1)
	if L.GetTop() == 1 {
		L.Push(LString("r"))
	} else if L.GetTop() > 1 && (L.Get(2)).Type() == LTNil {
		L.SetTop(1)
		L.Push(LString("r"))
	}
	var file *LUserData
	var err error

	switch ioPopenOptions[L.CheckOption(2, ioPopenOptions)] {
	case "r":
		file, err = newProcess(L, cmd, false, true)
	case "w":
		file, err = newProcess(L, cmd, true, false)
	}
	if err != nil {
		L.Push(LNil)
		L.Push(LString(err.Error()))
		return 2
	}
	L.Push(file)
	return 1
}

func ioRead(L *LState) int {
	return fileReadAux(L, fileDefIn(L).Value.(*lFile), 1)
}

func ioType(L *LState) int {
	ud, udok := L.Get(1).(*LUserData)
	if !udok {
		L.Push(LNil)
		return 1
	}
	file, ok := ud.Value.(*lFile)
	if !ok {
		L.Push(LNil)
		return 1
	}
	if file.closed {
		L.Push(LString("closed file"))
		return 1
	}
	L.Push(LString("file"))
	return 1
}

func ioTmpFile(L *LState) int {
	file, err := os.CreateTemp("", "")
	if err != nil {
		L.Push(LNil)
		L.Push(LString(err.Error()))
		return 2
	}
	L.G.tempFiles = append(L.G.tempFiles, file)
	ud, _ := newFile(L, file, "", 0, os.FileMode(0), true, true)
	L.Push(ud)
	return 1
}

func ioOutput(L *LState) int {
	if L.GetTop() == 0 {
		L.Push(fileDefOut(L))
		return 1
	}
	switch lv := L.Get(1).(type) {
	case LString:
		file, err := newFile(L, nil, string(lv), os.O_WRONLY|os.O_CREATE, 0600, true, false)
		if err != nil {
			L.RaiseError(err.Error())
		}
		L.Get(UpvalueIndex(1)).(*LTable).RawSetInt(fileDefOutIndex, file)
		L.Push(file)
		return 1
	case *LUserData:
		if _, ok := lv.Value.(*lFile); ok {
			L.Get(UpvalueIndex(1)).(*LTable).RawSetInt(fileDefOutIndex, lv)
			L.Push(lv)
			return 1
		}

	}
	L.ArgError(1, "string or file expedted, but got "+L.Get(1).Type().String())
	return 0
}

func ioWrite(L *LState) int {
	return fileWriteAux(L, fileDefOut(L).Value.(*lFile), 1)
}

/* Lua 5.5 profile {{{ */

var io55Funcs = map[string]LGFunction{
	"close":   io55Close,
	"flush":   io55Flush,
	"input":   io55Input,
	"lines":   io55Lines,
	"open":    io55Open,
	"output":  io55Output,
	"popen":   io55Popen,
	"read":    io55Read,
	"tmpfile": io55TmpFile,
	"type":    io55Type,
	"write":   io55Write,
}

var file55Methods = map[string]LGFunction{
	"close":   file55Close,
	"flush":   file55Flush,
	"lines":   file55Lines,
	"read":    file55Read,
	"seek":    file55Seek,
	"setvbuf": file55SetVBuf,
	"write":   file55Write,
}

var file55MetaMethods = map[string]LGFunction{
	"__close":    file55GC,
	"__gc":       file55GC,
	"__tostring": file55ToString,
}

// fileMaxLineFormats is the maximum number of formats accepted by the
// lines functions.
const fileMaxLineFormats = 250

// fileMaxNumeralLen is the maximum length of a numeral read with the
// "n" format.
const fileMaxNumeralLen = 200

// fileMaxBufferSize bounds the buffer size accepted by setvbuf.
const fileMaxBufferSize = 1 << 24

// errReader is the input side of a file that is not open for reading.
type errReader struct{ err error }

// Read always fails with the configured error.
func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// openIo55 registers the io library of the Lua 5.5 profile.
func openIo55(L *LState) int {
	mod := L.RegisterModule(IoLibName, map[string]LGFunction{}).(*LTable)
	mt := L.NewTypeMetatable(lFileClass)
	mt.RawSetString("__name", LString(lFileClass))
	mt.RawSetString("__index", L.SetFuncs(L.NewTable(), file55Methods))
	L.SetFuncs(mt, file55MetaMethods)

	for _, finfo := range stdFiles {
		ud := newFile55(L, finfo.file, finfo.readable, finfo.writable)
		ud.Value.(*lFile).std = true
		mod.RawSetString(finfo.name, ud)
	}
	uv := L.CreateTable(2, 0)
	uv.RawSetInt(fileDefOutIndex, mod.RawGetString("stdout"))
	uv.RawSetInt(fileDefInIndex, mod.RawGetString("stdin"))
	L.SetFuncs(mod, io55Funcs, uv)
	L.Push(mod)
	return 1
}

// newFile55 wraps an open file in a file handle.
func newFile55(L *LState, fp *os.File, readable, writable bool) *LUserData {
	file := &lFile{fp: fp}
	if writable {
		file.out, file.writer = fp, fp
	}
	if readable {
		file.reader = bufio.NewReaderSize(fp, fileDefaultReadBuffer)
	} else {
		file.reader = bufio.NewReaderSize(errReader{syscall.EBADF}, 16)
	}
	return newFileHandle55(L, file)
}

// newFileHandle55 creates the userdata of a file handle.
func newFileHandle55(L *LState, file *lFile) *LUserData {
	ud := L.NewUserData()
	ud.Value = file
	L.SetMetatable(ud, L.GetTypeMetatable(lFileClass))
	return ud
}

// fileModeValid reports whether mode is a valid io.open mode
// ("[rwa]%+?b*").
func fileModeValid(mode string) bool {
	if mode == "" || strings.IndexByte("rwa", mode[0]) < 0 {
		return false
	}
	rest := strings.TrimPrefix(mode[1:], "+")
	return strings.Trim(rest, "b") == ""
}

// openFile55 opens the named file with a (valid) C style mode.
func openFile55(L *LState, path, mode string) (*LUserData, error) {
	update := len(mode) > 1 && mode[1] == '+'
	var flag int
	readable, writable := update, true
	switch mode[0] {
	case 'r':
		flag, readable, writable = os.O_RDONLY, true, update
	case 'w':
		flag = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	default:
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	if update {
		flag = flag&^(os.O_RDONLY|os.O_WRONLY) | os.O_RDWR
	}
	fp, err := os.OpenFile(path, flag, 0666)
	if err != nil {
		return nil, err
	}
	if mode[0] == 'a' && (!update || appendUpdateStartsAtEnd()) {
		fp.Seek(0, io.SeekEnd) // only the initial read position; ignore errors
	}
	return newFile55(L, fp, readable, writable), nil
}

// appendUpdateStartsAtEnd reports whether a file opened in mode "a+" is
// initially positioned at its end (as the BSD C libraries do) instead of
// its beginning.
func appendUpdateStartsAtEnd() bool {
	switch runtime.GOOS {
	case "darwin", "ios", "freebsd", "netbsd", "openbsd", "dragonfly":
		return true
	}
	return false
}

// openCheckFile55 opens the named file and raises an error on failure.
func openCheckFile55(L *LState, path, mode string) *LUserData {
	ud, err := openFile55(L, path, mode)
	if err != nil {
		msg, _ := cErrorInfo(err)
		L.RaiseError("cannot open file '%s' (%s)", path, msg)
	}
	return ud
}

// newProcess55 starts a shell command whose output can be read (mode
// "r") or whose input can be written (mode "w"). The other standard
// streams are inherited.
func newProcess55(L *LState, command, mode string) (*LUserData, error) {
	name, args := popenArgs(command)
	pp := exec.Command(name, args...)
	pp.Stderr = os.Stderr
	file := &lFile{pp: pp}
	if mode == "r" {
		pp.Stdin = os.Stdin
		out, err := pp.StdoutPipe()
		if err != nil {
			return nil, err
		}
		file.pipe = out
		file.reader = bufio.NewReaderSize(out, fileDefaultReadBuffer)
	} else {
		pp.Stdout = os.Stdout
		in, err := pp.StdinPipe()
		if err != nil {
			return nil, err
		}
		file.pipe, file.out, file.writer = in, in, in
		file.reader = bufio.NewReaderSize(errReader{syscall.EBADF}, 16)
	}
	if err := pp.Start(); err != nil {
		return nil, err
	}
	return newFileHandle55(L, file), nil
}

// fileTypeError raises the error for an argument that is not a file.
func fileTypeError(L *LState, n int) {
	got := "no value"
	if n <= L.GetTop() {
		got = L.typeNameOf(L.Get(n))
	}
	L.ArgError(n, lFileClass+" expected, got "+got)
}

// toFile55 returns the file of the handle v, or nil if v is not a file.
func toFile55(v LValue) *lFile {
	if ud, ok := v.(*LUserData); ok {
		if file, ok := ud.Value.(*lFile); ok {
			return file
		}
	}
	return nil
}

// checkFile55 checks that argument n is a file handle (open or closed).
func checkFile55(L *LState, n int) *lFile {
	file := toFile55(L.Get(n))
	if file == nil {
		fileTypeError(L, n)
	}
	return file
}

// checkOpenFile55 checks that argument n is an open file handle.
func checkOpenFile55(L *LState, n int) *lFile {
	file := checkFile55(L, n)
	if file.closed {
		L.RaiseError("attempt to use a closed file")
	}
	return file
}

// defaultFile55 returns the default input or output file, which must be
// open.
func defaultFile55(L *LState, index int) (*LUserData, *lFile) {
	ud := L.Get(UpvalueIndex(1)).(*LTable).RawGetInt(index).(*LUserData)
	file := ud.Value.(*lFile)
	if file.closed {
		what := "output"
		if index == fileDefInIndex {
			what = "input"
		}
		L.RaiseError("default %s file is closed", what)
	}
	return ud, file
}

// flush55 writes buffered output to the underlying file.
func (file *lFile) flush55() error {
	if bw, ok := file.writer.(*bufio.Writer); ok {
		return bw.Flush()
	}
	return nil
}

// dropReadAhead discards buffered input and moves the file position back
// to the logical read position, so that a write goes where the program
// expects it.
func (file *lFile) dropReadAhead() {
	n := file.reader.Buffered()
	if n == 0 || file.fp == nil {
		return
	}
	if _, err := file.fp.Seek(-int64(n), io.SeekCurrent); err == nil {
		file.reader.Discard(n)
	}
}

// write55 writes s and returns the number of bytes written.
func (file *lFile) write55(s string) (int, error) {
	if file.writer == nil {
		return 0, syscall.EBADF
	}
	file.dropReadAhead()
	n, err := io.WriteString(file.writer, s)
	if err == nil && file.lineBuf && strings.IndexByte(s, '\n') >= 0 {
		err = file.flush55()
	}
	return n, err
}

// close55 closes the file and pushes the results of the close
// operation.
func (file *lFile) close55(L *LState) int {
	if file.std {
		L.Push(LNil)
		L.Push(LString("cannot close standard file"))
		return 2
	}
	file.closed = true
	err := file.flush55()
	if file.Type() == lFileProcess {
		file.pipe.Close() // ignore errors
		return pushExecResult(L, file.pp.Wait())
	}
	if cerr := file.fp.Close(); err == nil {
		err = cerr
	}
	return pushFileResult(L, err, "")
}

// flushStandardFiles flushes the buffered output of io.stdout and
// io.stderr (used before the process exits).
func flushStandardFiles(L *LState) {
	loaded, ok := L.GetField(L.Get(RegistryIndex), "_LOADED").(*LTable)
	if !ok {
		return
	}
	mod, ok := loaded.RawGetString(IoLibName).(*LTable)
	if !ok {
		return
	}
	for _, name := range []string{"stdout", "stderr"} {
		if file := toFile55(mod.RawGetString(name)); file != nil {
			file.flush55() // ignore errors
		}
	}
}

/* reading {{{ */

// numeralReader accumulates the longest prefix of the input that can be
// a numeral, reading with a look-ahead of one character.
type numeralReader struct {
	r        *bufio.Reader
	buf      []byte
	overflow bool
	err      error // read error other than the end of the input
}

// peek returns the next input character without consuming it; ok is
// false at the end of the input or after a read error.
func (rn *numeralReader) peek() (c byte, ok bool) {
	b, err := rn.r.Peek(1)
	if err != nil {
		if err != io.EOF {
			rn.err = err
		}
		return 0, false
	}
	return b[0], true
}

// accept consumes the next character if it is one of set. It fails (and
// invalidates the numeral) if the numeral becomes too long.
func (rn *numeralReader) accept(set string) bool {
	c, ok := rn.peek()
	if !ok || strings.IndexByte(set, c) < 0 {
		return false
	}
	if len(rn.buf) >= fileMaxNumeralLen {
		rn.overflow = true
		return false
	}
	rn.buf = append(rn.buf, c)
	rn.r.Discard(1)
	return true
}

// digits consumes a sequence of (hexa)decimal digits and returns its
// length.
func (rn *numeralReader) digits(hex bool) int {
	set := "0123456789"
	if hex {
		set = "0123456789abcdefABCDEF"
	}
	n := 0
	for rn.accept(set) {
		n++
	}
	return n
}

// readNumber implements the "n" read format.
func (file *lFile) readNumber() (LValue, bool, error) {
	rn := &numeralReader{r: file.reader}
	for {
		c, ok := rn.peek()
		if !ok || !isLuaSpace(c) {
			break
		}
		rn.r.Discard(1)
	}
	count := 0
	hex := false
	rn.accept("-+") // optional sign
	if rn.accept("0") {
		if rn.accept("xX") {
			hex = true
		} else {
			count = 1 // the initial '0' is a valid digit
		}
	}
	count += rn.digits(hex) // integral part
	if rn.accept(".") {
		count += rn.digits(hex) // fractional part
	}
	exponent := "eE"
	if hex {
		exponent = "pP"
	}
	if count > 0 && rn.accept(exponent) {
		rn.accept("-+") // exponent sign
		rn.digits(false)
	}
	if rn.overflow || rn.err != nil {
		return LNil, false, rn.err
	}
	if v, ok := str2Number55(string(rn.buf)); ok {
		return v, true, nil
	}
	return LNil, false, nil
}

// readLine implements the "l" (chop true) and "L" read formats.
func (file *lFile) readLine(chop bool) (LValue, bool, error) {
	line, err := file.reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return LNil, false, err
	}
	ok := len(line) > 0
	if chop && ok && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	return LString(line), ok, nil
}

// readChars reads up to n bytes; n == 0 only tests for the end of file.
func (file *lFile) readChars(n int64) (LValue, bool, error) {
	if n == 0 {
		_, err := file.reader.Peek(1)
		if err != nil && err != io.EOF {
			return LNil, false, err
		}
		return emptyLString, err == nil, nil
	}
	buf, err := io.ReadAll(io.LimitReader(file.reader, n))
	if err != nil {
		return LNil, false, err
	}
	return LString(buf), len(buf) > 0, nil
}

// read55 reads the given formats (a line if there is none) and pushes
// the results; firstArg is the argument index of the first format in
// error messages. It returns the number of results.
func (file *lFile) read55(L *LState, formats []LValue, firstArg int) int {
	file.flush55() // make pending output visible; errors show up on reads
	top := L.GetTop()
	var v LValue
	var err error
	success := true
	if len(formats) == 0 {
		v, success, err = file.readLine(true)
		L.Push(v)
	}
	for i := 0; i < len(formats) && success && err == nil; i++ {
		arg := firstArg + i
		switch format := formats[i].(type) {
		case LNumber, LInteger:
			n, _ := L.argInteger(arg, format)
			if n < 0 {
				L.RaiseError("resulting string too large")
			}
			v, success, err = file.readChars(n)
		case LString:
			spec := strings.TrimPrefix(string(format), "*") // optional, for compatibility
			if spec == "" {
				L.ArgError(arg, "invalid format")
			}
			switch spec[0] {
			case 'n':
				v, success, err = file.readNumber()
			case 'l':
				v, success, err = file.readLine(true)
			case 'L':
				v, success, err = file.readLine(false)
			case 'a':
				var data []byte
				data, err = io.ReadAll(file.reader)
				v, success = LString(data), true
			default:
				L.ArgError(arg, "invalid format")
			}
		default:
			// The formats may not be on the stack (see lines55).
			L.ArgError(arg, "string expected, got "+L.typeNameOf(format))
		}
		L.Push(v)
	}
	if err != nil {
		return pushFileResult(L, err, "")
	}
	if !success {
		L.Pop(1) // remove the last result
		L.Push(LNil)
	}
	return L.GetTop() - top
}

// fileArgs returns the arguments from index first on.
func fileArgs(L *LState, first int) []LValue {
	top := L.GetTop()
	if top < first {
		return nil
	}
	args := make([]LValue, 0, top-first+1)
	for i := first; i <= top; i++ {
		args = append(args, L.Get(i))
	}
	return args
}

// lines55 returns an iterator that reads the formats given as arguments
// 2... from the file on each call. If toclose is set the file is closed
// when the iteration ends.
func lines55(L *LState, file *lFile, toclose bool) *LFunction {
	formats := fileArgs(L, 2)
	if len(formats) > fileMaxLineFormats {
		L.ArgError(fileMaxLineFormats+2, "too many arguments")
	}
	return L.NewFunction(func(L *LState) int {
		if file.closed {
			L.RaiseError("file is already closed")
		}
		n := file.read55(L, formats, 2)
		first := L.GetTop() - n + 1
		if LVAsBool(L.Get(first)) {
			return n
		}
		if n > 1 { // the second result is the error message
			L.RaiseError("%s", LVAsString(L.Get(first+1)))
		}
		if toclose {
			L.Pop(file.close55(L))
		}
		return 0
	})
}

/* }}} */

/* file methods {{{ */

// file55Close implements file:close().
func file55Close(L *LState) int {
	return checkOpenFile55(L, 1).close55(L)
}

// file55GC implements the __gc and __close metamethods: it closes files
// that are still open.
func file55GC(L *LState) int {
	if file := checkFile55(L, 1); !file.closed {
		L.Pop(file.close55(L)) // ignore the results
	}
	return 0
}

// file55ToString implements the __tostring metamethod.
func file55ToString(L *LState) int {
	file := checkFile55(L, 1)
	if file.closed {
		L.Push(LString("file (closed)"))
	} else {
		L.Push(LString(fmt.Sprintf("file (%p)", file)))
	}
	return 1
}

// file55Flush implements file:flush().
func file55Flush(L *LState) int {
	return pushFileResult(L, checkOpenFile55(L, 1).flush55(), "")
}

// file55Lines implements file:lines(...).
func file55Lines(L *LState) int {
	L.Push(lines55(L, checkOpenFile55(L, 1), false))
	return 1
}

// file55Read implements file:read(...).
func file55Read(L *LState) int {
	return checkOpenFile55(L, 1).read55(L, fileArgs(L, 2), 2)
}

// file55Seek implements file:seek([whence [, offset]]).
func file55Seek(L *LState) int {
	file := checkOpenFile55(L, 1)
	whence := checkOptionArg(L, 2, "cur", fileSeekOptions)
	offset := L.OptInt64(3, 0)
	if file.Type() != lFileFile {
		return pushFileResult(L, syscall.ESPIPE, "")
	}
	if err := file.flush55(); err != nil {
		return pushFileResult(L, err, "")
	}
	if whence == io.SeekCurrent {
		offset -= int64(file.reader.Buffered()) // relative to the logical position
	}
	pos, err := file.fp.Seek(offset, whence)
	if err != nil {
		return pushFileResult(L, err, "")
	}
	file.reader.Discard(file.reader.Buffered())
	L.Push(LInteger(pos))
	return 1
}

var filebuf55Options = []string{"no", "full", "line"}

// file55SetVBuf implements file:setvbuf(mode [, size]).
func file55SetVBuf(L *LState) int {
	file := checkOpenFile55(L, 1)
	mode := filebuf55Options[checkOptionArg(L, 2, "", filebuf55Options)]
	size := L.OptInt64(3, fileDefaultWriteBuffer)
	if mode != "no" && size < 0 {
		L.Push(LNil)
		L.Push(LString("(no extra info)"))
		L.Push(LInteger(0))
		return 3
	}
	if err := file.flush55(); err != nil {
		return pushFileResult(L, err, "")
	}
	file.lineBuf = mode == "line"
	if file.out != nil {
		if mode == "no" {
			file.writer = file.out
		} else {
			file.writer = bufio.NewWriterSize(file.out, int(min(max(size, 1), fileMaxBufferSize)))
		}
	}
	L.Push(LTrue)
	return 1
}

// write55 writes the arguments from index first on to the file and
// returns the file handle, or the failure results followed by the number
// of bytes written.
func write55(L *LState, handle LValue, file *lFile, first int) int {
	top := L.GetTop()
	total := 0
	for i := first; i <= top; i++ {
		var s string
		switch v := L.Get(i).(type) {
		case LString:
			s = string(v)
		case LNumber, LInteger:
			s = L.numToString(v)
		default:
			L.TypeError(i, LTString)
		}
		n, err := file.write55(s)
		total += n
		if err != nil {
			nret := pushFileResult(L, err, "")
			L.Push(LInteger(total))
			return nret + 1
		}
	}
	L.Push(handle)
	return 1
}

// file55Write implements file:write(...).
func file55Write(L *LState) int {
	return write55(L, L.Get(1), checkOpenFile55(L, 1), 2)
}

/* }}} */

/* io functions {{{ */

// io55Close implements io.close([file]).
func io55Close(L *LState) int {
	if L.GetTop() == 0 {
		file := L.Get(UpvalueIndex(1)).(*LTable).RawGetInt(fileDefOutIndex).(*LUserData).Value.(*lFile)
		if file.closed {
			L.RaiseError("attempt to use a closed file")
		}
		return file.close55(L)
	}
	return file55Close(L)
}

// io55Flush implements io.flush().
func io55Flush(L *LState) int {
	_, file := defaultFile55(L, fileDefOutIndex)
	return pushFileResult(L, file.flush55(), "")
}

// io55SetDefault implements io.input and io.output: it optionally
// replaces the default file (by a file handle or a file to open with
// the given mode) and returns the current one.
func io55SetDefault(L *LState, index int, mode string) int {
	defaults := L.Get(UpvalueIndex(1)).(*LTable)
	switch v := L.Get(1).(type) {
	case *LNilType:
	case LString, LNumber, LInteger:
		defaults.RawSetInt(index, openCheckFile55(L, L.valueToString(v), mode))
	default:
		checkOpenFile55(L, 1)
		defaults.RawSetInt(index, v)
	}
	L.Push(defaults.RawGetInt(index))
	return 1
}

// io55Input implements io.input([file]).
func io55Input(L *LState) int {
	return io55SetDefault(L, fileDefInIndex, "r")
}

// io55Output implements io.output([file]).
func io55Output(L *LState) int {
	return io55SetDefault(L, fileDefOutIndex, "w")
}

// io55Lines implements io.lines([filename, ...]).
func io55Lines(L *LState) int {
	if L.Get(1) == LNil { // no file name: iterate over the default input
		ud := L.Get(UpvalueIndex(1)).(*LTable).RawGetInt(fileDefInIndex)
		file := toFile55(ud)
		if file.closed {
			L.RaiseError("attempt to use a closed file")
		}
		L.Push(lines55(L, file, false))
		return 1
	}
	ud := openCheckFile55(L, checkStringArg(L, 1), "r")
	L.Push(lines55(L, ud.Value.(*lFile), true))
	L.Push(LNil) // state
	L.Push(LNil) // control
	L.Push(ud)   // the file is the to-be-closed variable
	return 4
}

// io55Open implements io.open(filename [, mode]).
func io55Open(L *LState) int {
	path := checkStringArg(L, 1)
	mode := optStringArg(L, 2, "r")
	if !fileModeValid(mode) {
		L.ArgError(2, "invalid mode")
	}
	ud, err := openFile55(L, path, mode)
	if err != nil {
		return pushFileResult(L, err, path)
	}
	L.Push(ud)
	return 1
}

// io55Popen implements io.popen(prog [, mode]).
func io55Popen(L *LState) int {
	command := checkStringArg(L, 1)
	mode := optStringArg(L, 2, "r")
	if mode != "r" && mode != "w" {
		L.ArgError(2, "invalid mode")
	}
	ud, err := newProcess55(L, command, mode)
	if err != nil {
		return pushFileResult(L, err, command)
	}
	L.Push(ud)
	return 1
}

// io55Read implements io.read(...).
func io55Read(L *LState) int {
	_, file := defaultFile55(L, fileDefInIndex)
	return file.read55(L, fileArgs(L, 1), 1)
}

// io55TmpFile implements io.tmpfile().
func io55TmpFile(L *LState) int {
	fp, err := createTempFile()
	if err != nil {
		return pushFileResult(L, err, "")
	}
	if os.Remove(fp.Name()) != nil {
		// The system cannot unlink open files: remove it when the state closes.
		L.G.tempFiles = append(L.G.tempFiles, fp)
	}
	L.Push(newFile55(L, fp, true, true))
	return 1
}

// io55Type implements io.type(obj).
func io55Type(L *LState) int {
	file := toFile55(L.CheckAny(1))
	switch {
	case file == nil:
		L.Push(LNil)
	case file.closed:
		L.Push(LString("closed file"))
	default:
		L.Push(LString("file"))
	}
	return 1
}

// io55Write implements io.write(...).
func io55Write(L *LState) int {
	ud, file := defaultFile55(L, fileDefOutIndex)
	return write55(L, ud, file, 1)
}

/* }}} */

/* }}} */

//
