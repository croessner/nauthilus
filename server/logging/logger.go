package logging

import (
	"os"
	"sync"

	"github.com/croessner/nauthilus/server/global"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-kit/log/term"
)

var (
	mu sync.Mutex

	// Logger is used for all messages that are printed to stdout
	Logger log.Logger
)

// SetupLogging initializes the global "Logger" object.
func SetupLogging(configLogLevel int, formatJSON bool, useColor bool, instance string) {
	var logLevel level.Option

	mu.Lock()

	defer mu.Unlock()

	if useColor {
		colorFn := func(keyvals ...any) term.FgBgColor {
			for i := 0; i < len(keyvals)-1; i += 2 {
				if keyvals[i] != level.Key() {
					continue
				}

				switch keyvals[i+1] {
				case level.DebugValue():
					return term.FgBgColor{Fg: term.Gray}
				case level.InfoValue():
					return term.FgBgColor{Fg: term.Default}
				case level.WarnValue():
					return term.FgBgColor{Fg: term.Yellow}
				case level.ErrorValue():
					return term.FgBgColor{Fg: term.Red}
				default:
					return term.FgBgColor{}
				}
			}

			return term.FgBgColor{}
		}

		if formatJSON {
			Logger = term.NewLogger(os.Stdout, log.NewJSONLogger, colorFn)
		} else {
			Logger = term.NewLogger(os.Stdout, log.NewLogfmtLogger, colorFn)
		}
	} else {
		if formatJSON {
			Logger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
		} else {
			Logger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
		}
	}

	switch configLogLevel {
	case global.LogLevelNone:
		logLevel = level.AllowNone()
	case global.LogLevelError:
		logLevel = level.AllowError()
	case global.LogLevelWarn:
		logLevel = level.AllowWarn()
	case global.LogLevelInfo:
		logLevel = level.AllowInfo()
	case global.LogLevelDebug:
		logLevel = level.AllowDebug()
	}

	Logger = level.NewFilter(Logger, logLevel)

	Logger = log.With(
		Logger,
		"ts", log.DefaultTimestamp, "caller", log.DefaultCaller, global.LogKeyInstance, instance,
	)
}
