package logging

import (
	"os"

	"github.com/croessner/nauthilus/server/decl"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

var (
	DefaultLogger    log.Logger //nolint:gochecknoglobals // System wide logger
	DefaultErrLogger log.Logger //nolint:gochecknoglobals // System wide logger
)

// SetupLogging initializes the global "Logger" object.
func SetupLogging(configLogLevel int, formatJSON bool, instance string) {
	var logLevel level.Option

	if formatJSON {
		DefaultLogger = log.NewJSONLogger(log.NewSyncWriter(os.Stdout))
		DefaultErrLogger = log.NewJSONLogger(log.NewSyncWriter(os.Stderr))
	} else {
		DefaultLogger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
		DefaultErrLogger = log.NewLogfmtLogger(log.NewSyncWriter(os.Stderr))
	}

	switch configLogLevel {
	case decl.LogLevelNone:
		logLevel = level.AllowNone()
	case decl.LogLevelError:
		logLevel = level.AllowError()
	case decl.LogLevelWarn:
		logLevel = level.AllowWarn()
	case decl.LogLevelInfo:
		logLevel = level.AllowInfo()
	case decl.LogLevelDebug:
		logLevel = level.AllowDebug()
	}

	DefaultLogger = level.NewFilter(DefaultLogger, logLevel)

	DefaultLogger = log.With(
		DefaultLogger,
		"ts", log.DefaultTimestamp, "caller", log.DefaultCaller, decl.LogKeyInstance, instance,
	)
	DefaultErrLogger = log.With(
		DefaultErrLogger,
		"ts", log.DefaultTimestamp, "caller", log.DefaultCaller, decl.LogKeyInstance, instance,
	)
}
