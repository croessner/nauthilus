package core

import (
	"io"
	"log/slog"
)

func init() {
	SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}
