package engine

import (
	"errors"
	"fmt"
	"io"
)

// App wires source->filter->renderer->sink and runs the pipeline.
type App struct {
	Source RecordSource
	Filter RecordFilter
	Render Renderer
	Sink   Sink
}

// Run executes the pipeline until the source is exhausted.
func (a *App) Run() (int, error) {
	if a.Source == nil || a.Filter == nil || a.Render == nil || a.Sink == nil {
		return 0, errors.New("app not fully configured")
	}

	defer func() { _ = a.Source.Close() }()
	defer func() { _ = a.Sink.Close() }()

	written := 0

	for {
		rec, err := a.Source.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// tolerant: skip broken rows
			fmt.Printf("warn: read record failed: %v\n", err)

			continue
		}

		if !a.Filter.Allow(rec) {
			continue
		}

		entry, err := a.Render.Render(rec)
		if err != nil {
			fmt.Printf("warn: render failed: %v\n", err)

			continue
		}

		if err := a.Sink.WriteEntry(entry); err != nil {
			fmt.Printf("warn: write failed: %v\n", err)

			continue
		}

		written++
	}

	return written, nil
}
