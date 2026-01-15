package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/croessner/nauthilus/client/engine"
)

func main() {
	cfg := engine.DefaultConfig()

	flag.StringVar(&cfg.CSVPath, "csv", cfg.CSVPath, "CSV file path")
	flag.StringVar(&cfg.Endpoint, "url", cfg.Endpoint, "Auth endpoint URL")
	flag.StringVar(&cfg.Method, "method", cfg.Method, "HTTP method")
	flag.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "Concurrent workers")
	flag.Float64Var(&cfg.RPS, "rps", cfg.RPS, "Global rate limit (0=unlimited)")
	flag.IntVar(&cfg.JitterMs, "jitter-ms", cfg.JitterMs, "Random sleep 0..N ms before each request")
	flag.IntVar(&cfg.DelayMs, "delay-ms", cfg.DelayMs, "Fixed delay per item in worker")
	flag.IntVar(&cfg.TimeoutMs, "timeout-ms", cfg.TimeoutMs, "HTTP timeout")
	flag.IntVar(&cfg.MaxRows, "max", cfg.MaxRows, "Limit number of rows (0=all)")
	flag.BoolVar(&cfg.Shuffle, "shuffle", cfg.Shuffle, "Shuffle rows before sending")
	flag.StringVar(&cfg.HeadersList, "headers", cfg.HeadersList, "Extra headers, separated by '||'")
	flag.StringVar(&cfg.BasicAuth, "basic-auth", cfg.BasicAuth, "HTTP Basic-Auth credentials in format username:password")
	flag.IntVar(&cfg.OKStatus, "ok-status", cfg.OKStatus, "HTTP status indicating success when not using JSON flag")
	flag.BoolVar(&cfg.UseJSONFlag, "json-ok", cfg.UseJSONFlag, "Expect JSON {ok:true|false} in response")
	flag.BoolVar(&cfg.Verbose, "v", cfg.Verbose, "Verbose output")
	flag.BoolVar(&cfg.GenCSV, "generate-csv", cfg.GenCSV, "Generate a CSV at --csv path and exit")
	flag.IntVar(&cfg.GenCount, "generate-count", cfg.GenCount, "Number of rows to generate when --generate-csv is set")
	flag.Float64Var(&cfg.GenCIDRProb, "generate-cidr-prob", cfg.GenCIDRProb, "Probability (0..1) that generated IPs are taken from the same CIDR block")
	flag.IntVar(&cfg.GenCIDRPrefix, "generate-cidr-prefix", cfg.GenCIDRPrefix, "CIDR prefix length (8..30) of the shared block for IP grouping")
	flag.StringVar(&cfg.CSVDelim, "csv-delim", cfg.CSVDelim, "CSV delimiter override: ',', ';', 'tab'; empty=auto-detect")
	flag.BoolVar(&cfg.CSVDebug, "csv-debug", cfg.CSVDebug, "Print detected CSV headers and first row")
	flag.IntVar(&cfg.Loops, "loops", cfg.Loops, "Number of cycles to run over the CSV")
	flag.DurationVar(&cfg.RunFor, "duration", cfg.RunFor, "Total duration to run the test (e.g. 5m). CSV rows will loop until time elapses")
	flag.IntVar(&cfg.MaxParallel, "max-parallel", cfg.MaxParallel, "Max parallel requests per item (1=off)")
	flag.Float64Var(&cfg.ParallelProb, "parallel-prob", cfg.ParallelProb, "Probability (0..1) that an item is parallelized")
	flag.Float64Var(&cfg.AbortProb, "abort-prob", cfg.AbortProb, "Probability (0..1) to abort/cancel a request (simulates connection drop)")
	flag.DurationVar(&cfg.ProgressEvery, "progress-interval", cfg.ProgressEvery, "Progress report interval (e.g. 30s, 1m)")
	flag.BoolVar(&cfg.CompareParallel, "compare-parallel", cfg.CompareParallel, "Compare responses within a parallel group (strict byte equality)")
	flag.BoolVar(&cfg.UseIdemKey, "idempotency-key", cfg.UseIdemKey, "Add Idempotency-Key header computed from request body (SHA-256)")
	flag.BoolVar(&cfg.ProgressBar, "progress-bar", cfg.ProgressBar, "Render a single-line progress bar (TTY only)")
	flag.StringVar(&cfg.ColorMode, "color", cfg.ColorMode, "Color output: auto|always|never")

	flag.Parse()

	if cfg.GenCSV {
		if err := engine.GenerateCSV(cfg.CSVPath, cfg.GenCount, cfg.GenCIDRProb, cfg.GenCIDRPrefix); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("generated %d rows into %s\n", cfg.GenCount, cfg.CSVPath)
		return
	}

	// Handle Color
	useColor := true
	if strings.ToLower(cfg.ColorMode) == "never" || os.Getenv("NO_COLOR") != "" {
		useColor = false
	}
	engine.InitColorStyles(useColor)

	app, err := engine.NewApp(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := app.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Final stats and histogram
	stats := app.Collector.Snapshot()
	fmt.Printf("\nFinished. Total: %d, Matched: %d, Mismatched: %d, HTTP Errors: %d\n",
		stats.Total, stats.Matched, stats.Mismatched, stats.HttpErrs)

	engine.PrintLatencyHistogram(stats, app.Collector.Buckets(), app.Collector.Overflow())
}
