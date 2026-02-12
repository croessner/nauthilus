package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/client/engine"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

func main() {
	cfg := engine.DefaultConfig()

	setupFlags(cfg)

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

	fx.New(
		fx.Provide(func() *engine.Config { return cfg }),
		fx.WithLogger(func() fxevent.Logger {
			if cfg.Debug {
				return &fxevent.ConsoleLogger{W: os.Stderr}
			}
			return fxevent.NopLogger
		}),
		engine.Module,
		fx.Invoke(runApp),
	).Run()
}

func setupFlags(cfg *engine.Config) {
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

	// Thresholds & Coloring
	flag.IntVar(&cfg.WarnP95, "warn-p95", cfg.WarnP95, "P95 threshold (ms) for yellow output")
	flag.IntVar(&cfg.CritP95, "crit-p95", cfg.CritP95, "P95 threshold (ms) for red output")
	flag.Float64Var(&cfg.WarnErr, "warn-error-rate", cfg.WarnErr, "Warn threshold for error rate in %")
	flag.Float64Var(&cfg.CritErr, "crit-error-rate", cfg.CritErr, "Critical threshold for error rate in %")
	flag.Float64Var(&cfg.WarnTrack, "warn-track", cfg.WarnTrack, "Warn threshold for tracking ratio rps/target_rps")
	flag.Float64Var(&cfg.CritTrack, "crit-track", cfg.CritTrack, "Critical threshold for tracking ratio rps/target_rps")

	flag.IntVar(&cfg.GraceSeconds, "grace-seconds", cfg.GraceSeconds, "Grace period (seconds) before auto-mode or stats start")

	// Auto-mode flags
	flag.BoolVar(&cfg.AutoMode, "auto", cfg.AutoMode, "Enable adaptive/auto mode")
	flag.IntVar(&cfg.AutoTargetP95, "auto-target-p95", cfg.AutoTargetP95, "Target P95 latency for auto-mode")
	flag.Float64Var(&cfg.AutoMaxRPS, "auto-max-rps", cfg.AutoMaxRPS, "Max RPS for auto-mode")
	flag.IntVar(&cfg.AutoMaxConc, "auto-max-concurrency", cfg.AutoMaxConc, "Max concurrency for auto-mode")
	flag.Float64Var(&cfg.AutoStartRPS, "auto-start-rps", cfg.AutoStartRPS, "Initial RPS for auto-mode")
	flag.IntVar(&cfg.AutoStartConc, "auto-start-concurrency", cfg.AutoStartConc, "Initial concurrency for auto-mode")
	flag.Float64Var(&cfg.AutoStepRPS, "auto-step-rps", cfg.AutoStepRPS, "RPS increase step")
	flag.IntVar(&cfg.AutoStepConc, "auto-step-concurrency", cfg.AutoStepConc, "Concurrency increase step")
	flag.Float64Var(&cfg.AutoBackoff, "auto-backoff", cfg.AutoBackoff, "Backoff factor (0..1) when target is exceeded")
	flag.Float64Var(&cfg.AutoMaxErr, "auto-max-err", cfg.AutoMaxErr, "Max error rate (%) before backing off")
	flag.IntVar(&cfg.AutoMinSample, "auto-min-sample", cfg.AutoMinSample, "Minimum samples before making a decision")
	flag.StringVar(&cfg.AutoFocus, "auto-focus", cfg.AutoFocus, "What to scale: rps|concurrency")

	// Plateau detection
	flag.BoolVar(&cfg.AutoPlateau, "auto-plateau", cfg.AutoPlateau, "Enable plateau detection")
	flag.IntVar(&cfg.AutoPlateauWindows, "auto-plateau-windows", cfg.AutoPlateauWindows, "Number of windows to consider for plateau")
	flag.Float64Var(&cfg.AutoPlateauGain, "auto-plateau-gain", cfg.AutoPlateauGain, "Min gain (%) to not be considered a plateau")
	flag.StringVar(&cfg.AutoPlateauAction, "auto-plateau-action", cfg.AutoPlateauAction, "Action on plateau: freeze|backoff")
	flag.IntVar(&cfg.AutoPlateauCooldown, "auto-plateau-cooldown", cfg.AutoPlateauCooldown, "Cooldown windows after plateau before resuming increases")
	flag.Float64Var(&cfg.AutoPlateauTrackThreshold, "auto-plateau-track-threshold", cfg.AutoPlateauTrackThreshold, "Tracking threshold rps/trps (0..1)")
	flag.IntVar(&cfg.AutoPlateauTrackWindows, "auto-plateau-track-windows", cfg.AutoPlateauTrackWindows, "Windows for tracking plateau")
	flag.StringVar(&cfg.AutoPlateauTrackAction, "auto-plateau-track-action", cfg.AutoPlateauTrackAction, "Action on tracking plateau")

	// Random effects
	flag.BoolVar(&cfg.RandomNoAuth, "random-no-auth", cfg.RandomNoAuth, "Randomly send no-auth mode for valid rows")
	flag.Float64Var(&cfg.RandomNoAuthProb, "random-no-auth-prob", cfg.RandomNoAuthProb, "Probability for random-no-auth")
	flag.BoolVar(&cfg.RandomBadPass, "random-bad-pass", cfg.RandomBadPass, "Randomly send wrong password")
	flag.Float64Var(&cfg.RandomBadPassProb, "random-bad-pass-prob", cfg.RandomBadPassProb, "Probability for random-bad-pass")

	flag.BoolVar(&cfg.Debug, "debug", cfg.Debug, "Enable debug output (including FX logs)")
}

func runApp(lifecycle fx.Lifecycle, app *engine.App, shutdown fx.Shutdowner) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	lifecycle.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			go func() {
				defer close(done)

				if err := app.Run(ctx); err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
				}

				_ = shutdown.Shutdown()
			}()

			return nil
		},
		OnStop: func(stopCtx context.Context) error {
			app.Stop()

			select {
			case <-done:
			case <-stopCtx.Done():
				cancel()
				<-done
			}

			printStats(app)

			return nil
		},
	})
}

func printStats(app *engine.App) {
	stats := app.Collector.Snapshot()

	if app.Config.ProgressBar && engine.IsTTY() {
		fmt.Print("\x1b[2J\x1b[3J\x1b[H")
	}

	fmt.Printf("Done in %s\n", stats.Elapsed)
	fmt.Printf("total=%d matched=%d mismatched=%d http_errors=%d 429_errors=%d aborted=%d skipped=%d tolerated_bf=%d\n",
		stats.Total, stats.Matched, stats.Mismatched, stats.HttpErrs, stats.TooManyRequests, stats.Aborted, stats.Skipped, stats.ToleratedBF)

	if stats.Elapsed.Seconds() > 0 {
		fmt.Printf("throughput=%.2f req/s\n", float64(stats.Total)/stats.Elapsed.Seconds())
	}

	if app.Config.AutoMode {
		fmt.Printf("final_target_rps=%.f final_concurrency=%d focus=%s\n", stats.TargetRPS, stats.Concurrency, app.Config.AutoFocus)
	}

	if app.Config.CompareParallel {
		fmt.Printf("parallel_matched=%d parallel_mismatched=%d\n", stats.ParallelMatched, stats.ParallelMismatched)
	}

	fmt.Println()

	if stats.Total > 0 {
		fmt.Printf("avg_latency=%s\n", stats.Avg)
		fmt.Printf("min_latency=%s\n", stats.Min)
		fmt.Printf("max_latency=%s\n", stats.Max)
		fmt.Println()
		fmt.Printf("p50=%s p90=%s p99=%s\n", stats.P50, stats.P90, stats.P99)
		fmt.Println()

		of := app.Collector.Overflow()
		if of > 0 {
			// maxLatencyMs is not exported, it's 60000
			fmt.Printf("latency_overflow(>60000ms)=%d\n", of)
		}

		// Print HTTP status codes summary (code, count)
		fmt.Println("http_status_counts:")
		var codes []int
		for code := range stats.StatusCounts {
			codes = append(codes, code)
		}
		sort.Ints(codes)
		for _, code := range codes {
			fmt.Printf("  %d: %d\n", code, stats.StatusCounts[code])
		}

		if engine.IsTTY() {
			fmt.Println()
			engine.PrintLatencyHistogram(stats, app.Collector.Buckets())
			fmt.Println()
		}
	}
}
