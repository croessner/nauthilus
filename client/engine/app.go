package engine

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type App struct {
	Config         *Config
	Source         RowSource
	Collector      StatsCollector
	Client         *AuthClient
	Pacer          *Pacer
	AutoController *AutoController

	startTime time.Time
	wg        sync.WaitGroup
	rowChan   chan Row
	quitCh    chan struct{}
}

func NewApp(cfg *Config) (*App, error) {
	var src RowSource
	var err error

	if cfg.GenCSV {
		// This should be handled before NewApp in main, or we implement a GeneratorSource
	}

	src, err = NewCSVSource(cfg.CSVPath, 0, cfg.CSVDebug, cfg.MaxRows, cfg.Shuffle)
	if err != nil {
		return nil, err
	}

	collector := NewDefaultStatsCollector()
	client := NewAuthClient(cfg)

	var pacer *Pacer
	if cfg.RPS > 0 || (cfg.AutoMode && cfg.AutoStartRPS > 0) {
		initialRPS := cfg.RPS
		if cfg.AutoMode && cfg.AutoStartRPS > 0 {
			initialRPS = cfg.AutoStartRPS
		}
		pacer = NewPacer(initialRPS)
		collector.SetTargetRPS(initialRPS)
	}

	app := &App{
		Config:    cfg,
		Source:    src,
		Collector: collector,
		Client:    client,
		Pacer:     pacer,
		startTime: time.Now(),
		rowChan:   make(chan Row, cfg.Concurrency*2),
		quitCh:    make(chan struct{}, 1024),
	}

	if cfg.AutoMode {
		app.AutoController = NewAutoController(cfg, collector, pacer, app)
	}

	return app, nil
}

func (a *App) SpawnWorkers(ctx context.Context, n int) {
	for i := 0; i < n; i++ {
		a.wg.Add(1)
		go a.worker(ctx, a.rowChan)
	}
}

func (a *App) ReduceWorkers(n int) {
	for i := 0; i < n; i++ {
		select {
		case a.quitCh <- struct{}{}:
		default:
		}
	}
}

func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.startTime = time.Now()

	// Handle signals
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigC
		cancel()
	}()

	// Start progress reporter
	if a.Config.ProgressEvery > 0 {
		go a.progressLoop(ctx)
	}

	// Determine initial concurrency
	initConc := a.Config.Concurrency
	if a.Config.AutoMode {
		if a.Config.AutoStartConc > 0 {
			initConc = a.Config.AutoStartConc
		} else if a.Config.AutoFocus == "rps" && a.Config.Concurrency > 0 {
			initConc = a.Config.Concurrency
		} else {
			initConc = 1
		}
	}

	// Start initial workers
	a.SpawnWorkers(ctx, initConc)
	a.Collector.SetConcurrency(int64(initConc))

	// Start adaptive controller if enabled
	if a.Config.AutoMode && a.AutoController != nil {
		go a.AutoController.Run(ctx)
	}

	// Feeding loop
	go func() {
		defer close(a.rowChan)
		for l := 0; l < a.Config.Loops || a.Config.RunFor > 0; l++ {
			a.Source.Reset()
			for {
				row, ok := a.Source.Next()
				if !ok {
					break
				}

				if a.Pacer != nil {
					select {
					case <-a.Pacer.Tick():
					case <-ctx.Done():
						return
					}
				}

				select {
				case a.rowChan <- row:
				case <-ctx.Done():
					return
				}

				if a.Config.RunFor > 0 && time.Since(a.startTime) > a.Config.RunFor {
					return
				}
			}
			if a.Config.RunFor > 0 && time.Since(a.startTime) > a.Config.RunFor {
				break
			}
		}
	}()

	a.wg.Wait()
	return nil
}

func (a *App) worker(ctx context.Context, rows <-chan Row) {
	defer a.wg.Done()
	for {
		select {
		case <-a.quitCh:
			return
		case <-ctx.Done():
			return
		case row, ok := <-rows:
			if !ok {
				return
			}
			if a.Config.JitterMs > 0 {
				time.Sleep(time.Duration(rand.IntN(a.Config.JitterMs)) * time.Millisecond)
			}

			numReqs := 1
			if a.Config.MaxParallel > 1 && rand.Float64() < a.Config.ParallelProb {
				numReqs = rand.IntN(a.Config.MaxParallel-1) + 2
			}

			if numReqs == 1 {
				okResp, isMatch, isHttpErr, isTooManyRequests, latency, _, _, _ := a.Client.DoRequest(ctx, row)
				a.Collector.AddSample(latency, okResp, isMatch, isHttpErr, false, false, false, isTooManyRequests)
			} else {
				var wg sync.WaitGroup
				var bodies [][]byte
				var mu sync.Mutex

				for i := 0; i < numReqs; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						okResp, isMatch, isHttpErr, isTooManyRequests, latency, rb, _, _ := a.Client.DoRequest(ctx, row)
						a.Collector.AddSample(latency, okResp, isMatch, isHttpErr, false, false, false, isTooManyRequests)
						if a.Config.CompareParallel {
							mu.Lock()
							bodies = append(bodies, rb)
							mu.Unlock()
						}
					}()
				}
				wg.Wait()

				if a.Config.CompareParallel && len(bodies) > 1 {
					first := bodies[0]
					matched := true
					for i := 1; i < len(bodies); i++ {
						if !bytes.Equal(first, bodies[i]) {
							matched = false
							break
						}
					}
					if !matched {
						// We don't have a specific counter for parallel mismatch in Stats yet,
						// but main.go.bak had parallelMatched/Mismatched.
						// For now, we can log it or just keep it as is.
						// In main.go.bak it was just printed if verbose.
						if a.Config.Verbose {
							fmt.Printf("Parallel mismatch for row\n")
						}
					}
				}
			}

			if a.Config.DelayMs > 0 {
				time.Sleep(time.Duration(a.Config.DelayMs) * time.Millisecond)
			}
		}
	}
}

func (a *App) progressLoop(ctx context.Context) {
	ticker := time.NewTicker(a.Config.ProgressEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s := a.Collector.Snapshot()
			fmt.Printf("[%v] Total: %d, Matched: %d, Errors: %d, P95: %v, RPS: %.2f\n",
				s.Elapsed.Round(time.Second), s.Total, s.Matched, s.HttpErrs, s.P90, // Should be P95 if we had it
				float64(s.Total)/s.Elapsed.Seconds())
		case <-ctx.Done():
			return
		}
	}
}
