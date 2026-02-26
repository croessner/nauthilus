package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
)

type App struct {
	Config         *Config
	Source         RowSource
	Collector      StatsCollector
	Client         *AuthClient
	Pacer          *Pacer
	AutoController *AutoController
	MetricsPoller  *MetricsPoller

	startTime time.Time
	wg        sync.WaitGroup
	rowChan   chan Row
	quitCh    chan struct{}
	stopChan  chan struct{}
	stopOnce  sync.Once
}

func NewApp(cfg *Config, src RowSource, collector StatsCollector, client *AuthClient, pacer *Pacer) *App {
	app := &App{
		Config:        cfg,
		Source:        src,
		Collector:     collector,
		Client:        client,
		Pacer:         pacer,
		startTime:     time.Now(),
		rowChan:       make(chan Row, cfg.Concurrency*2),
		quitCh:        make(chan struct{}, 1024),
		stopChan:      make(chan struct{}),
		MetricsPoller: NewMetricsPoller(client.HTTPClient(), cfg.Endpoint, client.BaseHeader(), 5*time.Second),
	}

	if cfg.AutoMode {
		app.AutoController = NewAutoController(cfg, collector, pacer, app)
	}

	return app
}

func (a *App) SpawnWorkers(ctx context.Context, n int) {
	for range n {
		a.wg.Add(1)
		go a.worker(ctx, a.rowChan)
	}
}

func (a *App) ReduceWorkers(n int) {
	for range n {
		select {
		case a.quitCh <- struct{}{}:
		default:
		}
	}
}

func (a *App) Stop() {
	a.stopOnce.Do(func() {
		close(a.stopChan)

		if a.Client != nil {
			a.Client.Stop()
		}
	})
}

func (a *App) Run(ctx context.Context) error {
	a.startTime = time.Now()

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

	// Start metrics poller
	if a.MetricsPoller != nil {
		go a.MetricsPoller.Run(ctx)
	}

	// Feeding loop
	go func() {
		defer close(a.rowChan)
		for l := 0; l < a.Config.Loops || a.Config.RunFor > 0; l++ {
			a.Source.Reset()
			for {
				if a.Config.RunFor > 0 && time.Since(a.startTime) > a.Config.RunFor {
					return
				}

				row, ok := a.Source.Next()
				if !ok {
					break
				}

				if a.Pacer != nil {
					select {
					case <-a.Pacer.Tick():
					case <-ctx.Done():
						return
					case <-a.stopChan:
						return
					}
				}

				select {
				case a.rowChan <- row:
				case <-ctx.Done():
					return
				case <-a.stopChan:
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

			if a.Config.RunFor > 0 && time.Since(a.startTime) > a.Config.RunFor {
				continue
			}

			// Random effects determined once per logical request
			if a.Config.RandomBadPass && rand.Float64() < a.Config.RandomBadPassProb {
				row.BadPass = true
			}
			if a.Config.RandomNoAuth && row.ExpectOK && rand.Float64() < a.Config.RandomNoAuthProb {
				row.NoAuth = true
			}

			if a.Config.JitterMs > 0 {
				time.Sleep(time.Duration(rand.IntN(a.Config.JitterMs)) * time.Millisecond)
			}

			numReqs := 1
			if a.Config.MaxParallel > 1 && rand.Float64() < a.Config.ParallelProb {
				numReqs = rand.IntN(a.Config.MaxParallel-1) + 2
			}

			if numReqs == 1 {
				okResp, isMatch, isHttpErr, isTooManyRequests, isToleratedBF, isAborted, latency, _, statusCode, _ := a.Client.DoRequest(ctx, row)
				if a.Config.RunFor > 0 && time.Since(a.startTime) > a.Config.RunFor {
					continue
				}

				a.Collector.AddSample(latency, okResp, isMatch, isHttpErr, isAborted, false, isToleratedBF, isTooManyRequests, statusCode)
			} else {
				var wg sync.WaitGroup
				var bodies [][]byte
				var mu sync.Mutex

				for i := 0; i < numReqs; i++ {
					wg.Go(func() {
						okResp, isMatch, isHttpErr, isTooManyRequests, isToleratedBF, isAborted, latency, rb, statusCode, _ := a.Client.DoRequest(ctx, row)
						if a.Config.RunFor > 0 && time.Since(a.startTime) > a.Config.RunFor {
							return
						}

						a.Collector.AddSample(latency, okResp, isMatch, isHttpErr, isAborted, false, isToleratedBF, isTooManyRequests, statusCode)
						if a.Config.CompareParallel {
							mu.Lock()
							bodies = append(bodies, rb)
							mu.Unlock()
						}
					})
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
						a.Collector.IncParallelMismatched()
						if a.Config.Verbose || a.Config.Debug {
							fmt.Printf("Parallel mismatch for row\n")
						}
						if a.Config.Debug {
							fmt.Printf("--- PARALLEL MISMATCH DEBUG ---\n")
							for i, b := range bodies {
								var pj any
								_ = json.Unmarshal(b, &pj)
								out, _ := json.MarshalIndent(pj, "", "  ")
								fmt.Printf("Response %d:\n%s\n", i, string(out))
							}
							fmt.Printf("-------------------------------\n")
						}
					} else {
						a.Collector.IncParallelMatched()
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
	if a.Config.ProgressBar && IsTTY() {
		a.renderInteractiveLoop(ctx)
		return
	}

	if a.Config.ProgressEvery <= 0 {
		return
	}

	ticker := time.NewTicker(a.Config.ProgressEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s := a.Collector.Snapshot()
			fmt.Printf("[%v] Total: %d, Matched: %d, Errors: %d, PMatched: %d, PMismatched: %d, P95: %v, RPS: %.2f\n",
				s.Elapsed.Round(time.Second), s.Total, s.Matched, s.HttpErrs,
				s.ParallelMatched, s.ParallelMismatched, s.P95,
				float64(s.Total)/s.Elapsed.Seconds())
		case <-ctx.Done():
			return
		}
	}
}

func (a *App) renderInteractiveLoop(ctx context.Context) {
	// Clear screen at start
	fmt.Print("\x1b[2J\x1b[3J\x1b[H")
	fmt.Println("Running test...")

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.renderTTY()
		case <-ctx.Done():
			// Final clear of the status lines? No, leave them.
			return
		}
	}
}

func (a *App) renderTTY() {
	s := a.Collector.Snapshot()
	termW, termH := TermSize()
	if termW < 40 {
		termW = 80
	}

	// Calculate RPS
	rps := 0.0
	if s.Elapsed.Seconds() > 0 {
		rps = float64(s.Total) / s.Elapsed.Seconds()
	}

	// Calculate ETA and planned total
	plannedTotal := int64(a.Config.MaxRows)
	if a.Config.RunFor > 0 {
		plannedTotal = -2
	} else if plannedTotal == 0 {
		plannedTotal = int64(a.Source.Total() * a.Config.Loops)
	}

	etaStr := "--:--:--"
	if plannedTotal == -2 {
		if a.Config.RunFor > 0 {
			remain := max(a.Config.RunFor-s.Elapsed, 0)
			etaStr = humanETA(remain)
		}
	} else if plannedTotal > 0 {
		remain := max(plannedTotal-s.Total, 0)
		if rps > 0 {
			etaDur := time.Duration(float64(remain) / rps * float64(time.Second))
			etaStr = humanETA(etaDur)
		}
	}

	trkStr := ""
	if s.TargetRPS > 0 {
		trk := Clamp01(rps / s.TargetRPS)
		trkStr = fmt.Sprintf(" [trk: %3.0f%%]", trk*100)
	}

	mstr := ""
	if a.MetricsPoller != nil {
		mstr = a.MetricsPoller.GetLine()
	}

	// Determine severity for coloring
	errRate := CalcErrorRatePct(s)
	trkRatio := 1.0
	if s.TargetRPS > 0 {
		trkRatio = Clamp01(rps / s.TargetRPS)
	}

	severity := "ok"
	if s.P90 >= time.Duration(a.Config.CritP95)*time.Millisecond || errRate >= a.Config.CritErr || (s.TargetRPS > 0 && trkRatio <= a.Config.CritTrack) {
		severity = "crit"
	} else if s.P90 >= time.Duration(a.Config.WarnP95)*time.Millisecond || errRate >= a.Config.WarnErr || (s.TargetRPS > 0 && trkRatio <= a.Config.WarnTrack) {
		severity = "warn"
	}

	// Determine current stats for the header
	avgMs := int(s.Avg.Milliseconds())
	p50Ms := int(s.P50.Milliseconds())
	p90Ms := int(s.P90.Milliseconds())

	right := fmt.Sprintf(
		"[eta: %s] [rps: %7.1f] [trps: %7d]%s [conc: %4d] [ok: %4s] [err: %s] [pm: %s] [pmm: %s] [avg: %3s] [p50: %3s] [p90: %3s]",
		etaStr, rps, uint64(s.TargetRPS), trkStr, s.Concurrency,
		humanCount(s.Matched), humanCount(s.HttpErrs), humanCount(s.ParallelMatched), humanCount(s.ParallelMismatched),
		humanMs(avgMs), humanMs(p50Ms), humanMs(p90Ms),
	)

	// Header area under "Running test...":
	// Row 2: textual status (right string)
	// Row 3: metrics line
	hdr1 := " " + right
	hdr2 := " " + mstr

	if IsTTY() {
		hdr1 = " " + StyleCyan.S(right)
		hdr2 = " " + StyleFaint.S(mstr)
	}

	hdr1 = padToCellsRight(truncateToCells(hdr1, termW), termW)
	hdr2 = padToCellsRight(truncateToCells(hdr2, termW), termW)

	fmt.Printf("\x1b[s\x1b[2;1H\x1b[2K%s\x1b[3;1H\x1b[2K%s\x1b[u", hdr1, hdr2)

	// Bottom progress bar
	status := "RUN"
	if plannedTotal == -2 {
		status = "TIME"
	}
	left := fmt.Sprintf("[%s] %d", status, s.Total)
	if plannedTotal > 0 {
		left = fmt.Sprintf("[%s] %d / %d", status, s.Total, plannedTotal)
	}

	ratio := 0.0
	if plannedTotal == -2 {
		if a.Config.RunFor > 0 {
			ratio = Clamp01(s.Elapsed.Seconds() / a.Config.RunFor.Seconds())
		}
	} else if plannedTotal > 0 {
		ratio = Clamp01(float64(s.Total) / float64(plannedTotal))
	}

	const minBar = 10
	leftW := displayWidth(left)
	fixedSpaces := 2 // leading space + space before the bar
	available := termW - fixedSpaces - leftW

	if available < minBar {
		need := minBar - available
		newLeftW := max(leftW-need, 0)
		left = truncateToCells(left, newLeftW)
		leftW = displayWidth(left)
		available = termW - fixedSpaces - leftW
	}

	barWidth := available
	fill := min(max(int(math.Round(ratio*float64(barWidth))), 0), barWidth)

	fillChar := "#"
	emptyChar := "-"
	if SupportsUnicode() {
		fillChar = "█"
		emptyChar = "·"
	}
	if s.PlateauActive {
		if SupportsUnicode() {
			fillChar = "▒"
		} else {
			fillChar = "="
		}
	}

	var bar string
	filled := ""
	rest := ""
	if fill > 0 {
		filled = strings.Repeat(fillChar, fill)
	}
	if barWidth-fill > 0 {
		rest = strings.Repeat(emptyChar, barWidth-fill)
	}

	if IsTTY() {
		var c colorStyle
		switch {
		case s.PlateauActive:
			c = StyleMagenta
		case severity == "crit":
			c = StyleRed
		case severity == "warn":
			c = StyleYellow
		default:
			c = StyleGreen
		}

		if fill > 0 {
			bar = c.S(filled) + StyleFaint.S(rest)
		} else {
			bar = StyleFaint.S(rest)
		}
	} else {
		bar = filled + rest
	}

	leftColored := left
	if IsTTY() {
		switch {
		case s.PlateauActive:
			leftColored = StyleMagenta.S(left)
		case severity == "crit":
			leftColored = StyleRed.S(left)
		case severity == "warn":
			leftColored = StyleYellow.S(left)
		default:
			leftColored = StyleGreen.S(left)
		}
	}

	pctStr := fmt.Sprintf(" %5.1f%%", ratio*100)
	if IsTTY() {
		pctStr = StyleCyan.S(pctStr)
	}

	bottom := " " + leftColored + " " + bar + " " + pctStr
	bottom = padToCellsRight(truncateToCells(bottom, termW), termW)

	fmt.Printf("\x1b[s\x1b[%d;1H\x1b[2K%s\x1b[u", termH, bottom)
}
