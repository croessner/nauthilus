// Package engine provides engine functionality.
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

// App describes the exported App type.
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

// NewApp provides the exported NewApp function.
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

// SpawnWorkers provides the exported SpawnWorkers method.
func (a *App) SpawnWorkers(ctx context.Context, n int) {
	for range n {
		a.wg.Add(1)
		go a.worker(ctx, a.rowChan)
	}
}

// ReduceWorkers provides the exported ReduceWorkers method.
func (a *App) ReduceWorkers(n int) {
	for range n {
		select {
		case a.quitCh <- struct{}{}:
		default:
		}
	}
}

// Stop provides the exported Stop method.
func (a *App) Stop() {
	a.stopOnce.Do(func() {
		close(a.stopChan)

		if a.Client != nil {
			a.Client.Stop()
		}
	})
}

// Run provides the exported Run method.
func (a *App) Run(ctx context.Context) error {
	a.startTime = time.Now()

	if a.Config.ProgressEvery > 0 {
		go a.progressLoop(ctx)
	}

	initConc := a.initialConcurrency()
	a.SpawnWorkers(ctx, initConc)
	a.Collector.SetConcurrency(int64(initConc))

	if a.Config.AutoMode && a.AutoController != nil {
		go a.AutoController.Run(ctx)
	}

	if a.MetricsPoller != nil {
		go a.MetricsPoller.Run(ctx)
	}

	go a.feedRows(ctx)

	a.wg.Wait()

	return nil
}

// initialConcurrency resolves the worker count used before adaptive control starts.
func (a *App) initialConcurrency() int {
	if !a.Config.AutoMode {
		return a.Config.Concurrency
	}

	if a.Config.AutoStartConc > 0 {
		return a.Config.AutoStartConc
	}

	if a.Config.AutoFocus == autoFocusRPS && a.Config.Concurrency > 0 {
		return a.Config.Concurrency
	}

	return 1
}

// feedRows streams source rows into the worker queue until loops, duration, or cancellation stop it.
func (a *App) feedRows(ctx context.Context) {
	defer close(a.rowChan)

	for l := 0; l < a.Config.Loops || a.Config.RunFor > 0; l++ {
		a.Source.Reset()

		if !a.feedCurrentLoop(ctx) {
			return
		}

		if a.runForElapsed() {
			return
		}
	}
}

// feedCurrentLoop sends one complete source pass to the worker queue.
func (a *App) feedCurrentLoop(ctx context.Context) bool {
	for {
		if a.runForElapsed() {
			return false
		}

		row, ok := a.Source.Next()
		if !ok {
			return true
		}

		if !a.waitForPacer(ctx) {
			return false
		}

		if !a.enqueueRow(ctx, row) {
			return false
		}
	}
}

// waitForPacer waits for the configured pacer tick when pacing is enabled.
func (a *App) waitForPacer(ctx context.Context) bool {
	if a.Pacer == nil {
		return true
	}

	select {
	case <-a.Pacer.Tick():
		return true
	case <-ctx.Done():
		return false
	case <-a.stopChan:
		return false
	}
}

// enqueueRow sends a row to workers unless the run is canceled or stopped.
func (a *App) enqueueRow(ctx context.Context, row Row) bool {
	select {
	case a.rowChan <- row:
		return true
	case <-ctx.Done():
		return false
	case <-a.stopChan:
		return false
	}
}

// runForElapsed reports whether the duration-bound run has exceeded its configured runtime.
func (a *App) runForElapsed() bool {
	return a.Config.RunFor > 0 && time.Since(a.startTime) > a.Config.RunFor
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

			a.processRow(ctx, row)
		}
	}
}

// processRow applies per-row randomization, request fanout, and delay handling.
func (a *App) processRow(ctx context.Context, row Row) {
	if a.runForElapsed() {
		return
	}

	row = a.prepareRow(row)
	a.sleepJitter()

	numReqs := a.requestFanout()
	if numReqs == 1 {
		a.runSingleRequest(ctx, row)
	} else {
		a.runParallelRequests(ctx, row, numReqs)
	}

	a.sleepDelay()
}

// prepareRow applies random request mutations once per logical row.
func (a *App) prepareRow(row Row) Row {
	if a.Config.RandomBadPass && rand.Float64() < a.Config.RandomBadPassProb {
		row.BadPass = true
	}

	if a.Config.RandomNoAuth && row.ExpectOK && rand.Float64() < a.Config.RandomNoAuthProb {
		row.NoAuth = true
	}

	return row
}

// sleepJitter applies the configured per-row random jitter.
func (a *App) sleepJitter() {
	if a.Config.JitterMs > 0 {
		time.Sleep(time.Duration(rand.IntN(a.Config.JitterMs)) * time.Millisecond)
	}
}

// requestFanout returns the number of HTTP requests to issue for one logical row.
func (a *App) requestFanout() int {
	if a.Config.MaxParallel <= 1 || rand.Float64() >= a.Config.ParallelProb {
		return 1
	}

	return rand.IntN(a.Config.MaxParallel-1) + 2
}

// runSingleRequest executes and records one request for a row.
func (a *App) runSingleRequest(ctx context.Context, row Row) {
	result := a.doRequest(ctx, row)
	if a.runForElapsed() {
		return
	}

	a.recordRequestResult(result)
}

type requestResult struct {
	latency         time.Duration
	body            []byte
	statusCode      int
	ok              bool
	matched         bool
	httpError       bool
	tooManyRequests bool
	toleratedBF     bool
	aborted         bool
}

// doRequest executes one HTTP request and normalizes the positional return values.
func (a *App) doRequest(ctx context.Context, row Row) requestResult {
	okResp, isMatch, isHTTPErr, isTooManyRequests, isToleratedBF, isAborted, latency, body, statusCode, _ := a.Client.DoRequest(ctx, row)

	return requestResult{
		latency:         latency,
		body:            body,
		statusCode:      statusCode,
		ok:              okResp,
		matched:         isMatch,
		httpError:       isHTTPErr,
		tooManyRequests: isTooManyRequests,
		toleratedBF:     isToleratedBF,
		aborted:         isAborted,
	}
}

// recordRequestResult adds one request sample to the collector.
func (a *App) recordRequestResult(result requestResult) {
	a.Collector.AddSample(
		result.latency,
		result.ok,
		result.matched,
		result.httpError,
		result.aborted,
		false,
		result.toleratedBF,
		result.tooManyRequests,
		result.statusCode,
	)
}

// runParallelRequests executes and compares multiple requests for one logical row.
func (a *App) runParallelRequests(ctx context.Context, row Row, numReqs int) {
	var (
		wg     sync.WaitGroup
		bodies [][]byte
		mu     sync.Mutex
	)

	for i := 0; i < numReqs; i++ {
		wg.Go(func() {
			result := a.doRequest(ctx, row)
			if a.runForElapsed() {
				return
			}

			a.recordRequestResult(result)

			if a.Config.CompareParallel {
				mu.Lock()

				bodies = append(bodies, result.body)
				mu.Unlock()
			}
		})
	}

	wg.Wait()
	a.recordParallelComparison(bodies)
}

// recordParallelComparison records whether parallel responses matched byte-for-byte.
func (a *App) recordParallelComparison(bodies [][]byte) {
	if !a.Config.CompareParallel || len(bodies) <= 1 {
		return
	}

	if parallelBodiesMatch(bodies) {
		a.Collector.IncParallelMatched()

		return
	}

	a.Collector.IncParallelMismatched()
	a.printParallelMismatch(bodies)
}

// parallelBodiesMatch reports whether all response bodies equal the first body.
func parallelBodiesMatch(bodies [][]byte) bool {
	first := bodies[0]
	for i := 1; i < len(bodies); i++ {
		if !bytes.Equal(first, bodies[i]) {
			return false
		}
	}

	return true
}

// printParallelMismatch writes optional mismatch diagnostics.
func (a *App) printParallelMismatch(bodies [][]byte) {
	if a.Config.Verbose || a.Config.Debug {
		fmt.Printf("Parallel mismatch for row\n")
	}

	if !a.Config.Debug {
		return
	}

	fmt.Printf("--- PARALLEL MISMATCH DEBUG ---\n")

	for i, b := range bodies {
		var pj any

		_ = json.Unmarshal(b, &pj)
		out, _ := json.MarshalIndent(pj, "", "  ")
		fmt.Printf("Response %d:\n%s\n", i, string(out))
	}

	fmt.Printf("-------------------------------\n")
}

// sleepDelay applies the fixed per-row delay.
func (a *App) sleepDelay() {
	if a.Config.DelayMs > 0 {
		time.Sleep(time.Duration(a.Config.DelayMs) * time.Millisecond)
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
				s.Elapsed.Round(time.Second), s.Total, s.Matched, s.HTTPErrs,
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
	termW, termH := normalizedTermSize()
	rps := currentRPS(s)
	plannedTotal := a.plannedTotal()
	severity := a.currentSeverity(s, rps)

	a.renderTTYHeader(termW, s, a.etaString(s, plannedTotal, rps), rps)
	a.renderTTYBottom(termW, termH, s, plannedTotal, severity)
}

// normalizedTermSize returns a safe terminal size for progress rendering.
func normalizedTermSize() (int, int) {
	termW, termH := TermSize()
	if termW < 40 {
		termW = 80
	}

	return termW, termH
}

// currentRPS calculates observed requests per second for a stats snapshot.
func currentRPS(s Stats) float64 {
	if s.Elapsed.Seconds() <= 0 {
		return 0
	}

	return float64(s.Total) / s.Elapsed.Seconds()
}

// plannedTotal returns the total work target, or -2 for duration-bound runs.
func (a *App) plannedTotal() int64 {
	if a.Config.RunFor > 0 {
		return -2
	}

	plannedTotal := int64(a.Config.MaxRows)
	if plannedTotal == 0 {
		return int64(a.Source.Total() * a.Config.Loops)
	}

	return plannedTotal
}

// etaString formats the estimated remaining time.
func (a *App) etaString(s Stats, plannedTotal int64, rps float64) string {
	if plannedTotal == -2 && a.Config.RunFor > 0 {
		return humanETA(max(a.Config.RunFor-s.Elapsed, 0))
	}

	if plannedTotal > 0 && rps > 0 {
		remain := max(plannedTotal-s.Total, 0)

		return humanETA(time.Duration(float64(remain) / rps * float64(time.Second)))
	}

	return "--:--:--"
}

// currentSeverity returns the status severity used for progress coloring.
func (a *App) currentSeverity(s Stats, rps float64) string {
	trkRatio := 1.0
	if s.TargetRPS > 0 {
		trkRatio = Clamp01(rps / s.TargetRPS)
	}

	errRate := CalcErrorRatePct(s)
	if s.P90 >= time.Duration(a.Config.CritP95)*time.Millisecond || errRate >= a.Config.CritErr || (s.TargetRPS > 0 && trkRatio <= a.Config.CritTrack) {
		return severityCrit
	}

	if s.P90 >= time.Duration(a.Config.WarnP95)*time.Millisecond || errRate >= a.Config.WarnErr || (s.TargetRPS > 0 && trkRatio <= a.Config.WarnTrack) {
		return severityWarn
	}

	return severityOK
}

// renderTTYHeader renders the top status and metrics rows.
func (a *App) renderTTYHeader(termW int, s Stats, etaStr string, rps float64) {
	right := ttyHeaderStatus(s, etaStr, rps, trackString(s, rps))

	mstr := ""
	if a.MetricsPoller != nil {
		mstr = a.MetricsPoller.GetLine()
	}

	hdr1, hdr2 := ttyHeaderRows(right, mstr, termW)

	fmt.Printf("\x1b[s\x1b[2;1H\x1b[2K%s\x1b[3;1H\x1b[2K%s\x1b[u", hdr1, hdr2)
}

// trackString formats target-RPS tracking when a target exists.
func trackString(s Stats, rps float64) string {
	if s.TargetRPS <= 0 {
		return ""
	}

	trk := Clamp01(rps / s.TargetRPS)

	return fmt.Sprintf(" [trk: %3.0f%%]", trk*100)
}

// ttyHeaderStatus formats the textual status line above the progress bar.
func ttyHeaderStatus(s Stats, etaStr string, rps float64, trkStr string) string {
	avgMs := int(s.Avg.Milliseconds())
	p50Ms := int(s.P50.Milliseconds())
	p90Ms := int(s.P90.Milliseconds())

	return fmt.Sprintf(
		"[eta: %s] [rps: %7.1f] [trps: %7d]%s [conc: %4d] [ok: %4s] [err: %s] [pm: %s] [pmm: %s] [avg: %3s] [p50: %3s] [p90: %3s]",
		etaStr, rps, uint64(s.TargetRPS), trkStr, s.Concurrency,
		humanCount(s.Matched), humanCount(s.HTTPErrs), humanCount(s.ParallelMatched), humanCount(s.ParallelMismatched),
		humanMs(avgMs), humanMs(p50Ms), humanMs(p90Ms),
	)
}

// ttyHeaderRows returns terminal-width padded header rows.
func ttyHeaderRows(right string, metrics string, termW int) (string, string) {
	hdr1 := " " + right
	hdr2 := " " + metrics

	if IsTTY() {
		hdr1 = " " + StyleCyan.S(right)
		hdr2 = " " + StyleFaint.S(metrics)
	}

	return padToCellsRight(truncateToCells(hdr1, termW), termW),
		padToCellsRight(truncateToCells(hdr2, termW), termW)
}

// renderTTYBottom renders the bottom progress bar row.
func (a *App) renderTTYBottom(termW int, termH int, s Stats, plannedTotal int64, severity string) {
	left := progressLabel(s, plannedTotal)
	ratio := progressRatio(a.Config.RunFor, s, plannedTotal)
	left, barWidth := fitProgressLabel(left, termW)
	bar := renderProgressBar(barWidth, ratio, s.PlateauActive, severity)
	leftColored := colorProgressLabel(left, s.PlateauActive, severity)
	pctStr := progressPercent(ratio)

	bottom := " " + leftColored + " " + bar + " " + pctStr
	bottom = padToCellsRight(truncateToCells(bottom, termW), termW)

	fmt.Printf("\x1b[s\x1b[%d;1H\x1b[2K%s\x1b[u", termH, bottom)
}

// progressLabel returns the left-hand progress label.
func progressLabel(s Stats, plannedTotal int64) string {
	status := "RUN"
	if plannedTotal == -2 {
		status = "TIME"
	}

	if plannedTotal > 0 {
		return fmt.Sprintf("[%s] %d / %d", status, s.Total, plannedTotal)
	}

	return fmt.Sprintf("[%s] %d", status, s.Total)
}

// progressRatio returns the normalized progress bar fill ratio.
func progressRatio(runFor time.Duration, s Stats, plannedTotal int64) float64 {
	if plannedTotal == -2 && runFor > 0 {
		return Clamp01(s.Elapsed.Seconds() / runFor.Seconds())
	}

	if plannedTotal > 0 {
		return Clamp01(float64(s.Total) / float64(plannedTotal))
	}

	return 0
}

// fitProgressLabel truncates the label when needed and returns the available bar width.
func fitProgressLabel(left string, termW int) (string, int) {
	const minBar = 10

	leftW := displayWidth(left)

	available := termW - 2 - leftW
	if available >= minBar {
		return left, available
	}

	need := minBar - available
	newLeftW := max(leftW-need, 0)
	left = truncateToCells(left, newLeftW)
	leftW = displayWidth(left)

	return left, termW - 2 - leftW
}

// renderProgressBar returns the colored or plain progress bar string.
func renderProgressBar(barWidth int, ratio float64, plateauActive bool, severity string) string {
	fill := min(max(int(math.Round(ratio*float64(barWidth))), 0), barWidth)
	filled, rest := progressSegments(barWidth, fill, plateauActive)

	if !IsTTY() {
		return filled + rest
	}

	if fill > 0 {
		return progressColor(plateauActive, severity).S(filled) + StyleFaint.S(rest)
	}

	return StyleFaint.S(rest)
}

// progressSegments returns filled and empty progress bar segments.
func progressSegments(barWidth int, fill int, plateauActive bool) (string, string) {
	fillChar, emptyChar := progressChars(plateauActive)
	filled := ""
	rest := ""

	if fill > 0 {
		filled = strings.Repeat(fillChar, fill)
	}

	if barWidth-fill > 0 {
		rest = strings.Repeat(emptyChar, barWidth-fill)
	}

	return filled, rest
}

// progressChars chooses progress bar glyphs for the current terminal.
func progressChars(plateauActive bool) (string, string) {
	if !SupportsUnicode() {
		if plateauActive {
			return "=", "-"
		}

		return "#", "-"
	}

	if plateauActive {
		return "▒", "·"
	}

	return "█", "·"
}

// colorProgressLabel applies the same severity color used by the progress bar.
func colorProgressLabel(left string, plateauActive bool, severity string) string {
	if !IsTTY() {
		return left
	}

	return progressColor(plateauActive, severity).S(left)
}

// progressPercent formats and colorizes the progress percentage.
func progressPercent(ratio float64) string {
	pctStr := fmt.Sprintf(" %5.1f%%", ratio*100)
	if IsTTY() {
		return StyleCyan.S(pctStr)
	}

	return pctStr
}

// progressColor maps progress state to a terminal color style.
func progressColor(plateauActive bool, severity string) colorStyle {
	switch {
	case plateauActive:
		return StyleMagenta
	case severity == severityCrit:
		return StyleRed
	case severity == severityWarn:
		return StyleYellow
	default:
		return StyleGreen
	}
}
