package engine

import (
	"context"
	"math"
	"time"
)

// AutoController describes the exported AutoController type.
type AutoController struct {
	config    *Config
	collector StatsCollector
	pacer     *Pacer
	app       *App
}

// NewAutoController provides the exported NewAutoController function.
func NewAutoController(cfg *Config, collector StatsCollector, pacer *Pacer, app *App) *AutoController {
	return &AutoController{
		config:    cfg,
		collector: collector,
		pacer:     pacer,
		app:       app,
	}
}

// Run provides the exported Run method.
func (c *AutoController) Run(ctx context.Context) {
	ctrlEvery := c.controlInterval()
	state := c.newAutoState()

	tk := time.NewTicker(ctrlEvery)
	defer tk.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			stats := c.collector.Snapshot()
			window := state.advance(stats, ctrlEvery, c.config.AutoMinSample)
			c.applyWindow(ctx, stats, window, state)
		}
	}
}

type autoState struct {
	currR         float64
	maxR          float64
	maxC          int
	lastTotal     int64
	lastErrs      int64
	prevRPS       float64
	plateauStreak int
	freezeWins    int
}

type autoWindow struct {
	deltaTotal int64
	deltaErrs  int64
	actualRPS  float64
	errRate    float64
	effMin     int64
}

// controlInterval returns the cadence used by adaptive control.
func (c *AutoController) controlInterval() time.Duration {
	return max(min(c.config.ProgressEvery, 5*time.Second), 1*time.Second)
}

// newAutoState initializes mutable adaptive-control state.
func (c *AutoController) newAutoState() *autoState {
	state := &autoState{
		currR: c.config.AutoStartRPS,
		maxR:  c.config.AutoMaxRPS,
		maxC:  c.config.AutoMaxConc,
	}
	if state.maxC <= 0 {
		state.maxC = c.config.Concurrency
	}

	c.setTargetRPS(state.currR)

	return state
}

// advance updates rolling counters and returns metrics for the current control window.
func (s *autoState) advance(stats Stats, interval time.Duration, minSample int) autoWindow {
	total := stats.Total
	errs := stats.HTTPErrs + stats.Aborted
	deltaTotal := total - s.lastTotal
	deltaErrs := errs - s.lastErrs
	s.lastTotal = total
	s.lastErrs = errs

	errRate := 0.0
	if deltaTotal > 0 {
		errRate = float64(deltaErrs) / float64(deltaTotal) * 100.0
	}

	return autoWindow{
		deltaTotal: deltaTotal,
		deltaErrs:  deltaErrs,
		actualRPS:  float64(deltaTotal) / interval.Seconds(),
		errRate:    errRate,
		effMin:     int64(math.Max(1, math.Round(float64(minSample)*interval.Seconds()/60.0))),
	}
}

// applyWindow chooses the adaptive-control action for one sampling window.
func (c *AutoController) applyWindow(ctx context.Context, stats Stats, window autoWindow, state *autoState) {
	if window.deltaTotal < window.effMin {
		c.rampUp(ctx, stats, state)

		return
	}

	if c.shouldBackoff(stats, window) {
		state.plateauStreak = 0
		c.backoff(stats, state)

		return
	}

	if c.freezeForPlateau(window.actualRPS, state) {
		return
	}

	c.rampUp(ctx, stats, state)
}

// setTargetRPS updates the pacer and collector target when pacing is active.
func (c *AutoController) setTargetRPS(rps float64) {
	if c.pacer == nil {
		return
	}

	c.pacer.SetRPS(rps)
	c.collector.SetTargetRPS(rps)
}

// shouldBackoff reports whether latency, error rate, or target tracking requires a reduction.
func (c *AutoController) shouldBackoff(stats Stats, window autoWindow) bool {
	trackRatio := 1.0
	if stats.TargetRPS > 0 {
		trackRatio = window.actualRPS / stats.TargetRPS
	}

	badP95 := stats.P95 > time.Duration(c.config.AutoTargetP95)*time.Millisecond
	badErr := window.errRate > c.config.AutoMaxErr
	badTrack := trackRatio < c.config.AutoPlateauTrackThreshold

	return badP95 || badErr || badTrack
}

// backoff reduces the active RPS and concurrency targets according to configuration.
func (c *AutoController) backoff(stats Stats, state *autoState) {
	c.backoffRPS(state)
	c.backoffConcurrency(stats)
}

// backoffRPS reduces the target RPS unless adaptive control is focused on concurrency.
func (c *AutoController) backoffRPS(state *autoState) {
	if c.config.AutoFocus == autoFocusConcurrency {
		return
	}

	state.currR = math.Floor(state.currR * c.config.AutoBackoff)
	if state.currR < 1 {
		state.currR = 1
	}

	c.setTargetRPS(state.currR)
}

// backoffConcurrency reduces worker concurrency unless adaptive control is focused on RPS.
func (c *AutoController) backoffConcurrency(stats Stats) {
	if c.config.AutoFocus == autoFocusRPS {
		return
	}

	oldC := stats.Concurrency

	newC := max(int64(math.Ceil(float64(oldC)*c.config.AutoBackoff)), 1)
	if oldC <= newC {
		return
	}

	c.app.ReduceWorkers(int(oldC - newC))
	c.collector.SetConcurrency(newC)
}

// freezeForPlateau updates plateau state and reports whether ramping should pause.
func (c *AutoController) freezeForPlateau(actualRPS float64, state *autoState) bool {
	if !c.config.AutoPlateau {
		c.collector.SetPlateauActive(false)

		return false
	}

	state.updatePlateauStreak(actualRPS, c.config.AutoPlateauGain)

	if state.plateauStreak < c.config.AutoPlateauWindows {
		c.collector.SetPlateauActive(false)

		return false
	}

	c.collector.SetPlateauActive(true)

	if c.config.AutoPlateauAction != autoPlateauActionFreeze {
		return false
	}

	if state.freezeWins < c.config.AutoPlateauCooldown {
		state.freezeWins++

		return true
	}

	state.freezeWins = 0
	state.plateauStreak = 0

	return false
}

// updatePlateauStreak records whether throughput gains stayed below the plateau threshold.
func (s *autoState) updatePlateauStreak(actualRPS float64, minGain float64) {
	if s.prevRPS > 0 {
		gain := (actualRPS - s.prevRPS) / s.prevRPS * 100.0
		if gain < minGain {
			s.plateauStreak++
		} else {
			s.plateauStreak = 0
		}
	}

	s.prevRPS = actualRPS
}

// rampUp increases RPS and concurrency targets according to the adaptive focus.
func (c *AutoController) rampUp(ctx context.Context, stats Stats, state *autoState) {
	c.rampRPS(state)
	c.rampConcurrency(ctx, stats, state)
}

// rampRPS increases the target RPS unless adaptive control is focused on concurrency.
func (c *AutoController) rampRPS(state *autoState) {
	if c.config.AutoFocus == autoFocusConcurrency {
		return
	}

	state.currR += c.config.AutoStepRPS
	if state.maxR > 0 && state.currR > state.maxR {
		state.currR = state.maxR
	}

	c.setTargetRPS(state.currR)
}

// rampConcurrency increases worker concurrency unless adaptive control is focused on RPS.
func (c *AutoController) rampConcurrency(ctx context.Context, stats Stats, state *autoState) {
	if c.config.AutoFocus == autoFocusRPS {
		return
	}

	oldC := stats.Concurrency
	if oldC >= int64(state.maxC) {
		return
	}

	inc := c.config.AutoStepConc
	if int64(state.maxC)-oldC < int64(inc) {
		inc = int(int64(state.maxC) - oldC)
	}

	c.app.SpawnWorkers(ctx, inc)
	c.collector.SetConcurrency(oldC + int64(inc))
}
