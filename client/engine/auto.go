package engine

import (
	"context"
	"math"
	"time"
)

type AutoController struct {
	config    *Config
	collector StatsCollector
	pacer     *Pacer
	app       *App
}

func NewAutoController(cfg *Config, collector StatsCollector, pacer *Pacer, app *App) *AutoController {
	return &AutoController{
		config:    cfg,
		collector: collector,
		pacer:     pacer,
		app:       app,
	}
}

func (c *AutoController) Run(ctx context.Context) {
	// Control cadence: at most every 5s to ramp faster regardless of progress interval
	ctrlEvery := max(min(c.config.ProgressEvery, 5*time.Second), 1*time.Second)

	maxR := c.config.AutoMaxRPS
	maxC := c.config.AutoMaxConc
	if maxC <= 0 {
		maxC = c.config.Concurrency
	}

	currR := c.config.AutoStartRPS
	if c.pacer != nil {
		c.pacer.SetRPS(currR)
		c.collector.SetTargetRPS(currR)
	}

	var lastTotal int64
	var lastErrs int64

	tk := time.NewTicker(ctrlEvery)
	defer tk.Stop()

	var prevRPS float64
	var plateauStreak int
	var freezeWins int

	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			stats := c.collector.Snapshot()
			tNow := stats.Total
			eNow := stats.HttpErrs + stats.Aborted
			dt := tNow - lastTotal
			de := eNow - lastErrs
			lastTotal = tNow
			lastErrs = eNow

			effMin := int64(math.Max(1, math.Round(float64(c.config.AutoMinSample)*ctrlEvery.Seconds()/60.0)))

			if dt < effMin {
				// Too few samples: ramp up optimistically
				if c.config.AutoFocus != "concurrency" {
					currR += c.config.AutoStepRPS
					if maxR > 0 && currR > maxR {
						currR = maxR
					}
					if c.pacer != nil {
						c.pacer.SetRPS(currR)
						c.collector.SetTargetRPS(currR)
					}
				}
				if c.config.AutoFocus != "rps" {
					oldC := stats.Concurrency
					if oldC < int64(maxC) {
						inc := c.config.AutoStepConc
						if int64(maxC)-oldC < int64(inc) {
							inc = int(int64(maxC) - oldC)
						}
						c.app.SpawnWorkers(ctx, inc)
						c.collector.SetConcurrency(oldC + int64(inc))
					}
				}
				continue
			}

			// Judge based on metrics
			p95 := stats.P95
			errRate := 0.0
			if dt > 0 {
				errRate = float64(de) / float64(dt) * 100.0
			}

			// Plateau detection
			actualRPS := float64(dt) / ctrlEvery.Seconds()

			trackRatio := 1.0
			if stats.TargetRPS > 0 {
				trackRatio = actualRPS / stats.TargetRPS
			}

			badP95 := p95 > time.Duration(c.config.AutoTargetP95)*time.Millisecond
			badErr := errRate > c.config.AutoMaxErr
			badTrack := trackRatio < c.config.AutoPlateauTrackThreshold

			shouldBackoff := badP95 || badErr || badTrack

			if shouldBackoff {
				plateauStreak = 0
				if c.config.AutoFocus != "concurrency" {
					currR = math.Floor(currR * c.config.AutoBackoff)
					if currR < 1 {
						currR = 1
					}
					if c.pacer != nil {
						c.pacer.SetRPS(currR)
						c.collector.SetTargetRPS(currR)
					}
				}
				if c.config.AutoFocus != "rps" {
					oldC := stats.Concurrency
					newC := max(int64(math.Ceil(float64(oldC)*c.config.AutoBackoff)), 1)
					if oldC > newC {
						c.app.ReduceWorkers(int(oldC - newC))
						c.collector.SetConcurrency(newC)
					}
				}
				continue
			}

			if c.config.AutoPlateau && prevRPS > 0 {
				gain := (actualRPS - prevRPS) / prevRPS * 100.0
				if gain < c.config.AutoPlateauGain {
					plateauStreak++
				} else {
					plateauStreak = 0
				}
			}
			prevRPS = actualRPS

			if c.config.AutoPlateau && plateauStreak >= c.config.AutoPlateauWindows {
				c.collector.SetPlateauActive(true)
				if c.config.AutoPlateauAction == "freeze" {
					if freezeWins < c.config.AutoPlateauCooldown {
						freezeWins++
						continue
					}
					freezeWins = 0
					plateauStreak = 0
				}
			} else {
				c.collector.SetPlateauActive(false)
			}

			// Ramp up
			if c.config.AutoFocus != "concurrency" {
				currR += c.config.AutoStepRPS
				if maxR > 0 && currR > maxR {
					currR = maxR
				}
				if c.pacer != nil {
					c.pacer.SetRPS(currR)
					c.collector.SetTargetRPS(currR)
				}
			}
			if c.config.AutoFocus != "rps" {
				oldC := stats.Concurrency
				if oldC < int64(maxC) {
					inc := c.config.AutoStepConc
					if int64(maxC)-oldC < int64(inc) {
						inc = int(int64(maxC) - oldC)
					}
					c.app.SpawnWorkers(ctx, inc)
					c.collector.SetConcurrency(oldC + int64(inc))
				}
			}
		}
	}
}
