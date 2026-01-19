package engine

import (
	"sync"
	"time"
)

// Pacer generates ticks at a configurable RPS and allows live reconfiguration.
type Pacer struct {
	mu    sync.Mutex
	rps   float64
	ch    chan time.Time
	stopC chan struct{}
}

// NewPacer creates a new Pacer.
func NewPacer(rps float64) *Pacer {
	p := &Pacer{
		ch:    make(chan time.Time, 1),
		stopC: make(chan struct{}),
	}

	if rps <= 0 {
		rps = 1
	}

	p.rps = rps
	go p.loop()

	return p
}

func (p *Pacer) loop() {
	for {
		p.mu.Lock()
		r := p.rps
		p.mu.Unlock()

		interval := time.Duration(float64(time.Second) / r)
		if interval <= 0 {
			interval = time.Nanosecond
		}

		select {
		case <-time.After(interval):
			select {
			case p.ch <- time.Now():
			default:
			}
		case <-p.stopC:
			return
		}
	}
}

// SetRPS updates the pacing rate.
func (p *Pacer) SetRPS(rps float64) {
	if rps <= 0 {
		rps = 1
	}

	p.mu.Lock()
	p.rps = rps
	p.mu.Unlock()
}

// Tick returns a stable receive-only channel delivering pacing ticks.
func (p *Pacer) Tick() <-chan time.Time {
	return p.ch
}

// Stop terminates the internal goroutine.
func (p *Pacer) Stop() {
	close(p.stopC)
}
