package main

import (
	"context"
	"math/rand/v2"
	"time"
)

const (
	asnRetryInitial = time.Minute
	asnRetryMaximum = 15 * time.Minute
)

type asnRefreshSchedule struct {
	interval time.Duration
	retry    time.Duration
}

// next resets after success and bounds failure retries independently of the regular refresh interval.
func (s *asnRefreshSchedule) next(err error) time.Duration {
	if err == nil {
		s.retry = 0
		return s.interval
	}

	if s.retry == 0 {
		s.retry = min(asnRetryInitial, s.interval)
	} else {
		s.retry = min(s.retry*2, asnRetryMaximum, s.interval)
	}
	// Half-to-full jitter avoids synchronized retries across replicas without exceeding the cap.
	return s.retry/2 + time.Duration(rand.Int64N(int64(s.retry-s.retry/2)))
}

// runASNRefresh retries transactional downloads until cancellation; only success restores the regular cadence.
func runASNRefresh(ctx context.Context, interval time.Duration, refresh func(context.Context) error) error {
	schedule := asnRefreshSchedule{interval: interval}
	for ctx.Err() == nil {
		delay := schedule.next(refresh(ctx))

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}

	return nil
}
