// Copyright (C) 2025 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package signalsfx

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"syscall"

	"go.uber.org/fx"
)

type ReloadRunner interface {
	// Reload triggers a configuration reload operation.
	Reload(ctx context.Context) error
}

type RestartRunner interface {
	// Restart triggers an in-process restart operation.
	Restart(ctx context.Context) error
}

// Controller owns OS signal subscriptions and translates them into application actions.
//
// It is designed to be started/stopped from an fx lifecycle hook and is testable by
// injecting a Notifier implementation.
type Controller struct {
	ctx    context.Context
	cancel context.CancelFunc

	logger   *slog.Logger
	notifier Notifier

	reloadMgr  ReloadRunner
	restartMgr RestartRunner

	mu    sync.Mutex
	sigCh chan os.Signal
	wg    sync.WaitGroup
}

type controllerIn struct {
	fx.In

	Ctx    context.Context
	Cancel context.CancelFunc

	Logger   *slog.Logger
	Notifier Notifier

	ReloadManager  ReloadRunner
	RestartManager RestartRunner
}

// NewController constructs a Controller.
func NewController(in controllerIn) *Controller {
	return &Controller{
		ctx:        in.Ctx,
		cancel:     in.Cancel,
		logger:     in.Logger,
		notifier:   in.Notifier,
		reloadMgr:  in.ReloadManager,
		restartMgr: in.RestartManager,
	}
}

// Start subscribes to OS signals and starts the internal routing loop.
//
// Start is idempotent.
func (c *Controller) Start(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.sigCh != nil {
		return nil
	}

	sigCh := make(chan os.Signal, 8)
	c.sigCh = sigCh
	c.notifier.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.loop(sigCh)
	}()

	return nil
}

// Stop unsubscribes from OS signals and waits for the routing loop to exit.
func (c *Controller) Stop(_ context.Context) error {
	c.mu.Lock()
	sigCh := c.sigCh
	c.sigCh = nil
	c.mu.Unlock()

	if sigCh != nil {
		c.notifier.Stop(sigCh)
		close(sigCh)
	}

	c.wg.Wait()

	return nil
}

func (c *Controller) loop(sigCh <-chan os.Signal) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case sig, ok := <-sigCh:
			if !ok {
				return
			}

			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				c.logger.Info("received termination signal", slog.Any("signal", sig))
				c.cancel()

				return
			case syscall.SIGHUP:
				c.logger.Info("received reload signal", slog.Any("signal", sig))

				if c.reloadMgr != nil {
					_ = c.reloadMgr.Reload(c.ctx)
				}
			case syscall.SIGUSR1:
				c.logger.Info("received restart signal", slog.Any("signal", sig))

				if c.restartMgr != nil {
					_ = c.restartMgr.Restart(c.ctx)
				}
			default:
				c.logger.Debug("received unhandled signal", slog.Any("signal", sig))
			}
		}
	}
}
