package engine

import (
	"go.uber.org/fx"
)

// Module provides the fx module for the client engine.
var Module = fx.Module("engine",
	fx.Provide(
		NewStatsCollector,
		NewAuthClient,
		NewCSVSourceFromConfig,
		NewPacerFromConfig,
		NewApp,
	),
)

// NewStatsCollector provides a StatsCollector implementation.
func NewStatsCollector() StatsCollector {
	return NewDefaultStatsCollector()
}

// NewCSVSourceFromConfig provides a RowSource based on the configuration.
func NewCSVSourceFromConfig(cfg *Config) (RowSource, error) {
	return NewCSVSource(cfg.CSVPath, 0, cfg.CSVDebug, cfg.MaxRows, cfg.Shuffle)
}

// NewPacerFromConfig provides an optional Pacer based on the configuration.
func NewPacerFromConfig(cfg *Config, collector StatsCollector) *Pacer {
	if cfg.RPS > 0 || (cfg.AutoMode && cfg.AutoStartRPS > 0) {
		initialRPS := cfg.RPS
		if cfg.AutoMode && cfg.AutoStartRPS > 0 {
			initialRPS = cfg.AutoStartRPS
		}
		pacer := NewPacer(initialRPS)
		collector.SetTargetRPS(initialRPS)
		return pacer
	}
	return nil
}
