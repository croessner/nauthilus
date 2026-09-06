package main

import (
	"context"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	metricChannel          = "channel"
	metricResult           = "result"
	learningExternal       = "external"
	learningAuthentication = "authentication"
	learningRejected       = "rejected"
	learningUnavailable    = "unavailable"
	learningSkipped        = "skipped"
)

// initializeLearningMetrics requires one host-owned bounded collector before accepting evidence.
func (p *Plugin) initializeLearningMetrics(host pluginapi.Host) error {
	counter, err := host.Metrics(pluginName).Counter(pluginapi.MetricDefinition{
		Name: "learning_total", Help: "Reputation learning attempts by bounded channel and outcome.",
		Type: pluginapi.MetricTypeCounter, Labels: []string{metricChannel, metricResult},
	})
	if err != nil {
		return err
	}

	p.learningCounter = counter

	return nil
}

// recordLearning emits no caller identifiers, raw subjects, event IDs or contribution details.
func (p *Plugin) recordLearning(ctx context.Context, channel, result string) {
	if p == nil {
		return
	}

	p.mu.RLock()
	counter := p.learningCounter
	p.mu.RUnlock()

	if counter != nil {
		counter.Add(ctx, 1, pluginapi.LabelValue{Name: metricChannel, Value: channel}, pluginapi.LabelValue{Name: metricResult, Value: result})
	}
}

// learningIngestionResult distinguishes harmless retries from newly applied and partially acknowledged work.
func learningIngestionResult(result ingestionResult, err error) string {
	if err != nil {
		if result.Applied > 0 || result.Duplicates > 0 {
			return "partial"
		}

		return learningUnavailable
	}

	if result.Applied == 0 && result.Duplicates > 0 {
		return "duplicate"
	}

	return "applied"
}
