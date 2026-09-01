// Copyright (C) 2026 Christian Roessner
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

// Package prometheusutil centralizes strict Prometheus collector reuse.
package prometheusutil

import (
	"errors"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
)

// RegisterCollector registers a collector or returns an exactly compatible existing collector.
func RegisterCollector[T prometheus.Collector](
	registerer prometheus.Registerer,
	collector T,
	reuse bool,
	validateExisting func(T) error,
) (T, error) {
	var zero T

	if registerer == nil {
		return collector, nil
	}

	if err := registerer.Register(collector); err != nil {
		var already prometheus.AlreadyRegisteredError
		if reuse && errors.As(err, &already) {
			if !sameCollectorDescriptors(already.ExistingCollector, collector) {
				return zero, errors.New("existing Prometheus collector descriptor differs from requested contract")
			}

			existing, ok := already.ExistingCollector.(T)
			if !ok {
				return zero, err
			}

			if validateExisting != nil {
				if validateErr := validateExisting(existing); validateErr != nil {
					return zero, validateErr
				}
			}

			return existing, nil
		}

		return zero, err
	}

	return collector, nil
}

// sameCollectorDescriptors compares complete ordered descriptor strings.
func sameCollectorDescriptors(left prometheus.Collector, right prometheus.Collector) bool {
	return slices.Equal(collectorDescriptorStrings(left), collectorDescriptorStrings(right))
}

// collectorDescriptorStrings drains and sorts immutable collector descriptors.
func collectorDescriptorStrings(collector prometheus.Collector) []string {
	descriptors := make(chan *prometheus.Desc)

	go func() {
		collector.Describe(descriptors)
		close(descriptors)
	}()

	result := make([]string, 0)
	for descriptor := range descriptors {
		result = append(result, descriptor.String())
	}

	slices.Sort(result)

	return result
}
