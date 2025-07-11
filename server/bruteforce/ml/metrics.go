// Copyright (C) 2024 Christian Rößner
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

package ml

import (
	"strconv"
	"sync" // Used for sync.Once in the singleton pattern

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Singleton instance of MLMetrics
	mlMetrics     *MLMetrics
	initMLMetrics sync.Once
)

// MLMetrics contains all Prometheus metrics related to the neural network
type MLMetrics struct {
	// Neural network structure metrics
	networkStructure *prometheus.GaugeVec // Labels: layer (input, hidden, output), size

	// Training metrics
	trainingError       *prometheus.GaugeVec     // Labels: epoch
	trainingProgress    prometheus.Gauge         // Current epoch
	trainingSamplesUsed prometheus.Gauge         // Number of samples used in training
	trainingDuration    *prometheus.HistogramVec // Labels: result (success, failure)

	// Prediction metrics
	predictionConfidence *prometheus.GaugeVec     // Labels: result (true, false)
	predictionCount      *prometheus.CounterVec   // Labels: result (true, false)
	predictionDuration   *prometheus.HistogramVec // Labels: result (true, false)

	// Feature metrics
	featureValues *prometheus.GaugeVec // Labels: feature_name

	// Neuron activation metrics
	neuronActivations *prometheus.GaugeVec // Labels: layer (hidden, output), neuron_index

	// Weight metrics
	weightValues *prometheus.GaugeVec // Labels: from_layer, from_index, to_layer, to_index
}

// GetMLMetrics returns the singleton instance of MLMetrics
func GetMLMetrics() *MLMetrics {
	initMLMetrics.Do(func() {
		if mlMetrics == nil {
			mlMetrics = newMLMetrics()
		}
	})

	return mlMetrics
}

// newMLMetrics creates a new instance of MLMetrics with all Prometheus metrics initialized
func newMLMetrics() *MLMetrics {
	return &MLMetrics{
		// Neural network structure metrics
		networkStructure: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_ml_network_structure",
				Help: "Structure of the neural network (layer sizes)",
			},
			[]string{"layer"},
		),

		// Training metrics
		trainingError: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_ml_training_error",
				Help: "Error during neural network training",
			},
			[]string{"epoch"},
		),
		trainingProgress: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "nauthilus_ml_training_progress",
				Help: "Current epoch in neural network training",
			},
		),
		trainingSamplesUsed: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "nauthilus_ml_training_samples_used",
				Help: "Number of samples used in neural network training",
			},
		),
		trainingDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "nauthilus_ml_training_duration_seconds",
				Help:    "Duration of neural network training",
				Buckets: prometheus.ExponentialBuckets(0.01, 2, 10),
			},
			[]string{"result"},
		),

		// Prediction metrics
		predictionConfidence: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_ml_prediction_confidence",
				Help: "Confidence score of neural network predictions",
			},
			[]string{"result"},
		),
		predictionCount: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nauthilus_ml_prediction_count",
				Help: "Count of neural network predictions",
			},
			[]string{"result"},
		),
		predictionDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "nauthilus_ml_prediction_duration_seconds",
				Help:    "Duration of neural network prediction",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
			},
			[]string{"result"},
		),

		// Feature metrics
		featureValues: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_ml_feature_values",
				Help: "Values of features used in neural network prediction",
			},
			[]string{"feature_name"},
		),

		// Neuron activation metrics
		neuronActivations: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_ml_neuron_activations",
				Help: "Activation values of neurons in the neural network",
			},
			[]string{"layer", "neuron_index"},
		),

		// Weight metrics
		weightValues: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nauthilus_ml_weight_values",
				Help: "Weight values in the neural network",
			},
			[]string{"from_layer", "from_index", "to_layer", "to_index"},
		),
	}
}

// RecordNetworkStructure records the structure of the neural network
func (m *MLMetrics) RecordNetworkStructure(inputSize, hiddenSize, outputSize int) {
	m.networkStructure.WithLabelValues("input").Set(float64(inputSize))
	m.networkStructure.WithLabelValues("hidden").Set(float64(hiddenSize))
	m.networkStructure.WithLabelValues("output").Set(float64(outputSize))
}

// RecordTrainingError records the error during training
func (m *MLMetrics) RecordTrainingError(epoch int, error float64) {
	m.trainingError.WithLabelValues(strconv.Itoa(epoch)).Set(error)
	m.trainingProgress.Set(float64(epoch))
}

// RecordTrainingSamplesUsed records the number of samples used in training
func (m *MLMetrics) RecordTrainingSamplesUsed(samples int) {
	m.trainingSamplesUsed.Set(float64(samples))
}

// RecordTrainingDuration records the duration of training
func (m *MLMetrics) RecordTrainingDuration(duration float64, success bool) {
	result := "failure"
	if success {
		result = "success"
	}

	m.trainingDuration.WithLabelValues(result).Observe(duration)
}

// RecordPrediction records a prediction made by the neural network
func (m *MLMetrics) RecordPrediction(confidence float64, isBruteForce bool, duration float64) {
	result := "false"
	if isBruteForce {
		result = "true"
	}

	m.predictionConfidence.WithLabelValues(result).Set(confidence)
	m.predictionCount.WithLabelValues(result).Inc()
	m.predictionDuration.WithLabelValues(result).Observe(duration)
}

// RecordFeatureValue records a feature value used in prediction
func (m *MLMetrics) RecordFeatureValue(featureName string, value float64) {
	m.featureValues.WithLabelValues(featureName).Set(value)
}

// RecordNeuronActivation records the activation of a neuron
func (m *MLMetrics) RecordNeuronActivation(layer string, neuronIndex int, activation float64) {
	m.neuronActivations.WithLabelValues(layer, strconv.Itoa(neuronIndex)).Set(activation)
}

// RecordWeightValue records a weight value in the neural network
func (m *MLMetrics) RecordWeightValue(fromLayer string, fromIndex int, toLayer string, toIndex int, weight float64) {
	m.weightValues.WithLabelValues(fromLayer, strconv.Itoa(fromIndex), toLayer, strconv.Itoa(toIndex)).Set(weight)
}

// recordWeightMetrics records the current weight and bias values as Prometheus metrics
func (nn *NeuralNetwork) recordWeightMetrics() {
	metrics := GetMLMetrics()

	// Record weights between input and hidden layers
	for i := 0; i < nn.hiddenSize; i++ {
		for j := 0; j < nn.inputSize; j++ {
			weightIndex := i*nn.inputSize + j
			if weightIndex < len(nn.weights) {
				metrics.RecordWeightValue("input", j, "hidden", i, nn.weights[weightIndex])
			}
		}

		// Record hidden layer bias
		if i < len(nn.hiddenBias) {
			metrics.RecordWeightValue("bias", 0, "hidden", i, nn.hiddenBias[i])
		}
	}

	// Record weights between hidden and output layers
	for i := 0; i < nn.outputSize; i++ {
		for j := 0; j < nn.hiddenSize; j++ {
			weightIndex := nn.inputSize*nn.hiddenSize + i*nn.hiddenSize + j
			if weightIndex < len(nn.weights) {
				metrics.RecordWeightValue("hidden", j, "output", i, nn.weights[weightIndex])
			}
		}

		// Record output layer bias
		if i < len(nn.outputBias) {
			metrics.RecordWeightValue("bias", 0, "output", i, nn.outputBias[i])
		}
	}
}
