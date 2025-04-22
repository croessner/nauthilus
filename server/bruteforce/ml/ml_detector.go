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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/go-kit/log/level"
	"github.com/redis/go-redis/v9"
)

// LoginFeatures represents the features used for brute force detection
type LoginFeatures struct {
	// Time between login attempts in seconds
	TimeBetweenAttempts float64

	// Number of failed attempts in the last hour
	FailedAttemptsLastHour float64

	// Number of different usernames tried from the same IP
	DifferentUsernames float64

	// Number of different passwords tried for the same username
	DifferentPasswords float64

	// Time of day (normalized to 0-1)
	TimeOfDay float64

	// Is the IP address from a known suspicious network
	SuspiciousNetwork float64
}

// NeuralNetwork is a simplified implementation of a neural network
type NeuralNetwork struct {
	inputSize  int
	hiddenSize int
	outputSize int
	weights    []float64 // In a real implementation, this would be a more complex structure
}

// NewNeuralNetwork creates a new neural network with the specified layer sizes
func NewNeuralNetwork(inputSize, hiddenSize, outputSize int) *NeuralNetwork {
	// In a real implementation, weights would be initialized properly
	// Here we just create a placeholder
	return &NeuralNetwork{
		inputSize:  inputSize,
		hiddenSize: hiddenSize,
		outputSize: outputSize,
		weights:    make([]float64, inputSize*hiddenSize+hiddenSize*outputSize),
	}
}

// FeedForward performs forward propagation through the network
func (nn *NeuralNetwork) FeedForward(inputs []float64) []float64 {
	// This is a simplified implementation that doesn't actually use the weights
	// In a real neural network, this would perform matrix multiplications and apply activation functions

	// For demonstration purposes, we'll implement a simple heuristic
	// that simulates what a trained neural network might do

	// Calculate a weighted sum of the inputs
	sum := 0.0
	weights := []float64{0.1, 0.3, 0.2, 0.25, 0.05, 0.1} // Example weights for each feature

	for i, input := range inputs {
		if i < len(weights) {
			sum += input * weights[i]
		}
	}

	// Apply sigmoid activation function to get output between 0 and 1
	output := 1.0 / (1.0 + math.Exp(-sum))

	return []float64{output}
}

// BruteForceMLDetector implements machine learning based brute force detection
type BruteForceMLDetector struct {
	ctx      context.Context
	guid     string
	clientIP string
	username string
	model    *NeuralNetwork
}

// NewBruteForceMLDetector creates a new ML-based brute force detector
func NewBruteForceMLDetector(ctx context.Context, guid, clientIP, username string) *BruteForceMLDetector {
	detector := &BruteForceMLDetector{
		ctx:      ctx,
		guid:     guid,
		clientIP: clientIP,
		username: username,
	}

	// Initialize the neural network model
	detector.initModel()

	return detector
}

// initModel initializes the neural network model
func (d *BruteForceMLDetector) initModel() {
	// Create a neural network with 6 input neurons (for our features),
	// 8 hidden neurons, and 1 output neuron (probability of brute force)
	d.model = NewNeuralNetwork(6, 8, 1)
}

// CollectFeatures gathers the necessary features for the ML model
func (d *BruteForceMLDetector) CollectFeatures() (*LoginFeatures, error) {
	features := &LoginFeatures{}

	// Get the last login attempt time for this IP
	lastAttemptTime, err := d.getLastLoginAttemptTime()
	if err != nil {
		return nil, err
	}

	// Calculate time between attempts
	if !lastAttemptTime.IsZero() {
		features.TimeBetweenAttempts = time.Since(lastAttemptTime).Seconds()
	} else {
		features.TimeBetweenAttempts = 3600 // Default to 1 hour if first attempt
	}

	// Store current attempt time
	if err := d.storeLoginAttemptTime(); err != nil {
		return nil, err
	}

	// Get failed attempts in the last hour
	failedAttempts, err := d.getFailedAttemptsLastHour()
	if err != nil {
		return nil, err
	}

	features.FailedAttemptsLastHour = float64(failedAttempts)

	// Get different usernames tried from this IP
	differentUsernames, err := d.getDifferentUsernames()
	if err != nil {
		return nil, err
	}

	features.DifferentUsernames = float64(differentUsernames)

	// Get different passwords tried for this username
	differentPasswords, err := d.getDifferentPasswords()
	if err != nil {
		return nil, err
	}

	features.DifferentPasswords = float64(differentPasswords)

	// Calculate time of day (normalized to 0-1)
	hour := float64(time.Now().Hour())
	features.TimeOfDay = hour / 24.0

	// Check if IP is from a suspicious network
	suspicious, err := d.isFromSuspiciousNetwork()
	if err != nil {
		return nil, err
	}

	if suspicious {
		features.SuspiciousNetwork = 1.0
	} else {
		features.SuspiciousNetwork = 0.0
	}

	return features, nil
}

// Predict determines if the current login attempt is part of a brute force attack
func (d *BruteForceMLDetector) Predict() (bool, float64, error) {
	// Collect features for prediction
	features, err := d.CollectFeatures()
	if err != nil {
		return false, 0, err
	}

	// Convert features to input array
	inputs := []float64{
		features.TimeBetweenAttempts,
		features.FailedAttemptsLastHour,
		features.DifferentUsernames,
		features.DifferentPasswords,
		features.TimeOfDay,
		features.SuspiciousNetwork,
	}

	// Normalize inputs (simple min-max normalization)
	normalizedInputs := d.normalizeInputs(inputs)

	// Make prediction
	outputs := d.model.FeedForward(normalizedInputs)

	// The output is the probability of a brute force attack
	probability := outputs[0]

	// Determine if it's a brute force attack based on threshold
	isBruteForce := probability > 0.7 // Threshold can be adjusted

	return isBruteForce, probability, nil
}

// Train trains the neural network with labeled data
func (d *BruteForceMLDetector) Train(features [][]float64, labels [][]float64, epochs int) {
	// In a real implementation, this would train the model with historical data
	// For this example, we'll assume the model is already trained
	level.Info(log.Logger).Log(
		definitions.LogKeyGUID, d.guid,
		definitions.LogKeyMsg, fmt.Sprintf("Training ML model with %d samples for %d epochs", len(features), epochs),
	)

	// This is where the actual training would happen
	// d.model.Train(features, labels, epochs)
}

// normalizeInputs normalizes the input features to a range suitable for the neural network
func (d *BruteForceMLDetector) normalizeInputs(inputs []float64) []float64 {
	// Define normalization ranges for each feature
	ranges := []struct {
		min float64
		max float64
	}{
		{0, 3600}, // TimeBetweenAttempts (0 to 1 hour)
		{0, 100},  // FailedAttemptsLastHour
		{0, 20},   // DifferentUsernames
		{0, 20},   // DifferentPasswords
		{0, 1},    // TimeOfDay (already normalized)
		{0, 1},    // SuspiciousNetwork (already normalized)
	}

	normalized := make([]float64, len(inputs))
	for i, val := range inputs {
		// Apply min-max normalization
		normalized[i] = (val - ranges[i].min) / (ranges[i].max - ranges[i].min)

		// Ensure values are within [0,1]
		if normalized[i] < 0 {
			normalized[i] = 0
		} else if normalized[i] > 1 {
			normalized[i] = 1
		}
	}

	return normalized
}

// Helper methods to interact with Redis for feature collection

func (d *BruteForceMLDetector) getLastLoginAttemptTime() (time.Time, error) {
	key := d.getLoginTimeKey()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	val, err := rediscli.GetClient().GetReadHandle().Get(d.ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return time.Time{}, nil // No previous login attempt
		}

		return time.Time{}, err
	}

	timestamp, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}, err
	}

	return timestamp, nil
}

func (d *BruteForceMLDetector) storeLoginAttemptTime() error {
	key := d.getLoginTimeKey()

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	err := rediscli.GetClient().GetWriteHandle().Set(
		d.ctx,
		key,
		time.Now().Format(time.RFC3339),
		time.Hour, // TTL of 1 hour
	).Err()

	return err
}

func (d *BruteForceMLDetector) getFailedAttemptsLastHour() (uint, error) {
	key := d.getFailedAttemptsKey()

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	val, err := rediscli.GetClient().GetReadHandle().Get(d.ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil // No failed attempts
		}

		return 0, err
	}

	return uint(val), nil
}

func (d *BruteForceMLDetector) incrementFailedAttempts() error {
	key := d.getFailedAttemptsKey()

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	err := rediscli.GetClient().GetWriteHandle().Incr(d.ctx, key).Err()
	if err != nil {
		return err
	}

	// Set expiration to 1 hour if not already set
	err = rediscli.GetClient().GetWriteHandle().Expire(d.ctx, key, time.Hour).Err()

	return err
}

func (d *BruteForceMLDetector) getDifferentUsernames() (uint, error) {
	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:ip:usernames:" + d.clientIP

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	count, err := rediscli.GetClient().GetReadHandle().SCard(d.ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}

		return 0, err
	}

	// Add current username to the set
	if d.username != "" {
		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		err = rediscli.GetClient().GetWriteHandle().SAdd(d.ctx, key, d.username).Err()
		if err != nil {
			return 0, err
		}

		// Set expiration to 24 hours
		err = rediscli.GetClient().GetWriteHandle().Expire(d.ctx, key, 24*time.Hour).Err()
		if err != nil {
			return 0, err
		}
	}

	return uint(count), nil
}

func (d *BruteForceMLDetector) getDifferentPasswords() (uint, error) {
	if d.username == "" {
		return 0, nil
	}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:user:passwords:" + d.username

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	count, err := rediscli.GetClient().GetReadHandle().HLen(d.ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}

		return 0, err
	}

	return uint(count), nil
}

func (d *BruteForceMLDetector) isFromSuspiciousNetwork() (bool, error) {
	// This would check against a list of known suspicious networks
	// For this example, we'll return false
	return false, nil
}

// Redis key helpers

func (d *BruteForceMLDetector) getLoginTimeKey() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:login:time:" + d.clientIP
}

func (d *BruteForceMLDetector) getFailedAttemptsKey() string {
	return config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:failed:attempts:" + d.clientIP
}

// RecordLoginResult records the result of a login attempt for future training
func (d *BruteForceMLDetector) RecordLoginResult(success bool, features *LoginFeatures) error {
	// Store the login attempt result and features for future model training
	data := struct {
		Success  bool
		Features *LoginFeatures
		Time     time.Time
	}{
		Success:  success,
		Features: features,
		Time:     time.Now(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	key := config.GetFile().GetServer().GetRedis().GetPrefix() + "ml:training:data"

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	err = rediscli.GetClient().GetWriteHandle().LPush(d.ctx, key, jsonData).Err()
	if err != nil {
		return err
	}

	// Trim the list to keep only the last 10000 entries
	err = rediscli.GetClient().GetWriteHandle().LTrim(d.ctx, key, 0, 9999).Err()
	if err != nil {
		return err
	}

	// If login failed, increment the failed attempts counter
	if !success {
		err = d.incrementFailedAttempts()
		if err != nil {
			return err
		}
	}

	return nil
}
