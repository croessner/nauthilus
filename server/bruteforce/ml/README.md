# Machine Learning Enhanced Brute Force Detection

This package implements a machine learning approach to enhance the rule-based brute force detection system in Nauthilus.

## Overview

The traditional brute force detection in Nauthilus uses a rule-based approach with predefined thresholds for failed login attempts within specific time periods. While effective, this approach has limitations:

1. It relies on static thresholds that may not adapt to different usage patterns
2. It doesn't consider the broader context of login attempts
3. It may generate false positives for legitimate users with occasional typos
4. It may miss sophisticated attacks that stay just below the thresholds

The machine learning approach addresses these limitations by:

1. Learning from historical login patterns
2. Considering multiple features beyond just failed attempt counts
3. Adapting to different user behaviors
4. Potentially detecting attacks earlier based on subtle patterns

## Implementation

### Neural Network Model

The implementation uses a simple neural network with:
- 6 input neurons (for the features)
- 8 hidden neurons
- 1 output neuron (probability of brute force attack)

### Features Used

The model considers the following features:

1. **Time Between Attempts**: How quickly consecutive login attempts are made
2. **Failed Attempts in Last Hour**: Number of failed login attempts from the same IP
3. **Different Usernames**: Number of different usernames tried from the same IP
4. **Different Passwords**: Number of different passwords tried for the same username
5. **Time of Day**: When login attempts occur (normalized to 0-1)
6. **Suspicious Network**: Whether the IP is from a known suspicious network

### Integration with Existing System

The ML-based detection works alongside the existing rule-based system:

1. First, the traditional rule-based checks are performed
2. If no rule is triggered, the ML model evaluates the login attempt
3. If the ML model predicts a brute force attack with high probability, it blocks the attempt
4. All login attempts (successful or not) are recorded for future model training

## How to Use

Replace the standard bucket manager creation with the ML-enhanced version:

```go
// Instead of:
// bm := bruteforce.NewBucketManager(ctx, guid, clientIP)

// Use:
bm := ml.NewMLBucketManager(ctx, guid, clientIP)
```

The rest of the code remains the same, as the ML-enhanced version implements the same BucketManager interface.

## Benefits

1. **Improved Detection**: Can detect sophisticated attacks that traditional rule-based systems might miss
2. **Reduced False Positives**: Can learn to distinguish between legitimate login failures and actual attacks
3. **Adaptability**: Automatically adapts to changing attack patterns over time
4. **Earlier Detection**: May detect attacks earlier, before they reach rule-based thresholds
5. **Contextual Awareness**: Considers multiple factors beyond just the number of failed attempts

## Future Improvements

1. **Model Training**: Implement a scheduled job to periodically train the model with new data
2. **Feature Engineering**: Add more sophisticated features like geographic location, device fingerprinting, etc.
3. **Hyperparameter Tuning**: Optimize the neural network architecture and parameters
4. **Ensemble Methods**: Combine multiple ML models for better accuracy
5. **Explainability**: Add tools to explain why a particular login attempt was flagged as suspicious