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

The implementation uses a simple feed-forward neural network with:
- 6 input neurons (for the features)
- 8 hidden neurons
- 1 output neuron (probability of brute force attack)

The neural network is properly initialized with small random weights and uses the sigmoid activation function for both hidden and output layers. The forward propagation algorithm correctly calculates activations through the network layers using the trained weights.

#### Training Algorithm

The neural network is trained using stochastic gradient descent with backpropagation:

1. **Forward Pass**: Calculate activations through the network
2. **Error Calculation**: Compute the error between predicted and actual outputs
3. **Backpropagation**: Calculate gradients and update weights to minimize error
4. **Iterative Learning**: Repeat the process for multiple epochs to improve accuracy

The training process automatically normalizes input features to appropriate ranges and logs progress during training. The trained model is persisted in Redis for reuse across restarts.

### Features Used

The model considers the following features:

1. **Time Between Attempts**: How quickly consecutive login attempts are made
2. **Failed Attempts in Last Hour**: Number of failed login attempts from the same IP
3. **Different Usernames**: Number of different usernames tried from the same IP
4. **Different Passwords**: Number of different passwords tried for the same username
5. **Time of Day**: When login attempts occur (normalized to 0-1)
6. **Suspicious Network**: Whether the IP is from a known suspicious network

#### Username Tracking

The system tracks different usernames tried from the same IP address using Redis Sets:

1. Each IP address has a Redis Set that stores unique usernames tried from that IP
2. When a login attempt is made, the username is added to the set for that IP
3. The number of different usernames (set cardinality) is used as a feature in the ML model
4. Sets expire after 1 hour to avoid accumulating stale data
5. This feature helps detect "username enumeration" attacks where an attacker tries many different usernames

This approach provides several benefits:
- Efficiently tracks unique usernames with minimal storage overhead
- Automatically handles duplicates (each username is counted only once)
- Provides fast lookup and counting operations
- Automatically expires old data to prevent memory leaks

#### Password Tracking

The system leverages the existing password history implementation to track different passwords tried for the same username:

1. Failed login attempts are stored in Redis with pseudonymized password hashes
2. The system uses the Redis key pattern `<prefix>:PW_HIST:<username>:<clientIP>` to store password history
3. Each password is hashed before storage to ensure security
4. The number of different passwords (hash keys in Redis) is used as a feature in the ML model
5. This feature helps detect "password guessing" attacks where an attacker tries many different passwords for the same username

This approach provides several benefits:
- Reuses the existing password history implementation from the standard brute force detection system
- Ensures passwords are never stored in plaintext
- Provides an accurate count of unique password attempts
- Integrates seamlessly with the rest of the ML-based detection system

### Integration with Existing System

The ML-based detection works alongside the existing rule-based system:

1. First, the traditional rule-based checks are performed
2. If no rule is triggered, the ML model evaluates the login attempt
3. If the ML model predicts a brute force attack with high probability, it blocks the attempt
4. All login attempts (successful or not) are recorded for future model training
5. The model is automatically trained with historical data once per day
6. Trained models are persisted in Redis for reuse across restarts

### Separation of Training and Prediction

The implementation separates the training functionality from the prediction functionality:

1. The `MLTrainer` handles the training of the model without requiring request-specific parameters
2. The `BruteForceMLDetector` handles the prediction functionality for specific requests
3. A global ML system manages the training and model persistence
4. All detectors share the same trained model

This separation allows the ML system to be initialized and trained without requiring request-specific parameters like guid, clientIP, and username. The training can happen in the background, independent of individual requests.

### Singleton Pattern

The ML system uses a singleton pattern with `sync.Once` to ensure that:

1. Only one instance of the trainer exists across all requests
2. Only one training scheduler is running at any time
3. Resources are shared efficiently between requests
4. The model is trained consistently with data from all requests

The implementation uses Go's `sync.Once` primitive, which guarantees that the initialization function is executed only once, even across multiple goroutines. This is more efficient than using a mutex for singleton initialization because:

1. It eliminates the need for locking after the first initialization
2. It's specifically designed for one-time initialization patterns
3. It provides better performance in high-concurrency scenarios

## How to Use

### Basic Integration

Replace the standard bucket manager creation with the ML-enhanced version:

```go
// Instead of:
// bm := bruteforce.NewBucketManager(ctx, guid, clientIP)

// Use:
bm := ml.NewMLBucketManager(ctx, guid, clientIP)
```

The rest of the code remains the same, as the ML-enhanced version implements the same BucketManager interface.

### Resource Cleanup

The ML system uses a singleton pattern with `sync.Once` to ensure that only one instance of the trainer exists and only one training scheduler is running. The `Close` method on both `MLBucketManager` and `BruteForceMLDetector` are now no-ops to prevent premature cleanup of the shared ML system.

When the application is shutting down, you should properly clean up the ML system:

```go
// Call this when your application is shutting down
ml.ShutdownMLSystem()
```

This will stop the training scheduler and clean up any resources used by the ML system.

### Manual Training

You can manually trigger training of the model:

```go
// If you have a reference to the ML bucket manager
if mlBM, ok := bm.(*ml.MLBucketManager); ok {
    // Train with 5000 samples for 50 epochs
    err := mlBM.TrainModel(5000, 50)
    if err != nil {
        // Handle error
    }
}
```

## Benefits

1. **Improved Detection**: Can detect sophisticated attacks that traditional rule-based systems might miss
2. **Reduced False Positives**: Can learn to distinguish between legitimate login failures and actual attacks
3. **Adaptability**: Automatically adapts to changing attack patterns over time
4. **Earlier Detection**: May detect attacks earlier, before they reach rule-based thresholds
5. **Contextual Awareness**: Considers multiple factors beyond just the number of failed attempts

## Future Improvements

1. **Advanced Model Architecture**: Implement more sophisticated neural network architectures (e.g., LSTM, GRU)
2. **Feature Engineering**: Add more sophisticated features like geographic location, device fingerprinting, etc.
3. **Hyperparameter Tuning**: Optimize the neural network architecture and parameters
4. **Ensemble Methods**: Combine multiple ML models for better accuracy
5. **Explainability**: Add tools to explain why a particular login attempt was flagged as suspicious
6. **Real-time Adaptation**: Implement online learning to adapt the model in real-time
7. **Model Evaluation**: Add metrics and tools to evaluate model performance
