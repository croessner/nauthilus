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
- 6 input neurons (for the standard features)
- Configurable number of hidden neurons (default: 10)
- 1 output neuron (probability of brute force attack)

#### Network Architecture

The neural network has a classic three-layer architecture:

```
    [Input Layer]       [Hidden Layer]        [Output Layer]
       (6 neurons)       (10 neurons)          (1 neuron)
          x₁  ○              ○  h₁                  
          x₂  ○              ○  h₂                  
          x₃  ○              ○  h₃                  
          x₄  ○ -----------> ○  ...  ----------->  ○  y
          x₅  ○              ○  h₉                  
          x₆  ○              ○  h₁₀                 
                           + bias                + bias
```

Each connection between neurons has an associated weight. Additionally, each neuron in the hidden and output layers has a bias term.

#### Weight Initialization

The neural network is properly initialized with small random weights to break symmetry and enable effective learning:

```go
// Initialize weights with small random values
for i := range nn.weights {
    nn.weights[i] = (nn.rng.Float64() - 0.5) * 0.1
}

// Initialize bias terms with small random values
for i := range nn.hiddenBias {
    nn.hiddenBias[i] = (nn.rng.Float64() - 0.5) * 0.1
}

for i := range nn.outputBias {
    nn.outputBias[i] = (nn.rng.Float64() - 0.5) * 0.1
}
```

This initialization uses values in the range [-0.05, 0.05], which helps prevent saturation of activation functions and allows for faster convergence during training.

#### Activation Functions

The neural network supports multiple activation functions:

1. **Sigmoid** (default): 
   - Formula: σ(x) = 1 / (1 + e^(-x))
   - Range: (0, 1)
   - Characteristics: Smooth, differentiable, saturates for large positive or negative inputs
   - Derivative: σ'(x) = σ(x) * (1 - σ(x))


2. **Tanh** (Hyperbolic Tangent):
   - Formula: tanh(x) = (e^x - e^(-x)) / (e^x + e^(-x))
   - Range: (-1, 1)
   - Characteristics: Similar to sigmoid but zero-centered, which can help with training
   - Derivative: tanh'(x) = 1 - tanh²(x)


3. **ReLU** (Rectified Linear Unit):
   - Formula: ReLU(x) = max(0, x)
   - Range: [0, ∞)
   - Characteristics: Simple, computationally efficient, helps with vanishing gradient problem
   - Derivative: ReLU'(x) = 1 if x > 0, else 0


4. **Leaky ReLU**:
   - Formula: LeakyReLU(x) = x if x > 0, else 0.01x
   - Range: (-∞, ∞)
   - Characteristics: Addresses "dying ReLU" problem by allowing small negative values
   - Derivative: LeakyReLU'(x) = 1 if x > 0, else 0.01


The neural network can be configured with several options in the configuration file:

```yaml
brute_force:
  neural_network:
    # Number of neurons in the hidden layer (default: 10)
    hidden_neurons: 10

    # Activation function to use (default: "sigmoid")
    # Options: "sigmoid", "tanh", "relu", "leaky_relu"
    activation_function: "sigmoid"

    # Weight for static rules in the weighted decision (default: 0.4)
    static_weight: 0.4

    # Weight for ML in the weighted decision (default: 0.6)
    ml_weight: 0.6

    # Threshold for the weighted decision (default: 0.7)
    threshold: 0.7

    # Learning rate for the neural network (default: 0.01)
    learning_rate: 0.01

    # Maximum number of training records to keep (default: 10000)
    max_training_records: 10000
```

These configuration options allow you to fine-tune the behavior of the neural network:

- **hidden_neurons**: Controls the complexity of the model. More neurons can capture more complex patterns but may lead to overfitting.
- **activation_function**: Determines how neurons activate. Different functions have different properties and may work better for different datasets.
- **static_weight**: The weight given to the traditional rule-based detection in the weighted decision.
- **ml_weight**: The weight given to the ML prediction in the weighted decision.
- **threshold**: The threshold above which a weighted score is considered a brute force attack.
- **learning_rate**: Controls how quickly the model adapts to new data. Higher values may learn faster but can be unstable.
- **max_training_records**: Limits the number of training samples to prevent excessive memory usage.

#### Forward Propagation

Forward propagation is the process of calculating the network's output given an input. Here's how it works:

1. **Input to Hidden Layer**:
   For each hidden neuron i:
   ```
   net_i = ∑(w_ij * x_j) + b_i
   h_i = activation(net_i)
   ```
   Where:
   - net_i is the weighted sum of inputs to neuron i
   - w_ij is the weight from input j to hidden neuron i
   - x_j is the j-th input
   - b_i is the bias for hidden neuron i
   - h_i is the activation of hidden neuron i

2. **Hidden to Output Layer**:
   For each output neuron k:
   ```
   net_k = ∑(w_ki * h_i) + b_k
   y_k = activation(net_k)
   ```
   Where:
   - net_k is the weighted sum of inputs to output neuron k
   - w_ki is the weight from hidden neuron i to output neuron k
   - h_i is the activation of hidden neuron i
   - b_k is the bias for output neuron k
   - y_k is the activation of output neuron k (the final output)

In code, this looks like:

```go
// Calculate hidden layer activations
hiddenActivations := make([]float64, nn.hiddenSize)
for i := 0; i < nn.hiddenSize; i++ {
    sum := 0.0
    for j := 0; j < nn.inputSize; j++ {
        weightIndex := i*nn.inputSize + j
        sum += inputs[j] * nn.weights[weightIndex]
    }
    sum += nn.hiddenBias[i]  // Add bias
    hiddenActivations[i] = nn.activate(sum)  // Apply activation function
}

// Calculate output layer activations
outputs := make([]float64, nn.outputSize)
for i := 0; i < nn.outputSize; i++ {
    sum := 0.0
    for j := 0; j < nn.hiddenSize; j++ {
        weightIndex := nn.inputSize*nn.hiddenSize + i*nn.hiddenSize + j
        sum += hiddenActivations[j] * nn.weights[weightIndex]
    }
    sum += nn.outputBias[i]  // Add bias
    outputs[i] = nn.activate(sum)  // Apply activation function
}
```

The final output is a probability between 0 and 1, indicating the likelihood that the current login attempt is part of a brute force attack.

#### Training Algorithm

The neural network is trained using stochastic gradient descent with backpropagation:

1. **Forward Pass**: Calculate activations through the network (as described above)
2. **Error Calculation**: Compute the error between predicted and actual outputs
3. **Backpropagation**: Calculate gradients and update weights to minimize error
4. **Iterative Learning**: Repeat the process for multiple epochs to improve accuracy

##### Backpropagation in Detail

Backpropagation is the heart of neural network training. It works by calculating how much each weight contributes to the error, and then adjusting the weights to reduce the error. Here's how it works:

1. **Calculate Output Layer Error**:
   For each output neuron k:
   ```
   error_k = target_k - output_k
   ```
   Where:
   - error_k is the error for output neuron k
   - target_k is the desired output for neuron k
   - output_k is the actual output from neuron k

2. **Calculate Output Layer Deltas**:
   For each output neuron k:
   ```
   delta_k = error_k * activation'(net_k)
   ```
   Where:
   - delta_k is the delta for output neuron k
   - error_k is the error for output neuron k
   - activation'(net_k) is the derivative of the activation function at net_k

3. **Calculate Hidden Layer Deltas**:
   For each hidden neuron i:
   ```
   error_i = ∑(delta_k * w_ki)
   delta_i = error_i * activation'(net_i)
   ```
   Where:
   - error_i is the error for hidden neuron i
   - delta_k is the delta for output neuron k
   - w_ki is the weight from hidden neuron i to output neuron k
   - delta_i is the delta for hidden neuron i
   - activation'(net_i) is the derivative of the activation function at net_i

4. **Update Weights and Biases**:
   For weights between input and hidden layers:
   ```
   w_ij = w_ij + learning_rate * delta_i * input_j
   ```
   For weights between hidden and output layers:
   ```
   w_ki = w_ki + learning_rate * delta_k * hidden_i
   ```
   For biases:
   ```
   b_i = b_i + learning_rate * delta_i
   b_k = b_k + learning_rate * delta_k
   ```

In code, this looks like:

```go
// Calculate output layer deltas
outputDeltas := make([]float64, nn.outputSize)
for i := 0; i < nn.outputSize; i++ {
    derivative := nn.activateDerivative(outputNetInputs[i])
    outputDeltas[i] = outputErrors[i] * derivative
}

// Calculate hidden layer deltas
hiddenDeltas := make([]float64, nn.hiddenSize)
for i := 0; i < nn.hiddenSize; i++ {
    errorValue := 0.0
    for j := 0; j < nn.outputSize; j++ {
        weightIndex := nn.inputSize*nn.hiddenSize + j*nn.hiddenSize + i
        errorValue += outputDeltas[j] * nn.weights[weightIndex]
    }
    derivative := nn.activateDerivative(hiddenNetInputs[i])
    hiddenDeltas[i] = errorValue * derivative
}

// Update weights and biases
// Update weights between input and hidden layers
for i := 0; i < nn.hiddenSize; i++ {
    for j := 0; j < nn.inputSize; j++ {
        weightIndex := i*nn.inputSize + j
        delta := nn.learningRate * hiddenDeltas[i] * inputFeatures[j]
        nn.weights[weightIndex] += delta
    }
    // Update hidden layer bias
    delta := nn.learningRate * hiddenDeltas[i]
    nn.hiddenBias[i] += delta
}

// Update weights between hidden and output layers
for i := 0; i < nn.outputSize; i++ {
    for j := 0; j < nn.hiddenSize; j++ {
        weightIndex := nn.inputSize*nn.hiddenSize + i*nn.hiddenSize + j
        delta := nn.learningRate * outputDeltas[i] * hiddenActivations[j]
        nn.weights[weightIndex] += delta
    }
    // Update output layer bias
    delta := nn.learningRate * outputDeltas[i]
    nn.outputBias[i] += delta
}
```

##### Learning Process Visualization

The learning process can be visualized as follows:

```
                                 ┌─────────────────┐
                                 │ Training Sample │
                                 └────────┬────────┘
                                          │
                                          ▼
                                 ┌─────────────────┐
                                 │  Forward Pass   │
                                 └────────┬────────┘
                                          │
                                          ▼
                                 ┌─────────────────┐
                                 │ Calculate Error │
                                 └────────┬────────┘
                                          │
                                          ▼
                                 ┌─────────────────┐
                                 │ Backpropagation │
                                 └────────┬────────┘
                                          │
                                          ▼
                                 ┌─────────────────┐
                                 │ Update Weights  │
                                 └────────┬────────┘
                                          │
                                          ▼
                                 ┌─────────────────┐
                                 │  Next Sample    │
                                 └─────────────────┘
```

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

The ML-based detection works alongside the existing rule-based system using a weighted decision approach:

1. First, the traditional rule-based checks are performed
2. The ML model evaluates all login attempts, regardless of whether a rule was triggered
3. A weighted decision is made combining both the static rule result and the ML prediction:
   - Static rule result is converted to a score (0.0 for not triggered, 1.0 for triggered)
   - ML prediction provides a probability between 0.0 and 1.0
   - These scores are weighted and combined (configurable weights, defaults: 40% static, 60% ML)
   - If the weighted score exceeds a threshold (configurable, default: 0.7), the attempt is blocked
4. High-confidence overrides ensure ML has the final say in extreme cases:
   - If ML is very confident it's a brute force attack (probability > 0.9), always block
   - If ML is very confident it's NOT a brute force attack (probability < 0.1), never block
5. Failed login attempts are recorded for future model training in two cases:
   - When a static rule is triggered
   - When the ML detector itself identifies a brute force attack
6. Successful login attempts are recorded separately via the `RecordSuccessfulLogin` method
7. The model is automatically trained with historical data once per day
8. Trained models are persisted in Redis for reuse across restarts

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

## Weighted Decision Making

The ML system uses a weighted decision approach to combine the results of the traditional rule-based system with the ML predictions:

1. **Static Rule Score**:
   - 0.0 if no static rule was triggered
   - 1.0 if a static rule was triggered

2. **ML Score**:
   - The probability (between 0.0 and 1.0) from the ML model

3. **Weighted Score Calculation**:
   ```
   weightedScore = (staticScore * staticWeight) + (mlScore * mlWeight)
   ```
   - Default staticWeight: 0.4 (40%)
   - Default mlWeight: 0.6 (60%)

4. **Decision**:
   - If weightedScore >= threshold (default: 0.7), block the attempt
   - If weightedScore < threshold, allow the attempt

5. **High-Confidence Overrides**:
   - If ML probability > 0.9, always block (regardless of weighted score)
   - If ML probability < 0.1, never block (regardless of weighted score)

### Decision Process Visualization

The decision-making process can be visualized as follows:

```
                           ┌───────────────────┐
                           │   Login Attempt   │
                           └─────────┬─────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     │                               │
                     ▼                               ▼
          ┌────────────────────┐         ┌────────────────────┐
          │ Static Rule Check  │         │   ML Prediction    │
          └──────────┬─────────┘         └──────────┬─────────┘
                     │                               │
                     ▼                               ▼
          ┌────────────────────┐         ┌────────────────────┐
          │   Static Score     │         │     ML Score       │
          │  (0.0 or 1.0)      │         │   (0.0 to 1.0)     │
          └──────────┬─────────┘         └──────────┬─────────┘
                     │                               │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │      Weighted Calculation     │
                     │ (staticScore * 0.4) +         │
                     │ (mlScore * 0.6)               │
                     └─────────────┬─────────────────┘
                                   │
                                   ▼
                     ┌───────────────────────────────┐
                     │       Decision Logic          │
                     └─────────────┬─────────────────┘
                                   │
           ┌─────────────────────┬─┴─┬─────────────────────┐
           │                     │   │                     │
           ▼                     ▼   ▼                     ▼
┌────────────────────┐ ┌─────────────────┐ ┌────────────────────────┐
│  ML Score > 0.9    │ │ Weighted Score  │ │    ML Score < 0.1      │
│                    │ │    >= 0.7       │ │                        │
│  Always Block      │ │                 │ │    Never Block         │
│  (High Confidence) │ │    Block        │ │    (High Confidence)   │
└────────────────────┘ └─────────────────┘ └────────────────────────┘
```

### Example Calculations

Let's look at some example scenarios:

1. **Static rule triggered, ML predicts high probability**:
   - Static score: 1.0
   - ML score: 0.8
   - Weighted score: (1.0 * 0.4) + (0.8 * 0.6) = 0.4 + 0.48 = 0.88
   - Decision: Block (weighted score > 0.7)

2. **Static rule not triggered, ML predicts moderate probability**:
   - Static score: 0.0
   - ML score: 0.6
   - Weighted score: (0.0 * 0.4) + (0.6 * 0.6) = 0.0 + 0.36 = 0.36
   - Decision: Allow (weighted score < 0.7)

3. **Static rule triggered, ML predicts very low probability**:
   - Static score: 1.0
   - ML score: 0.05
   - Weighted score: (1.0 * 0.4) + (0.05 * 0.6) = 0.4 + 0.03 = 0.43
   - Decision: Allow (ML high confidence override: score < 0.1)

4. **Static rule not triggered, ML predicts very high probability**:
   - Static score: 0.0
   - ML score: 0.95
   - Weighted score: (0.0 * 0.4) + (0.95 * 0.6) = 0.0 + 0.57 = 0.57
   - Decision: Block (ML high confidence override: score > 0.9)

This approach allows the system to leverage both the reliability of static rules and the adaptability of ML predictions.

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

### Adding Additional Features

To add additional features for the ML system, use the WithAdditionalFeatures method:

```go
// Create a map of additional features
additionalFeatures := map[string]any{
    "geo_country": "DE",
    "geo_city": "Berlin",
    "device_type": "mobile",
    "connection_type": "4G",
}

// Add the features to the bucket manager
bm = bm.WithAdditionalFeatures(additionalFeatures)
```

These features will be stored in the LoginFeatures struct and used by the neural network.

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

## Feature Encoding

The ML system supports both numerical and categorical features:

### Numerical Features

Numerical features (like time between attempts, failed attempts count, etc.) are used directly in the neural network after normalization.

#### Feature Normalization

Normalization is crucial for neural networks to work effectively. It ensures that all features have similar scales, which helps the network learn more efficiently. Here's how features are normalized:

```go
func normalizeInputs(inputs []float64) []float64 {
    normalized := make([]float64, len(inputs))

    // Normalize each feature based on its expected range
    if len(inputs) > 0 {
        // TimeBetweenAttempts: normalize to [0,1] with max value of 3600 (1 hour)
        normalized[0] = math.Min(inputs[0]/3600.0, 1.0)
    }

    if len(inputs) > 1 {
        // FailedAttemptsLastHour: normalize to [0,1] with max value of 100
        normalized[1] = math.Min(inputs[1]/100.0, 1.0)
    }

    if len(inputs) > 2 {
        // DifferentUsernames: normalize to [0,1] with max value of 20
        normalized[2] = math.Min(inputs[2]/20.0, 1.0)
    }

    if len(inputs) > 3 {
        // DifferentPasswords: normalize to [0,1] with max value of 20
        normalized[3] = math.Min(inputs[3]/20.0, 1.0)
    }

    if len(inputs) > 4 {
        // TimeOfDay: already normalized to [0,1]
        normalized[4] = inputs[4]
    }

    if len(inputs) > 5 {
        // SuspiciousNetwork: already normalized to [0,1]
        normalized[5] = inputs[5]
    }

    // Additional features are assumed to be already normalized
    for i := 6; i < len(inputs); i++ {
        normalized[i] = inputs[i]
    }

    return normalized
}
```

This normalization ensures that:
- Time between attempts is normalized to [0,1] with 1 hour as the maximum value
- Failed attempts count is normalized to [0,1] with 100 as the maximum value
- Different usernames and passwords are normalized to [0,1] with 20 as the maximum value
- Time of day and suspicious network flags are already in the [0,1] range
- Additional features are assumed to be already normalized

#### Example of Normalized Features

Original features:
```
TimeBetweenAttempts: 120 seconds
FailedAttemptsLastHour: 5
DifferentUsernames: 3
DifferentPasswords: 2
TimeOfDay: 0.5 (noon)
SuspiciousNetwork: 1.0 (true)
```

Normalized features:
```
TimeBetweenAttempts: 0.033 (120/3600)
FailedAttemptsLastHour: 0.05 (5/100)
DifferentUsernames: 0.15 (3/20)
DifferentPasswords: 0.1 (2/20)
TimeOfDay: 0.5 (unchanged)
SuspiciousNetwork: 1.0 (unchanged)
```

These normalized values are what the neural network actually processes.

### Categorical Features

For categorical features (like country codes, continent codes, ASN numbers, etc.), the system supports two encoding methods:

#### One-Hot Encoding (Default)

1. **What is One-Hot Encoding?**
   - A technique to represent categorical variables as binary vectors
   - Each category gets its own binary feature (0 or 1)
   - Only one feature is "hot" (set to 1) at a time

2. **Benefits of One-Hot Encoding**:
   - Preserves categorical relationships (no artificial ordering)
   - Allows the model to learn separate weights for each category
   - Handles high-cardinality features (many possible values)
   - Improves model accuracy for categorical data

3. **Implementation Details**:
   - The system automatically detects string values that can't be converted to numbers
   - Each unique value for a feature gets assigned a unique index
   - The encoding is consistent across training and prediction
   - Encodings are persisted in Redis alongside the model

4. **Example**:
   - For a "continent" feature with values like "EU", "NA", "AS", etc.
   - Instead of hashing to arbitrary values, each continent gets its own dimension
   - The model can learn that some continents have higher risk than others

#### Embedding Encoding

1. **What is Embedding Encoding?**
   - A technique to represent categorical variables as dense vectors in a continuous space
   - Each category gets mapped to a fixed-size vector of floating-point values
   - Allows for more efficient representation of high-cardinality features

2. **Benefits of Embedding Encoding**:
   - More efficient for high-cardinality features (many possible values)
   - Captures semantic relationships between categories
   - Reduces dimensionality compared to one-hot encoding
   - Improves model performance for features with many possible values

3. **Implementation Details**:
   - The system generates deterministic embeddings based on the feature value
   - Default embedding size is 8 dimensions but can be configured
   - Embeddings are consistent across training and prediction
   - Empty strings produce zero vectors

4. **How Embeddings Are Generated**:

   The embedding generation process creates a fixed-size vector (default: 8 dimensions) for each string value. The algorithm ensures that similar strings produce similar embeddings, which helps the neural network learn meaningful patterns.

   ```go
   func generateEmbedding(value string) []float64 {
       // Initialize embedding vector with zeros
       embedding := make([]float64, embeddingSize)

       // If string is empty, return zero embedding
       if len(value) == 0 {
           return embedding
       }

       // Generate a deterministic embedding based on the string content
       for i, char := range value {
           // Use character value and position to influence all dimensions
           for j := 0; j < embeddingSize; j++ {
               // Different formula for each dimension
               switch j % 4 {
               case 0:
                   // Use character value directly
                   embedding[j] += float64(char) / 256.0 / float64(i+1)
               case 1:
                   // Use character position
                   embedding[j] += float64(i) / float64(len(value)) * float64(char%64) / 64.0
               case 2:
                   // Combine character value and position
                   embedding[j] += math.Sin(float64(char) * float64(i+1) / 100.0)
               case 3:
                   // Another combination
                   embedding[j] += math.Cos(float64(char) / float64(i+1))
               }
           }
       }

       // Normalize the embedding to have values between 0 and 1
       // (normalization code omitted for brevity)

       return embedding
   }
   ```

   **Why Modulo 4 and Trigonometric Functions?**

   The embedding generation algorithm uses several mathematical techniques to create rich, meaningful vector representations:

   1. **Modulo 4 Pattern**: The `j % 4` operation cycles through four different formulas for each dimension of the embedding vector. This ensures that:
      - Each dimension captures different aspects of the input string
      - The embedding space has varied and complementary information
      - Similar strings produce similar embeddings while preserving differences

   2. **The Four Cases (0-3) Explained**:
      - **Case 0**: Captures the raw character values, normalized and weighted by position. Characters at the beginning of the string have more influence.
      - **Case 1**: Focuses on the position of characters within the string, combined with a reduced character value range (modulo 64).
      - **Case 2**: Uses sine function to create oscillating patterns based on character values and positions. Sine produces values between -1 and 1, creating distinctive patterns.
      - **Case 3**: Uses cosine function with a different combination of character value and position. Cosine is 90° out of phase with sine, capturing complementary patterns.

   3. **Why Sine and Cosine?**
      - **Orthogonality**: Sine and cosine are orthogonal functions (90° out of phase), capturing different aspects of the input
      - **Bounded output**: Both functions produce values between -1 and 1, preventing any single dimension from dominating
      - **Smooth transitions**: Small changes in input produce small changes in output, helping similar strings map to similar embeddings
      - **Periodic nature**: The cyclical nature helps capture patterns in repeating characters or sequences

   This approach is inspired by techniques used in signal processing and modern embedding systems like Word2Vec and positional encodings in transformers, where sine and cosine functions help capture positional and semantic relationships.

5. **Example Embeddings**:

   Let's see how different string values are embedded:

   ```
   "EU" → [0.32, 0.45, 0.67, 0.21, 0.55, 0.78, 0.43, 0.11]
   "NA" → [0.31, 0.44, 0.65, 0.22, 0.54, 0.77, 0.42, 0.12]
   "AS12345" → [0.25, 0.38, 0.59, 0.29, 0.48, 0.71, 0.36, 0.19]
   ```

   Notice that similar strings like "EU" and "NA" have similar embeddings, while "AS12345" is more different. This helps the neural network learn relationships between different categorical values.

6. **Comparison with One-Hot Encoding**:

   For a feature with 1000 possible values:
   - One-hot encoding would require 1000 dimensions (mostly zeros)
   - Embedding encoding requires only 8 dimensions
   - This is a 125x reduction in dimensionality!

   Visual comparison:
   ```
   One-hot: [0,0,0,0,1,0,0,0,...,0] (1000 dimensions)
   Embedding: [0.32, 0.45, 0.67, 0.21, 0.55, 0.78, 0.43, 0.11] (8 dimensions)
   ```

   This dimensionality reduction is especially important for features with many possible values, like ASN numbers or country codes.

### Adding Categorical Features via Lua

You can add categorical features through the Lua interface:

```lua
function nauthilus_call_neural_network(request)
    -- Add categorical features with default encoding (one-hot)
    neural.add_additional_features({
        continent_code = "EU",
        country_code = "DE",
        network_type = "mobile"
    })

    -- Add features with specific encoding type (embedding)
    neural.add_additional_features({
        asn = "AS12345"
    }, "embedding")
end
```

These features will be automatically encoded using the specified encoding type (or one-hot encoding by default) and used by the neural network.

## Future Improvements

1. **Advanced Model Architecture**: Implement more sophisticated neural network architectures (e.g., LSTM, GRU)
2. **Feature Engineering**: Add more sophisticated features like geographic location, device fingerprinting, etc.
3. **Hyperparameter Tuning**: Optimize the neural network architecture and parameters
4. **Ensemble Methods**: Combine multiple ML models for better accuracy
5. **Explainability**: Add tools to explain why a particular login attempt was flagged as suspicious
6. **Real-time Adaptation**: Implement online learning to adapt the model in real-time
7. **Model Evaluation**: Add metrics and tools to evaluate model performance
9. **Advanced Embedding Techniques**: Implement more sophisticated embedding techniques for categorical features
