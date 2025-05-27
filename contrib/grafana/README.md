# Nauthilus Grafana Dashboards

This directory contains Grafana dashboard configurations for monitoring Nauthilus.

## Available Dashboards

### 1. nauthilus.json

General Nauthilus metrics dashboard.

### 2. nauthilus-ml.json

Machine Learning metrics dashboard for monitoring the neural network used for brute force detection.

### 3. nauthilus-distributed-brute-force.json

Dashboard for monitoring distributed brute force attack detection metrics. This dashboard visualizes metrics collected by the global pattern monitoring system, which is designed to detect distributed brute force attacks that use many unique IP addresses with few attempts per IP.

## Distributed Brute Force Dashboard

The distributed brute force dashboard provides visualization for metrics related to detecting distributed brute force attacks. It includes:

### Current Metrics
- Authentication attempts in different time windows (1m, 5m, 15m, 1h)
- Unique IPs in different time windows
- Unique users in different time windows
- Key indicators for distributed brute force attacks (1h window)

### Derived Metrics
- Attempts per IP: A low value combined with a high number of unique IPs can indicate a distributed brute force attack
- Attempts per user: A high value can indicate a targeted brute force attack
- IPs per user: A high value can indicate a distributed brute force attack targeting specific users

### Historical Metrics
- Historical authentication attempts per hour
- Historical unique IPs per hour
- Historical derived metrics (attempts per IP, attempts per user, IPs per user)

## Installation

1. Import the dashboard JSON files into your Grafana instance.
2. Configure the Prometheus data source to point to your Nauthilus Prometheus endpoint.
3. Ensure that the experimental_ml environment variable is set to enable the ML metrics collection.

## Requirements

- Nauthilus with Redis for storing metrics
- Prometheus for scraping metrics
- Grafana for visualization

## Importing Dashboards into Grafana

### Prerequisites

1. A running Grafana instance (version 11.0.0 or later recommended)
2. Prometheus data source configured in Grafana
3. Nauthilus exporting metrics to Prometheus

### Import Steps

1. Open your Grafana instance in a web browser
2. Navigate to Dashboards > Import
3. Either:
   - Upload the JSON file directly
   - Copy the contents of the JSON file and paste it into the "Import via panel json" text area
4. Select the appropriate Prometheus data source when prompted
5. Click "Import"

### Installing Multiple Instances

If you want to have multiple instances of the same dashboard (e.g., to compare configurations or test changes):

1. Before importing, open the JSON file in a text editor
2. Find the line containing `"uid": "e4491148-50c2-485d-8eb3-c594dd7a4099"` (near the end of the file)
3. Either:
   - Remove this line completely (Grafana will generate a new UID)
   - Replace the UID with a different value
   - Leave it as is if you want to replace an existing dashboard
4. Change the dashboard title to something distinctive
5. Save the file and import it as described above

## Machine Learning Dashboard

The Machine Learning dashboard (`nauthilus-ml.json`) provides comprehensive visualizations for monitoring the neural network used in Nauthilus's brute force detection system.

### Dashboard Sections

1. **Neural Network Structure**
   - Visualizes the size of each layer (input, hidden, output) in the neural network

2. **Training Metrics**
   - Training Error: Shows the error rate during training over time
   - Training Progress: Displays the current epoch in the training process
   - Training Samples Used: Shows the number of samples used for training
   - Training Duration: Visualizes the duration of training operations

3. **Prediction Metrics**
   - Brute Force Prediction Confidence: Gauge showing the confidence level of brute force predictions
   - Prediction Results: Pie chart showing the distribution of true/false predictions
   - Prediction Duration: Graph showing the time taken to make predictions

4. **Feature Metrics**
   - Feature Values: Time series of the values of features used in predictions

5. **Neuron Activation Metrics**
   - Hidden Layer Neuron Activations: Heatmap showing activation values of neurons in the hidden layer
   - Output Layer Neuron Activations: Bar gauge showing activation values of neurons in the output layer

### Using the Dashboard

- The dashboard auto-refreshes every 5 seconds by default
- Time range can be adjusted using the time picker at the top right
- Hover over any panel for more detailed information
- Click on panel titles to see panel options and edit if needed

### Interpreting the Data

1. **Network Structure**
   - Larger layer sizes may indicate more complex models that can capture more patterns but might be slower to train

2. **Training Metrics**
   - Decreasing error rates indicate the model is learning effectively
   - Stable or increasing error rates might indicate overfitting or other training issues

3. **Prediction Metrics**
   - High confidence with correct predictions indicates a well-trained model
   - Low confidence or incorrect predictions may indicate the model needs more training or refinement

4. **Feature Values**
   - Unusual spikes or patterns in feature values might indicate anomalies or attacks
   - Consistent patterns can help understand normal behavior

5. **Neuron Activations**
   - Diverse activation patterns indicate the network is using its capacity effectively
   - Dead neurons (consistently low activation) might indicate training issues

## Grafana 11.x Compatibility

The dashboards have been updated to be compatible with Grafana 11.x. The following changes were made:

1. Updated the Grafana version requirement to 11.0.0 or later
2. Updated the dashboard schema version to 40 (compatible with Grafana 11.x)

If you encounter any issues with the dashboards in Grafana 11.x:

1. Make sure you're using the latest version of the dashboard JSON files
2. Check that all required panel plugins are installed in your Grafana instance
3. If a panel doesn't render correctly, try changing its visualization type and then changing it back

## Troubleshooting

If metrics are not appearing in the dashboard:

1. Verify that Nauthilus is running and exporting metrics
2. Check that Prometheus is scraping the Nauthilus metrics endpoint
3. Ensure the Prometheus data source in Grafana is correctly configured
4. Check for any errors in the Grafana logs
5. Try adjusting the time range to ensure data is within the selected period
