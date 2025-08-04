# Nauthilus Grafana Dashboards

This directory contains Grafana dashboard configurations for monitoring Nauthilus.

## Available Dashboards

### 1. nauthilus.json

General Nauthilus metrics dashboard.

## Installation

1. Import the dashboard JSON file(s) into your Grafana instance.
2. Configure the Prometheus data source to point to your Nauthilus Prometheus endpoint.

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
