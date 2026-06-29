# Nauthilus Grafana Dashboards

This directory contains Grafana dashboard configurations for monitoring Nauthilus.

## Available Dashboards

### 1. nauthilus.json

General Nauthilus metrics dashboard.

### 2. nauthilus-rest-admin-infinity.json

`Nauthilus REST Admin Center` is a Grafana Infinity dashboard for the authenticated backchannel API. It does not expose runtime configuration readback.

Included views:

- Brute-force overview from `GET /api/v1/bruteforce/list`
- Active bans grouped by bucket
- Active ban and blocked-account tables with Grafana-side pagination

## Installation

1. Import the dashboard JSON file(s) into your Grafana instance.
2. Configure the matching data source for the dashboard you import.

## Requirements

- Nauthilus with Redis for storing metrics
- Prometheus for scraping metrics
- Grafana for visualization
- Grafana Infinity data source for `nauthilus-rest-admin-infinity.json`

## Importing Dashboards into Grafana

### Prerequisites

1. A running Grafana instance (version 11.0.0 or later recommended)
2. Prometheus data source configured in Grafana
3. Nauthilus exporting metrics to Prometheus
4. For `nauthilus-rest-admin-infinity.json`, an Infinity data source configured for the Nauthilus backchannel API

### Import Steps

1. Open your Grafana instance in a web browser
2. Navigate to Dashboards > Import
3. Either:
   - Upload the JSON file directly
   - Copy the contents of the JSON file and paste it into the "Import via panel json" text area
4. Select the appropriate data source when prompted
5. Click "Import"

For the REST admin dashboard, select the configured Infinity data source when Grafana prompts for "Nauthilus REST Infinity datasource".

## REST Admin Dashboard

The REST admin dashboard is intentionally auth-mode neutral. Configure exactly one Infinity data source for the Nauthilus backchannel API, matching the global Nauthilus backchannel authentication mode:

- Basic Auth: configure the Infinity data source with the same backchannel Basic Auth credentials Nauthilus accepts.
- Bearer tokens: configure the Infinity data source with OAuth2 client credentials. The token must carry the base backchannel scope `nauthilus:authenticate`, and brute-force visibility requires `nauthilus:security` or `nauthilus:admin` as an additional scope.

Recommended data source setup:

1. Leave the Infinity data source Base URL empty.
2. Add the Nauthilus origin to the Infinity data source Allowed hosts list, for example `https://nauthilus.example.com`. Do not include `/api/v1` in the allowed host.
3. If OAuth2 client credentials are used, enter scopes in the format expected by the Infinity UI, for example `openid,nauthilus:authenticate,nauthilus:admin,nauthilus:security`. The resulting token must contain `nauthilus:authenticate` plus either `nauthilus:admin` or `nauthilus:security` in its `scope` claim.
4. Keep the imported Infinity queries on the UQL parser.

The dashboard uses absolute query URLs such as `https://nauthilus.example.com/api/v1/bruteforce/list`. It sends `GET` requests for read-only brute-force visibility and avoids stale Grafana dashboard-variable values and relative URLs being checked against the Infinity Allowed hosts list.

If Grafana shows `requested URL not allowed`, open the Infinity data source settings and add the Nauthilus origin to Allowed hosts. Infinity requires this when authentication, custom headers, or TLS options are configured.

If the REST panels fail with `missing required scope: nauthilus:authenticate`, the OAuth2 client credentials setup is missing the base backchannel scope. When testing the token endpoint manually with `curl`, send OAuth scopes as a space-separated form value, for example `scope=openid nauthilus:authenticate nauthilus:admin nauthilus:security`.

Mutating operations are intentionally not implemented as Infinity panels. Grafana queries panels on load, refresh, and inspection; a `DELETE` panel would therefore execute automatically instead of behaving like a guarded button. Use explicit operator commands for the flush endpoints.

User cache flush:

```bash
curl -sS -X DELETE "https://nauthilus.example.com/api/v1/cache/flush" \
  -H "Authorization: Bearer ${NAUTHILUS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"user":"alice@example.test"}'
```

Brute-force flush:

```bash
curl -sS -X DELETE "https://nauthilus.example.com/api/v1/bruteforce/flush" \
  -H "Authorization: Bearer ${NAUTHILUS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"ip_address":"203.0.113.10","rule_name":"rule-name","protocol":"imap","oidc_cid":""}'
```

The dashboard does not include runtime config loading by design.

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
