<!-- TOC -->
  * [Prometheus](#prometheus)
  * [Grafana](#grafana)
<!-- TOC -->

There is some limited support for Prometheus and Grafana. For an example have a look at the contrib folder included with
the source code.

## Prometheus

```yaml
  - job_name: nauthilus
    scheme: https
    static_configs:
      - targets:
          - nauthilus.example.test:9443
    basic_auth:
      username: "nauthilususer"
      password: "nauthiluspassword"
```

Lines 6 and below are required, if nauthilus is protected with HTTP basic authentication. Please include the correct
values.

## Grafana

This is still work in progress. Here is an example screenshot.

[![img](https://nauthilus.io/wp-content/uploads/2022/11/nauthilus-grafana-1024x644.png)](https://nauthilus.io/wp-content/uploads/2022/11/nauthilus-grafana.png)
Sample dashboard (click to view the picture in full size)