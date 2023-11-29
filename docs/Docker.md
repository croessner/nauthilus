The recommended way of installing nauthilus is using docker.

## Using docker compose

The following docker-compose.yml file is a really basic example. Please have a look at the reference page and the
configuration page to build your own docker environment:

```yaml
services:

  nauthilus:
    container_name: nauthilus
    image: gitlab.roessner-net.de:5050/croessner/nauthilus:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      TZ: "Europe/Berlin"
      AUTHSERV_VERBOSE_LEVEL: "info"
      AUTHSERV_FEATURES: "tls_encryption rbl"
      AUTHSERV_LOG_FORMAT: "default"
      AUTHSERV_HTTP_ADDRESS: "[::]:8080"
      AUTHSERV_PASSDB_BACKENDS: "cache test"
      AUTHSERV_TEST_PASSDB_USERNAME: ${TEST_PASSDB_USERNAME}
      AUTHSERV_TEST_PASSDB_PASSWORD: ${TEST_PASSDB_PASSWORD}
      AUTHSERV_TEST_PASSDB_ACCOUNT: ${TEST_PASSDB_ACCOUNT}

    healthcheck:
      test: [ "CMD", "/usr/app/healthcheck", "--url", "http://nauthilus:8080/ping" ]
      timeout: 60s
      interval: 30s
      retries: 2
      start_period: 3s
```
