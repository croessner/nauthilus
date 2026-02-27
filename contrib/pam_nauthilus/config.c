/*
 * config.c – PAM module configuration parsing.
 */

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* safe_copy copies src into dst with bounds checking. */
static int safe_copy(char *dst, size_t dstlen, const char *src)
{
    if (strlen(src) >= dstlen) {
        return -1;
    }

    strncpy(dst, src, dstlen - 1);
    dst[dstlen - 1] = '\0';

    return 0;
}

/* has_scheme returns true if the URL starts with a scheme (e.g. "https://"). */
static int has_scheme(const char *url)
{
    const char *p = strstr(url, "://");

    return p != NULL && p != url;
}

/* is_https returns true if the URL starts with "https://". */
static int is_https(const char *url)
{
    return strncmp(url, "https://", 8) == 0;
}

/*
 * validate_endpoint checks that an endpoint URL has a scheme and host,
 * and enforces HTTPS unless allow_http is set.
 */
static int validate_endpoint(const char *url, int allow_http,
                             char *errbuf, size_t errlen)
{
    if (url[0] == '\0') {
        snprintf(errbuf, errlen, "endpoint is empty");

        return -1;
    }

    if (!has_scheme(url)) {
        snprintf(errbuf, errlen, "endpoint must include scheme and host: %s", url);

        return -1;
    }

    if (!allow_http && !is_https(url)) {
        snprintf(errbuf, errlen, "endpoint must use https unless allow_http=true: %s", url);

        return -1;
    }

    return 0;
}

/* join_endpoint appends path to base, writing into dst. */
static int join_endpoint(char *dst, size_t dstlen,
                         const char *base, const char *path)
{
    size_t blen = strlen(base);

    /* Strip trailing slash from base. */
    while (blen > 0 && base[blen - 1] == '/') {
        blen--;
    }

    int n = snprintf(dst, dstlen, "%.*s%s", (int)blen, base, path);

    if (n < 0 || (size_t)n >= dstlen) {
        return -1;
    }

    return 0;
}

void settings_init(pam_settings *s)
{
    memset(s, 0, sizeof(*s));

    safe_copy(s->scope, sizeof(s->scope), DEFAULT_SCOPE);
    safe_copy(s->user_claim, sizeof(s->user_claim), DEFAULT_USER_CLAIM);

    s->timeout_sec = DEFAULT_TIMEOUT_SEC;
    s->request_timeout_sec = DEFAULT_REQ_TIMEOUT_SEC;
    s->allow_http = false;
}

long parse_duration(const char *value)
{
    if (value == NULL || value[0] == '\0') {
        return -1;
    }

    size_t len = strlen(value);
    char last = value[len - 1];

    /* Pure numeric → seconds. */
    if (isdigit((unsigned char)last)) {
        char *end = NULL;
        long sec = strtol(value, &end, 10);

        if (*end != '\0' || sec < 0) {
            return -1;
        }

        return sec;
    }

    /* Go-style suffixes: s, m, h. */
    char *end = NULL;
    long num = strtol(value, &end, 10);

    if (num < 0 || end == value) {
        return -1;
    }

    switch (*end) {
    case 's':
        return num;
    case 'm':
        return num * 60;
    case 'h':
        return num * 3600;
    default:
        return -1;
    }
}

int settings_parse(pam_settings *s, int argc, const char **argv,
                   char *errbuf, size_t errlen)
{
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];

        if (arg == NULL || arg[0] == '\0') {
            continue;
        }

        const char *eq = strchr(arg, '=');
        char key[128] = {0};
        const char *value = "true";

        if (eq != NULL) {
            size_t klen = (size_t)(eq - arg);

            if (klen >= sizeof(key)) {
                snprintf(errbuf, errlen, "option key too long");

                return -1;
            }

            memcpy(key, arg, klen);
            key[klen] = '\0';
            value = eq + 1;
        } else {
            safe_copy(key, sizeof(key), arg);
        }

        /* Lowercase the key for case-insensitive matching. */
        for (char *p = key; *p; p++) {
            *p = (char)tolower((unsigned char)*p);
        }

        if (strcmp(key, "issuer") == 0) {
            safe_copy(s->issuer, sizeof(s->issuer), value);
        } else if (strcmp(key, "device_endpoint") == 0) {
            safe_copy(s->device_endpoint, sizeof(s->device_endpoint), value);
        } else if (strcmp(key, "token_endpoint") == 0) {
            safe_copy(s->token_endpoint, sizeof(s->token_endpoint), value);
        } else if (strcmp(key, "userinfo_endpoint") == 0) {
            safe_copy(s->userinfo_endpoint, sizeof(s->userinfo_endpoint), value);
        } else if (strcmp(key, "jwks_endpoint") == 0) {
            safe_copy(s->jwks_endpoint, sizeof(s->jwks_endpoint), value);
        } else if (strcmp(key, "introspection_endpoint") == 0) {
            safe_copy(s->introspection_endpoint, sizeof(s->introspection_endpoint), value);
        } else if (strcmp(key, "client_id") == 0) {
            safe_copy(s->client_id, sizeof(s->client_id), value);
        } else if (strcmp(key, "client_secret") == 0) {
            safe_copy(s->client_secret, sizeof(s->client_secret), value);
        } else if (strcmp(key, "scope") == 0) {
            safe_copy(s->scope, sizeof(s->scope), value);
        } else if (strcmp(key, "user_claim") == 0) {
            safe_copy(s->user_claim, sizeof(s->user_claim), value);
        } else if (strcmp(key, "timeout") == 0) {
            long sec = parse_duration(value);

            if (sec <= 0) {
                snprintf(errbuf, errlen, "invalid timeout: %s", value);

                return -1;
            }

            s->timeout_sec = sec;
        } else if (strcmp(key, "request_timeout") == 0) {
            long sec = parse_duration(value);

            if (sec <= 0) {
                snprintf(errbuf, errlen, "invalid request_timeout: %s", value);

                return -1;
            }

            s->request_timeout_sec = sec;
        } else if (strcmp(key, "allow_http") == 0) {
            s->allow_http = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "ca_file") == 0) {
            safe_copy(s->ca_file, sizeof(s->ca_file), value);
        } else if (strcmp(key, "tls_server_name") == 0) {
            safe_copy(s->tls_server_name, sizeof(s->tls_server_name), value);
        } else {
            snprintf(errbuf, errlen, "unknown option: %s", key);

            return -1;
        }
    }

    return settings_validate(s, errbuf, errlen);
}

int settings_validate(const pam_settings *s, char *errbuf, size_t errlen)
{
    if (s->client_id[0] == '\0') {
        snprintf(errbuf, errlen, "client_id is required");

        return -1;
    }

    if (s->client_secret[0] == '\0') {
        snprintf(errbuf, errlen, "client_secret is required");

        return -1;
    }

    if (s->scope[0] == '\0') {
        snprintf(errbuf, errlen, "scope must not be empty");

        return -1;
    }

    if (s->user_claim[0] == '\0') {
        snprintf(errbuf, errlen, "user_claim must not be empty");

        return -1;
    }

    if (s->timeout_sec <= 0) {
        snprintf(errbuf, errlen, "timeout must be positive");

        return -1;
    }

    if (s->request_timeout_sec <= 0) {
        snprintf(errbuf, errlen, "request_timeout must be positive");

        return -1;
    }

    /* Issuer is required when any endpoint is missing. */
    int all_endpoints = (s->device_endpoint[0] != '\0' &&
                         s->token_endpoint[0] != '\0' &&
                         s->userinfo_endpoint[0] != '\0' &&
                         s->jwks_endpoint[0] != '\0' &&
                         s->introspection_endpoint[0] != '\0');

    if (s->issuer[0] == '\0' && !all_endpoints) {
        snprintf(errbuf, errlen, "issuer is required when any endpoint is not provided");

        return -1;
    }

    if (s->issuer[0] != '\0' && !s->allow_http && !is_https(s->issuer)) {
        snprintf(errbuf, errlen, "issuer must use https unless allow_http=true");

        return -1;
    }

    if (s->ca_file[0] != '\0') {
        struct stat st;

        if (stat(s->ca_file, &st) != 0) {
            snprintf(errbuf, errlen, "ca_file not accessible: %s", s->ca_file);

            return -1;
        }
    }

    return 0;
}

int settings_resolve_endpoints(const pam_settings *s, endpoint_set *ep,
                               char *errbuf, size_t errlen)
{
    memset(ep, 0, sizeof(*ep));

    /* Copy explicit endpoints or derive from issuer. */
    if (s->device_endpoint[0] != '\0') {
        safe_copy(ep->device, sizeof(ep->device), s->device_endpoint);
    } else {
        if (join_endpoint(ep->device, sizeof(ep->device), s->issuer, "/oidc/device") != 0) {
            snprintf(errbuf, errlen, "device endpoint too long");

            return -1;
        }
    }

    if (s->token_endpoint[0] != '\0') {
        safe_copy(ep->token, sizeof(ep->token), s->token_endpoint);
    } else {
        if (join_endpoint(ep->token, sizeof(ep->token), s->issuer, "/oidc/token") != 0) {
            snprintf(errbuf, errlen, "token endpoint too long");

            return -1;
        }
    }

    if (s->userinfo_endpoint[0] != '\0') {
        safe_copy(ep->userinfo, sizeof(ep->userinfo), s->userinfo_endpoint);
    } else {
        if (join_endpoint(ep->userinfo, sizeof(ep->userinfo), s->issuer, "/oidc/userinfo") != 0) {
            snprintf(errbuf, errlen, "userinfo endpoint too long");

            return -1;
        }
    }

    if (s->jwks_endpoint[0] != '\0') {
        safe_copy(ep->jwks, sizeof(ep->jwks), s->jwks_endpoint);
    } else {
        if (join_endpoint(ep->jwks, sizeof(ep->jwks), s->issuer, "/oidc/jwks") != 0) {
            snprintf(errbuf, errlen, "jwks endpoint too long");

            return -1;
        }
    }

    if (s->introspection_endpoint[0] != '\0') {
        safe_copy(ep->introspection, sizeof(ep->introspection), s->introspection_endpoint);
    } else {
        if (join_endpoint(ep->introspection, sizeof(ep->introspection), s->issuer, "/oidc/introspect") != 0) {
            snprintf(errbuf, errlen, "introspection endpoint too long");

            return -1;
        }
    }

    /* Validate all endpoints. */
    if (validate_endpoint(ep->device, s->allow_http, errbuf, errlen) != 0) {
        return -1;
    }

    if (validate_endpoint(ep->token, s->allow_http, errbuf, errlen) != 0) {
        return -1;
    }

    if (validate_endpoint(ep->userinfo, s->allow_http, errbuf, errlen) != 0) {
        return -1;
    }

    if (validate_endpoint(ep->jwks, s->allow_http, errbuf, errlen) != 0) {
        return -1;
    }

    if (validate_endpoint(ep->introspection, s->allow_http, errbuf, errlen) != 0) {
        return -1;
    }

    return 0;
}
