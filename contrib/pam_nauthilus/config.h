/*
 * config.h – PAM module configuration parsing.
 *
 * Parses PAM arguments into a settings structure and resolves IdP endpoints.
 */

#ifndef PAM_NAUTHILUS_CONFIG_H
#define PAM_NAUTHILUS_CONFIG_H

#include <stdbool.h>
#include <time.h>

/* Default values. */
#define DEFAULT_SCOPE          "openid"
#define DEFAULT_USER_CLAIM     "preferred_username"
#define DEFAULT_TIMEOUT_SEC    300   /* 5 minutes */
#define DEFAULT_REQ_TIMEOUT_SEC 10   /* 10 seconds */

/* Maximum length for string configuration values. */
#define CONFIG_MAX_STR 1024

/*
 * pam_settings holds all configuration options parsed from PAM arguments.
 *
 * Pointer fields are grouped first for GC-friendliness (not relevant in C,
 * but keeps the struct tidy). Scalar fields follow, largest to smallest.
 */
typedef struct pam_settings {
    char issuer[CONFIG_MAX_STR];
    char device_endpoint[CONFIG_MAX_STR];
    char token_endpoint[CONFIG_MAX_STR];
    char userinfo_endpoint[CONFIG_MAX_STR];
    char jwks_endpoint[CONFIG_MAX_STR];
    char introspection_endpoint[CONFIG_MAX_STR];
    char client_id[CONFIG_MAX_STR];
    char client_secret[CONFIG_MAX_STR];
    char scope[CONFIG_MAX_STR];
    char user_claim[CONFIG_MAX_STR];
    char ca_file[CONFIG_MAX_STR];
    char tls_server_name[CONFIG_MAX_STR];
    long timeout_sec;
    long request_timeout_sec;
    bool allow_http;
} pam_settings;

/*
 * endpoint_set holds the resolved IdP endpoint URLs.
 */
typedef struct endpoint_set {
    char device[CONFIG_MAX_STR];
    char token[CONFIG_MAX_STR];
    char userinfo[CONFIG_MAX_STR];
    char jwks[CONFIG_MAX_STR];
    char introspection[CONFIG_MAX_STR];
} endpoint_set;

/*
 * settings_init initializes a pam_settings structure with default values.
 */
void settings_init(pam_settings *s);

/*
 * settings_parse parses PAM module arguments into the settings structure.
 * Returns 0 on success, -1 on error (with errbuf filled).
 */
int settings_parse(pam_settings *s, int argc, const char **argv,
                   char *errbuf, size_t errlen);

/*
 * settings_validate checks that required fields are present and consistent.
 * Returns 0 on success, -1 on error (with errbuf filled).
 */
int settings_validate(const pam_settings *s, char *errbuf, size_t errlen);

/*
 * settings_resolve_endpoints builds the endpoint_set from settings.
 * Returns 0 on success, -1 on error (with errbuf filled).
 */
int settings_resolve_endpoints(const pam_settings *s, endpoint_set *ep,
                               char *errbuf, size_t errlen);

/*
 * parse_duration parses a duration string (Go-style "5m", "10s", "300")
 * into seconds. Returns the number of seconds, or -1 on error.
 */
long parse_duration(const char *value);

#endif /* PAM_NAUTHILUS_CONFIG_H */
