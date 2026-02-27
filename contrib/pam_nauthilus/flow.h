/*
 * flow.h – RFC 8628 Device Authorization Flow.
 *
 * Coordinates the device code grant: start authorization, poll for token,
 * fetch userinfo, and verify the authenticated user claim.
 */

#ifndef PAM_NAUTHILUS_FLOW_H
#define PAM_NAUTHILUS_FLOW_H

#include "config.h"
#include "http_client.h"

/* Error codes returned by flow operations. */
#define FLOW_OK              0
#define FLOW_ERR_TIMEOUT    -1
#define FLOW_ERR_DENIED     -2
#define FLOW_ERR_MISMATCH   -3
#define FLOW_ERR_SIGNATURE  -4
#define FLOW_ERR_INACTIVE   -5
#define FLOW_ERR_INTERNAL   -6

/* device_auth holds the response from the device authorization endpoint. */
typedef struct device_auth {
    char verification_uri[CONFIG_MAX_STR];
    char verification_uri_complete[CONFIG_MAX_STR];
    char device_code[CONFIG_MAX_STR];
    char user_code[256];
    int  interval_sec;
    int  expires_in_sec;
} device_auth;

/* token_response holds the access token from the token endpoint. */
typedef struct token_response {
    char *access_token;   /* heap-allocated; caller must free */
    char  token_type[64];
    int   expires_in_sec;
} token_response;

/* device_flow coordinates the entire device authorization flow. */
typedef struct device_flow {
    http_client  *hc;
    endpoint_set  endpoints;
    char          client_id[CONFIG_MAX_STR];
    char          client_secret[CONFIG_MAX_STR];
    char          scope[CONFIG_MAX_STR];
    char          user_claim[CONFIG_MAX_STR];
    long          timeout_sec;
    long          request_timeout_sec;
} device_flow;

/*
 * device_flow_init initializes a device_flow from settings and an HTTP client.
 * Returns 0 on success, -1 on error (with errbuf filled).
 */
int device_flow_init(device_flow *df, const pam_settings *s,
                     http_client *hc, char *errbuf, size_t errlen);

/*
 * device_flow_start_auth requests a device code from the IdP.
 * Returns FLOW_OK on success, FLOW_ERR_INTERNAL on error.
 */
int device_flow_start_auth(device_flow *df, device_auth *auth,
                           char *errbuf, size_t errlen);

/*
 * device_flow_poll_token polls the token endpoint until authorization
 * completes, is denied, or times out.
 * Returns FLOW_OK on success, or a FLOW_ERR_* code.
 */
int device_flow_poll_token(device_flow *df, const char *device_code,
                           int interval_sec, int expires_in_sec,
                           token_response *tok,
                           char *errbuf, size_t errlen);

/*
 * device_flow_fetch_userinfo queries the userinfo endpoint and extracts
 * the configured user_claim value into claim_value.
 * Returns FLOW_OK on success, FLOW_ERR_INTERNAL on error.
 */
int device_flow_fetch_userinfo(device_flow *df, const char *access_token,
                               char *claim_value, size_t claim_len,
                               char *errbuf, size_t errlen);

/*
 * device_flow_verify_user compares the claim value with the PAM username
 * using constant-time comparison.
 * Returns FLOW_OK on match, FLOW_ERR_MISMATCH otherwise.
 */
int device_flow_verify_user(const char *claim_value, const char *username);

/*
 * token_response_free releases heap memory in a token_response.
 */
void token_response_free(token_response *tok);

#endif /* PAM_NAUTHILUS_FLOW_H */
