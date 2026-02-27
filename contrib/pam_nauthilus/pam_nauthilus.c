/*
 * pam_nauthilus.c – PAM module entry points for Nauthilus Device Code Flow.
 *
 * This is a pure C PAM module that authenticates users through the
 * Nauthilus IdP Device Authorization flow (RFC 8628).
 */

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "config.h"
#include "flow.h"
#include "jwks.h"

#define ERRBUF_SIZE 512

/* show_device_instruction displays the verification URL and code to the user.
 *
 * OpenSSH buffers PAM_TEXT_INFO messages and only sends them to the client
 * together with the next PAM_PROMPT_ECHO_ON/OFF message.  We therefore
 * append a dummy prompt ("Press Enter to continue...") so that the info
 * messages are actually delivered over the SSH channel.
 */
static void show_device_instruction(pam_handle_t *pamh, const device_auth *auth)
{
    const char *uri = auth->verification_uri;

    if (uri[0] == '\0') {
        uri = auth->verification_uri_complete;
    }

    if (uri[0] != '\0') {
        pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                   "Open %s to approve the login.", uri);
    }

    if (auth->user_code[0] != '\0') {
        pam_prompt(pamh, PAM_TEXT_INFO, NULL,
                   "Enter this code in the browser: %s", auth->user_code);
    }

    /*
     * Flush the buffered info messages by sending a real prompt.
     * The user just presses Enter; the response is discarded.
     */
    char *resp = NULL;

    pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &resp,
               "Press Enter after you have approved the login in the browser...");
    free(resp);
}

/* handle_flow_error maps flow error codes to PAM return codes and logs them. */
static int handle_flow_error(pam_handle_t *pamh, int flow_rc, const char *errbuf)
{
    switch (flow_rc) {
    case FLOW_ERR_TIMEOUT:
        pam_syslog(pamh, LOG_NOTICE, "pam_nauthilus authentication timed out");

        return PAM_AUTH_ERR;

    case FLOW_ERR_DENIED:
        pam_syslog(pamh, LOG_NOTICE, "pam_nauthilus authentication denied");

        return PAM_AUTH_ERR;

    case FLOW_ERR_MISMATCH:
        pam_syslog(pamh, LOG_NOTICE, "pam_nauthilus user claim mismatch");

        return PAM_AUTH_ERR;

    case FLOW_ERR_SIGNATURE:
        pam_syslog(pamh, LOG_NOTICE, "pam_nauthilus token signature invalid");

        return PAM_AUTH_ERR;

    case FLOW_ERR_INACTIVE:
        pam_syslog(pamh, LOG_NOTICE, "pam_nauthilus token not active");

        return PAM_AUTH_ERR;

    default:
        pam_syslog(pamh, LOG_ERR, "pam_nauthilus internal error: %s", errbuf);

        return PAM_SERVICE_ERR;
    }
}

/*
 * run_device_flow executes the complete device authorization flow.
 * This is the core logic extracted from pam_sm_authenticate for clarity.
 */
static int run_device_flow(pam_handle_t *pamh, const pam_settings *settings,
                           const char *username)
{
    char errbuf[ERRBUF_SIZE] = {0};
    int rc;

    /* Initialize libcurl for this thread. */
    http_client hc;

    if (http_client_init(&hc, settings) != 0) {
        pam_syslog(pamh, LOG_ERR, "pam_nauthilus: failed to init HTTP client");

        return PAM_SERVICE_ERR;
    }

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: HTTP client initialized");

    /* Initialize the device flow. */
    device_flow df;

    rc = device_flow_init(&df, settings, &hc, errbuf, sizeof(errbuf));

    if (rc != 0) {
        pam_syslog(pamh, LOG_ERR, "pam_nauthilus flow init error: %s", errbuf);
        http_client_cleanup(&hc);

        return PAM_SERVICE_ERR;
    }

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: device flow initialized, endpoints ready");

    /* Step 1: Start device authorization. */
    device_auth auth;

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: calling device_flow_start_auth (POST to device endpoint)");

    rc = device_flow_start_auth(&df, &auth, errbuf, sizeof(errbuf));

    if (rc != FLOW_OK) {
        pam_syslog(pamh, LOG_ERR, "pam_nauthilus device authorization failed: %s", errbuf);
        http_client_cleanup(&hc);

        return PAM_AUTH_ERR;
    }

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: device auth OK, showing instruction to user");

    /* Step 2: Show verification URL and code to the user. */
    show_device_instruction(pamh, &auth);

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: instruction shown, starting token poll");

    /* Step 3: Poll for token. */
    token_response tok;

    rc = device_flow_poll_token(&df, auth.device_code, auth.interval_sec,
                                auth.expires_in_sec, &tok, errbuf, sizeof(errbuf));

    if (rc != FLOW_OK) {
        int pam_rc = handle_flow_error(pamh, rc, errbuf);

        http_client_cleanup(&hc);

        return pam_rc;
    }

    /* Step 4: Verify JWT signature via JWKS (only for JWT tokens). */
    if (strchr(tok.access_token, '.') != NULL) {
        rc = device_flow_verify_signature(&df, tok.access_token, errbuf, sizeof(errbuf));

        if (rc != FLOW_OK) {
            pam_syslog(pamh, LOG_ERR, "pam_nauthilus JWKS signature verification failed");
            int pam_rc = handle_flow_error(pamh, rc, errbuf);

            token_response_free(&tok);
            http_client_cleanup(&hc);

            return pam_rc;
        }≤
    } else {
        pam_syslog(pamh, LOG_DEBUG,
                   "pam_nauthilus: opaque access token, skipping JWKS verification");
    }

    /* Step 5: Introspect token. */
    rc = device_flow_introspect_token(&df, tok.access_token, errbuf, sizeof(errbuf));

    if (rc != FLOW_OK) {
        pam_syslog(pamh, LOG_ERR, "pam_nauthilus token introspection failed");
        int pam_rc = handle_flow_error(pamh, rc, errbuf);

        token_response_free(&tok);
        http_client_cleanup(&hc);

        return pam_rc;
    }

    /* Step 6: Fetch userinfo and verify user claim. */
    char claim_value[CONFIG_MAX_STR] = {0};

    rc = device_flow_fetch_userinfo(&df, tok.access_token,
                                    claim_value, sizeof(claim_value),
                                    errbuf, sizeof(errbuf));

    if (rc != FLOW_OK) {
        pam_syslog(pamh, LOG_ERR, "pam_nauthilus userinfo failed: %s", errbuf);
        token_response_free(&tok);
        http_client_cleanup(&hc);

        return PAM_AUTH_ERR;
    }

    token_response_free(&tok);

    /* Step 7: Verify user claim matches PAM username. */
    if (device_flow_verify_user(claim_value, username) != 0) {
        pam_syslog(pamh, LOG_NOTICE, "pam_nauthilus user claim mismatch");
        http_client_cleanup(&hc);

        return PAM_AUTH_ERR;
    }

    http_client_cleanup(&hc);

    return PAM_SUCCESS;
}

/* pam_sm_authenticate is the PAM authentication entry point. */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    (void)flags;

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: pam_sm_authenticate entered");

    /*
     * Prevent libcurl from initializing OpenSSL globals.  OpenSSH already
     * initializes OpenSSL in the parent process before forking the
     * privilege-separation child that loads this PAM module.  Letting
     * libcurl call OPENSSL_init_ssl() again inside the forked child can
     * deadlock or corrupt state.  CURL_GLOBAL_NOTHING skips all
     * sub-library initialization while still allowing curl_easy_init().
     */
    curl_global_init(CURL_GLOBAL_NOTHING);

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: curl_global_init done");

    char errbuf[ERRBUF_SIZE] = {0};

    /* Parse and validate configuration. */
    pam_settings settings;

    settings_init(&settings);

    if (settings_parse(&settings, argc, argv, errbuf, sizeof(errbuf)) != 0) {
        pam_syslog(pamh, LOG_ERR, "pam_nauthilus config error: %s", errbuf);

        return PAM_SERVICE_ERR;
    }

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: settings parsed OK");

    /* Get the PAM username. */
    const char *username = NULL;

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL) {
        pam_syslog(pamh, LOG_ERR, "pam_nauthilus: failed to get username");

        return PAM_SERVICE_ERR;
    }

    pam_syslog(pamh, LOG_DEBUG, "pam_nauthilus: username=%s, starting device flow", username);

    return run_device_flow(pamh, &settings, username);
}

/* pam_sm_setcred is a no-op credential handler required by the PAM API. */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;

    return PAM_SUCCESS;
}
