/*
 * http_client.h – HTTP client abstraction using libcurl.
 *
 * Provides a thin wrapper around CURL for form-encoded POST and GET requests
 * with Basic Auth, TLS configuration, and response buffering.
 */

#ifndef PAM_NAUTHILUS_HTTP_CLIENT_H
#define PAM_NAUTHILUS_HTTP_CLIENT_H

#include <curl/curl.h>
#include <stddef.h>

#include "config.h"

/* Dynamic buffer for HTTP response bodies. */
typedef struct http_buffer {
    char  *data;
    size_t size;
    size_t capacity;
} http_buffer;

/* http_client wraps a CURL handle with module-specific defaults. */
typedef struct http_client {
    CURL *curl;
    char  ca_file[CONFIG_MAX_STR];
    char  tls_server_name[CONFIG_MAX_STR];
    long  request_timeout_sec;
} http_client;

/*
 * http_client_init creates and configures a new HTTP client.
 * Returns 0 on success, -1 on error.
 */
int http_client_init(http_client *hc, const pam_settings *s);

/*
 * http_client_cleanup releases all resources held by the HTTP client.
 */
void http_client_cleanup(http_client *hc);

/*
 * http_post_form sends a POST request with form-encoded body.
 * If use_basic_auth is true, client_id/client_secret are sent as Basic Auth.
 * The response body is written into buf (caller must free buf->data).
 * Returns the HTTP status code, or -1 on error.
 */
int http_post_form(http_client *hc, const char *url,
                   const char *form_data,
                   const char *client_id, const char *client_secret,
                   int use_basic_auth,
                   http_buffer *buf);

/*
 * http_get sends a GET request with an optional Bearer token.
 * The response body is written into buf (caller must free buf->data).
 * Returns the HTTP status code, or -1 on error.
 */
int http_get(http_client *hc, const char *url,
             const char *bearer_token,
             http_buffer *buf);

/*
 * http_buffer_init initializes a response buffer.
 */
void http_buffer_init(http_buffer *buf);

/*
 * http_buffer_free releases the buffer memory.
 */
void http_buffer_free(http_buffer *buf);

#endif /* PAM_NAUTHILUS_HTTP_CLIENT_H */
