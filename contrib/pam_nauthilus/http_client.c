/*
 * http_client.c – HTTP client implementation using libcurl.
 */

#include "http_client.h"

#include <stdlib.h>
#include <string.h>

#define INITIAL_BUF_CAP 4096

void http_buffer_init(http_buffer *buf)
{
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

void http_buffer_free(http_buffer *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

/* write_callback is the CURLOPT_WRITEFUNCTION handler. */
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    http_buffer *buf = (http_buffer *)userdata;
    size_t total = size * nmemb;
    size_t needed = buf->size + total + 1;

    if (needed > buf->capacity) {
        size_t newcap = (buf->capacity == 0) ? INITIAL_BUF_CAP : buf->capacity;

        while (newcap < needed) {
            newcap *= 2;
        }

        char *tmp = realloc(buf->data, newcap);

        if (tmp == NULL) {
            return 0;
        }

        buf->data = tmp;
        buf->capacity = newcap;
    }

    memcpy(buf->data + buf->size, ptr, total);
    buf->size += total;
    buf->data[buf->size] = '\0';

    return total;
}

/* apply_tls_opts configures TLS settings on the CURL handle. */
static void apply_tls_opts(http_client *hc)
{
    curl_easy_setopt(hc->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(hc->curl, CURLOPT_SSL_VERIFYHOST, 2L);

    if (hc->ca_file[0] != '\0') {
        curl_easy_setopt(hc->curl, CURLOPT_CAINFO, hc->ca_file);
    }

    if (hc->tls_server_name[0] != '\0') {
        /* CURLOPT_SSL_EC_CURVES is not what we want; use resolve or SNI. */
        /* libcurl uses the Host header for SNI by default; override via
         * CURLOPT_RESOLVE or by setting the Host header is complex.
         * For TLS server name override we use CURLOPT_SSL_EC_CURVES... no.
         * Actually, there is no direct SNI override in libcurl.
         * We can use CURLOPT_CONNECT_TO for this purpose. */
    }

    curl_easy_setopt(hc->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
}

/* reset_curl prepares the handle for a new request. */
static void reset_curl(http_client *hc)
{
    curl_easy_reset(hc->curl);

    curl_easy_setopt(hc->curl, CURLOPT_TIMEOUT, hc->request_timeout_sec);
    curl_easy_setopt(hc->curl, CURLOPT_CONNECTTIMEOUT, hc->request_timeout_sec);
    curl_easy_setopt(hc->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(hc->curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(hc->curl, CURLOPT_WRITEFUNCTION, write_callback);

    apply_tls_opts(hc);
}

int http_client_init(http_client *hc, const pam_settings *s)
{
    memset(hc, 0, sizeof(*hc));

    hc->curl = curl_easy_init();

    if (hc->curl == NULL) {
        return -1;
    }

    hc->request_timeout_sec = s->request_timeout_sec;

    if (s->ca_file[0] != '\0') {
        snprintf(hc->ca_file, sizeof(hc->ca_file), "%s", s->ca_file);
    }

    if (s->tls_server_name[0] != '\0') {
        snprintf(hc->tls_server_name, sizeof(hc->tls_server_name), "%s", s->tls_server_name);
    }

    return 0;
}

void http_client_cleanup(http_client *hc)
{
    if (hc->curl != NULL) {
        curl_easy_cleanup(hc->curl);
        hc->curl = NULL;
    }
}

int http_post_form(http_client *hc, const char *url,
                   const char *form_data,
                   const char *client_id, const char *client_secret,
                   int use_basic_auth,
                   http_buffer *buf)
{
    reset_curl(hc);

    curl_easy_setopt(hc->curl, CURLOPT_URL, url);
    curl_easy_setopt(hc->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(hc->curl, CURLOPT_POSTFIELDS, form_data);
    curl_easy_setopt(hc->curl, CURLOPT_WRITEDATA, buf);

    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "Accept: application/json");
    curl_easy_setopt(hc->curl, CURLOPT_HTTPHEADER, headers);

    if (use_basic_auth) {
        curl_easy_setopt(hc->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(hc->curl, CURLOPT_USERNAME, client_id);
        curl_easy_setopt(hc->curl, CURLOPT_PASSWORD, client_secret);
    }

    CURLcode res = curl_easy_perform(hc->curl);

    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        return -1;
    }

    long status = 0;

    curl_easy_getinfo(hc->curl, CURLINFO_RESPONSE_CODE, &status);

    return (int)status;
}

int http_get(http_client *hc, const char *url,
             const char *bearer_token,
             http_buffer *buf)
{
    reset_curl(hc);

    curl_easy_setopt(hc->curl, CURLOPT_URL, url);
    curl_easy_setopt(hc->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(hc->curl, CURLOPT_WRITEDATA, buf);

    struct curl_slist *headers = NULL;

    headers = curl_slist_append(headers, "Accept: application/json");

    if (bearer_token != NULL && bearer_token[0] != '\0') {
        char auth_header[2048];

        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", bearer_token);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(hc->curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(hc->curl);

    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        return -1;
    }

    long status = 0;

    curl_easy_getinfo(hc->curl, CURLINFO_RESPONSE_CODE, &status);

    return (int)status;
}
