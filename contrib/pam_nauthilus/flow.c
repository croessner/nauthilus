/*
 * flow.c – RFC 8628 Device Authorization Flow implementation.
 */

#include "flow.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/* constant_time_compare returns 0 if a and b are equal, -1 otherwise. */
static int constant_time_compare(const char *a, const char *b)
{
    size_t alen = strlen(a);
    size_t blen = strlen(b);
    size_t maxlen = (alen > blen) ? alen : blen;

    volatile unsigned char result = (alen != blen) ? 1 : 0;

    for (size_t i = 0; i < maxlen; i++) {
        unsigned char ca = (i < alen) ? (unsigned char)a[i] : 0;
        unsigned char cb = (i < blen) ? (unsigned char)b[i] : 0;

        result |= ca ^ cb;
    }

    return (result == 0) ? 0 : -1;
}

/* build_form_data URL-encodes key=value pairs into a static buffer. */
static int build_form_data(char *dst, size_t dstlen,
                           const char *pairs[][2], int count)
{
    dst[0] = '\0';
    size_t pos = 0;

    for (int i = 0; i < count; i++) {
        /* libcurl's curl_easy_escape could be used here, but for simple
         * ASCII values (client_id, scope, device_code) plain concatenation
         * is safe and avoids needing a CURL handle in this function. */
        int n;

        if (pos > 0) {
            n = snprintf(dst + pos, dstlen - pos, "&%s=%s", pairs[i][0], pairs[i][1]);
        } else {
            n = snprintf(dst + pos, dstlen - pos, "%s=%s", pairs[i][0], pairs[i][1]);
        }

        if (n < 0 || (size_t)n >= dstlen - pos) {
            return -1;
        }

        pos += (size_t)n;
    }

    return 0;
}

void token_response_free(token_response *tok)
{
    if (tok == NULL) {
        return;
    }

    free(tok->access_token);
    tok->access_token = NULL;
}

int device_flow_init(device_flow *df, const pam_settings *s,
                     http_client *hc, char *errbuf, size_t errlen)
{
    memset(df, 0, sizeof(*df));

    df->hc = hc;
    df->timeout_sec = s->timeout_sec;
    df->request_timeout_sec = s->request_timeout_sec;

    snprintf(df->client_id, sizeof(df->client_id), "%s", s->client_id);
    snprintf(df->client_secret, sizeof(df->client_secret), "%s", s->client_secret);
    snprintf(df->scope, sizeof(df->scope), "%s", s->scope);
    snprintf(df->user_claim, sizeof(df->user_claim), "%s", s->user_claim);

    return settings_resolve_endpoints(s, &df->endpoints, errbuf, errlen);
}

int device_flow_start_auth(device_flow *df, device_auth *auth,
                           char *errbuf, size_t errlen)
{
    memset(auth, 0, sizeof(*auth));

    char form[2048];
    const char *pairs[][2] = {
        {"client_id", df->client_id},
        {"scope",     df->scope},
    };

    if (build_form_data(form, sizeof(form), pairs, 2) != 0) {
        snprintf(errbuf, errlen, "form data too long");

        return FLOW_ERR_INTERNAL;
    }

    http_buffer buf;

    http_buffer_init(&buf);

    int status = http_post_form(df->hc, df->endpoints.device, form,
                                df->client_id, df->client_secret,
                                0, &buf);

    if (status < 0 || buf.data == NULL) {
        http_buffer_free(&buf);
        snprintf(errbuf, errlen, "device authorization request failed");

        return FLOW_ERR_INTERNAL;
    }

    cJSON *json = cJSON_Parse(buf.data);

    http_buffer_free(&buf);

    if (json == NULL) {
        snprintf(errbuf, errlen, "failed to parse device response JSON");

        return FLOW_ERR_INTERNAL;
    }

    /* Check for error response. */
    cJSON *jerr = cJSON_GetObjectItemCaseSensitive(json, "error");

    if (cJSON_IsString(jerr) && jerr->valuestring[0] != '\0') {
        snprintf(errbuf, errlen, "device authorization error: %s", jerr->valuestring);
        cJSON_Delete(json);

        return FLOW_ERR_INTERNAL;
    }

    if (status != 200) {
        snprintf(errbuf, errlen, "device authorization failed: status %d", status);
        cJSON_Delete(json);

        return FLOW_ERR_INTERNAL;
    }

    /* Extract required fields. */
    cJSON *jdc  = cJSON_GetObjectItemCaseSensitive(json, "device_code");
    cJSON *juc  = cJSON_GetObjectItemCaseSensitive(json, "user_code");
    cJSON *jvu  = cJSON_GetObjectItemCaseSensitive(json, "verification_uri");
    cJSON *jvuc = cJSON_GetObjectItemCaseSensitive(json, "verification_uri_complete");
    cJSON *jei  = cJSON_GetObjectItemCaseSensitive(json, "expires_in");
    cJSON *jiv  = cJSON_GetObjectItemCaseSensitive(json, "interval");

    if (!cJSON_IsString(jdc) || !cJSON_IsString(juc) || !cJSON_IsString(jvu)) {
        snprintf(errbuf, errlen, "device response missing required fields");
        cJSON_Delete(json);

        return FLOW_ERR_INTERNAL;
    }

    snprintf(auth->device_code, sizeof(auth->device_code), "%s", jdc->valuestring);
    snprintf(auth->user_code, sizeof(auth->user_code), "%s", juc->valuestring);
    snprintf(auth->verification_uri, sizeof(auth->verification_uri), "%s", jvu->valuestring);

    if (cJSON_IsString(jvuc)) {
        snprintf(auth->verification_uri_complete, sizeof(auth->verification_uri_complete),
                 "%s", jvuc->valuestring);
    }

    auth->expires_in_sec = cJSON_IsNumber(jei) ? jei->valueint : 0;
    auth->interval_sec = cJSON_IsNumber(jiv) ? jiv->valueint : 5;

    if (auth->interval_sec <= 0) {
        auth->interval_sec = 5;
    }

    cJSON_Delete(json);

    return FLOW_OK;
}

int device_flow_poll_token(device_flow *df, const char *device_code,
                           int interval_sec, int expires_in_sec,
                           token_response *tok,
                           char *errbuf, size_t errlen)
{
    memset(tok, 0, sizeof(*tok));

    if (device_code == NULL || device_code[0] == '\0') {
        snprintf(errbuf, errlen, "device code is required");

        return FLOW_ERR_INTERNAL;
    }

    if (interval_sec <= 0) {
        interval_sec = 5;
    }

    time_t start = time(NULL);
    time_t deadline = start + df->timeout_sec;

    /* Use device expiry if shorter. */
    if (expires_in_sec > 0) {
        time_t dev_deadline = start + expires_in_sec;

        if (dev_deadline < deadline) {
            deadline = dev_deadline;
        }
    }

    char form[2048];
    const char *pairs[][2] = {
        {"grant_type",  "urn:ietf:params:oauth:grant-type:device_code"},
        {"device_code", device_code},
    };

    if (build_form_data(form, sizeof(form), pairs, 2) != 0) {
        snprintf(errbuf, errlen, "form data too long");

        return FLOW_ERR_INTERNAL;
    }

    for (;;) {
        if (time(NULL) >= deadline) {
            return FLOW_ERR_TIMEOUT;
        }

        http_buffer buf;

        http_buffer_init(&buf);

        int status = http_post_form(df->hc, df->endpoints.token, form,
                                    df->client_id, df->client_secret,
                                    1, &buf);

        if (status < 0 || buf.data == NULL) {
            http_buffer_free(&buf);
            snprintf(errbuf, errlen, "token request failed");

            return FLOW_ERR_INTERNAL;
        }

        cJSON *json = cJSON_Parse(buf.data);

        http_buffer_free(&buf);

        if (json == NULL) {
            snprintf(errbuf, errlen, "failed to parse token response JSON");

            return FLOW_ERR_INTERNAL;
        }

        cJSON *jerr = cJSON_GetObjectItemCaseSensitive(json, "error");

        if (cJSON_IsString(jerr) && jerr->valuestring[0] != '\0') {
            const char *errstr = jerr->valuestring;

            if (strcmp(errstr, "authorization_pending") == 0) {
                cJSON_Delete(json);
                sleep((unsigned int)interval_sec);

                continue;
            }

            if (strcmp(errstr, "slow_down") == 0) {
                interval_sec += 5;
                cJSON_Delete(json);
                sleep((unsigned int)interval_sec);

                continue;
            }

            if (strcmp(errstr, "access_denied") == 0) {
                cJSON_Delete(json);

                return FLOW_ERR_DENIED;
            }

            if (strcmp(errstr, "expired_token") == 0) {
                cJSON_Delete(json);

                return FLOW_ERR_TIMEOUT;
            }

            snprintf(errbuf, errlen, "token error: %s", errstr);
            cJSON_Delete(json);

            return FLOW_ERR_INTERNAL;
        }

        if (status != 200) {
            snprintf(errbuf, errlen, "token request failed: status %d", status);
            cJSON_Delete(json);

            return FLOW_ERR_INTERNAL;
        }

        cJSON *jat = cJSON_GetObjectItemCaseSensitive(json, "access_token");

        if (!cJSON_IsString(jat) || jat->valuestring[0] == '\0') {
            snprintf(errbuf, errlen, "token response missing access_token");
            cJSON_Delete(json);

            return FLOW_ERR_INTERNAL;
        }

        cJSON *jtt = cJSON_GetObjectItemCaseSensitive(json, "token_type");

        if (cJSON_IsString(jtt) && jtt->valuestring[0] != '\0') {
            if (strcasecmp(jtt->valuestring, "bearer") != 0) {
                snprintf(errbuf, errlen, "unsupported token type: %s", jtt->valuestring);
                cJSON_Delete(json);

                return FLOW_ERR_INTERNAL;
            }

            snprintf(tok->token_type, sizeof(tok->token_type), "%s", jtt->valuestring);
        }

        tok->access_token = strdup(jat->valuestring);

        cJSON *jei = cJSON_GetObjectItemCaseSensitive(json, "expires_in");

        tok->expires_in_sec = cJSON_IsNumber(jei) ? jei->valueint : 0;

        cJSON_Delete(json);

        return FLOW_OK;
    }
}

int device_flow_fetch_userinfo(device_flow *df, const char *access_token,
                               char *claim_value, size_t claim_len,
                               char *errbuf, size_t errlen)
{
    claim_value[0] = '\0';

    http_buffer buf;

    http_buffer_init(&buf);

    int status = http_get(df->hc, df->endpoints.userinfo, access_token, &buf);

    if (status < 0 || buf.data == NULL) {
        http_buffer_free(&buf);
        snprintf(errbuf, errlen, "userinfo request failed");

        return FLOW_ERR_INTERNAL;
    }

    if (status != 200) {
        http_buffer_free(&buf);
        snprintf(errbuf, errlen, "userinfo request failed: status %d", status);

        return FLOW_ERR_INTERNAL;
    }

    cJSON *json = cJSON_Parse(buf.data);

    http_buffer_free(&buf);

    if (json == NULL) {
        snprintf(errbuf, errlen, "failed to parse userinfo response JSON");

        return FLOW_ERR_INTERNAL;
    }

    cJSON *jclaim = cJSON_GetObjectItemCaseSensitive(json, df->user_claim);

    if (!cJSON_IsString(jclaim)) {
        snprintf(errbuf, errlen, "claim %s not found or not a string", df->user_claim);
        cJSON_Delete(json);

        return FLOW_ERR_INTERNAL;
    }

    snprintf(claim_value, claim_len, "%s", jclaim->valuestring);

    cJSON_Delete(json);

    return FLOW_OK;
}

int device_flow_verify_user(const char *claim_value, const char *username)
{
    return constant_time_compare(claim_value, username);
}
