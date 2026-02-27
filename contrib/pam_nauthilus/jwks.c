/*
 * jwks.c – JWKS fetching and JWT RS256 signature verification using OpenSSL.
 */

#include "jwks.h"

#include <cjson/cJSON.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#else
#include <openssl/rsa.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * base64url_decode decodes a base64url-encoded string (no padding) into
 * a newly allocated buffer. Sets *out_len to the decoded length.
 * Returns the buffer on success, NULL on failure. Caller must free().
 */
static unsigned char *base64url_decode(const char *input, size_t *out_len)
{
    if (input == NULL) {
        return NULL;
    }

    size_t inlen = strlen(input);

    /* Convert base64url to standard base64: replace - with +, _ with /. */
    char *b64 = malloc(inlen + 4);  /* room for padding */

    if (b64 == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < inlen; i++) {
        switch (input[i]) {
        case '-':
            b64[i] = '+';
            break;
        case '_':
            b64[i] = '/';
            break;
        default:
            b64[i] = input[i];
            break;
        }
    }

    /* Add padding. */
    size_t padded = inlen;

    while (padded % 4 != 0) {
        b64[padded++] = '=';
    }

    b64[padded] = '\0';

    /* Decode using OpenSSL EVP. */
    size_t maxout = (padded / 4) * 3;
    unsigned char *out = malloc(maxout + 1);

    if (out == NULL) {
        free(b64);

        return NULL;
    }

    int decoded = EVP_DecodeBlock(out, (const unsigned char *)b64, (int)padded);

    free(b64);

    if (decoded < 0) {
        free(out);

        return NULL;
    }

    /* EVP_DecodeBlock includes padding bytes in the count; subtract them. */
    size_t actual = (size_t)decoded;

    if (padded > inlen) {
        actual -= (padded - inlen);
    }

    *out_len = actual;

    return out;
}

/*
 * parse_jwt_header extracts the "alg" and "kid" fields from the JWT header.
 * header_b64 is the first segment of the JWT (before the first dot).
 */
static int parse_jwt_header(const char *header_b64,
                            char *alg, size_t alg_len,
                            char *kid, size_t kid_len)
{
    size_t decoded_len = 0;
    unsigned char *decoded = base64url_decode(header_b64, &decoded_len);

    if (decoded == NULL) {
        return -1;
    }

    cJSON *json = cJSON_ParseWithLength((const char *)decoded, decoded_len);

    free(decoded);

    if (json == NULL) {
        return -1;
    }

    cJSON *jalg = cJSON_GetObjectItemCaseSensitive(json, "alg");
    cJSON *jkid = cJSON_GetObjectItemCaseSensitive(json, "kid");

    if (cJSON_IsString(jalg)) {
        snprintf(alg, alg_len, "%s", jalg->valuestring);
    }

    if (cJSON_IsString(jkid)) {
        snprintf(kid, kid_len, "%s", jkid->valuestring);
    }

    cJSON_Delete(json);

    return 0;
}

/*
 * find_signing_key locates the JWK matching kid (or the first "sig" key
 * if kid is empty) in the JWKS JSON array.
 * Returns the matching cJSON key object (not a copy; owned by keys_array).
 */
static cJSON *find_signing_key(cJSON *keys_array, const char *kid)
{
    cJSON *key = NULL;
    cJSON *fallback = NULL;

    cJSON_ArrayForEach(key, keys_array) {
        cJSON *juse = cJSON_GetObjectItemCaseSensitive(key, "use");
        cJSON *jkid = cJSON_GetObjectItemCaseSensitive(key, "kid");

        int is_sig = (cJSON_IsString(juse) && strcmp(juse->valuestring, "sig") == 0);

        if (!is_sig) {
            continue;
        }

        if (kid[0] != '\0' && cJSON_IsString(jkid) &&
            strcmp(jkid->valuestring, kid) == 0) {
            return key;
        }

        if (fallback == NULL) {
            fallback = key;
        }
    }

    /* If no kid match, return the first signing key as fallback. */
    if (kid[0] == '\0') {
        return fallback;
    }

    return NULL;
}

/*
 * build_rsa_pkey constructs an EVP_PKEY from the JWK "n" and "e" values.
 * On OpenSSL 3.0+ it uses EVP_PKEY_fromdata; on OpenSSL 1.1.x it falls
 * back to RSA_new + RSA_set0_key + EVP_PKEY_assign_RSA.
 * Caller must free the returned key with EVP_PKEY_free().
 */

/* Shared helper: decode n and e, convert to BIGNUMs. */
static int decode_rsa_components(const char *n_b64, const char *e_b64,
                                 BIGNUM **bn_n, BIGNUM **bn_e)
{
    size_t n_len = 0, e_len = 0;
    unsigned char *n_bytes = base64url_decode(n_b64, &n_len);
    unsigned char *e_bytes = base64url_decode(e_b64, &e_len);

    if (n_bytes == NULL || e_bytes == NULL) {
        free(n_bytes);
        free(e_bytes);

        return -1;
    }

    *bn_n = BN_bin2bn(n_bytes, (int)n_len, NULL);
    *bn_e = BN_bin2bn(e_bytes, (int)e_len, NULL);

    free(n_bytes);
    free(e_bytes);

    if (*bn_n == NULL || *bn_e == NULL) {
        BN_free(*bn_n);
        BN_free(*bn_e);

        return -1;
    }

    return 0;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

static EVP_PKEY *build_rsa_pkey(const char *n_b64, const char *e_b64)
{
    BIGNUM *bn_n = NULL, *bn_e = NULL;

    if (decode_rsa_components(n_b64, e_b64, &bn_n, &bn_e) != 0) {
        return NULL;
    }

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();

    if (bld == NULL) {
        BN_free(bn_n);
        BN_free(bn_e);

        return NULL;
    }

    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e);

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

    OSSL_PARAM_BLD_free(bld);
    BN_free(bn_n);
    BN_free(bn_e);

    if (params == NULL) {
        return NULL;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

    if (ctx == NULL) {
        OSSL_PARAM_free(params);

        return NULL;
    }

    EVP_PKEY *pkey = NULL;

    if (EVP_PKEY_fromdata_init(ctx) != 1 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_CTX_free(ctx);
        OSSL_PARAM_free(params);

        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);

    return pkey;
}

#else /* OpenSSL 1.1.x */

static EVP_PKEY *build_rsa_pkey(const char *n_b64, const char *e_b64)
{
    BIGNUM *bn_n = NULL, *bn_e = NULL;

    if (decode_rsa_components(n_b64, e_b64, &bn_n, &bn_e) != 0) {
        return NULL;
    }

    RSA *rsa = RSA_new();

    if (rsa == NULL) {
        BN_free(bn_n);
        BN_free(bn_e);

        return NULL;
    }

    /* RSA_set0_key takes ownership of the BIGNUMs on success. */
    if (RSA_set0_key(rsa, bn_n, bn_e, NULL) != 1) {
        RSA_free(rsa);

        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();

    if (pkey == NULL) {
        RSA_free(rsa);

        return NULL;
    }

    /* EVP_PKEY_assign_RSA takes ownership of rsa on success. */
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);

        return NULL;
    }

    return pkey;
}

#endif /* OPENSSL_VERSION_NUMBER */

/*
 * verify_rs256 verifies an RS256 signature over signing_input using pkey.
 * Returns 0 on success, -1 on failure.
 */
static int verify_rs256(EVP_PKEY *pkey,
                        const char *signing_input, size_t input_len,
                        const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        return -1;
    }

    int rc = -1;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(ctx, signing_input, input_len) != 1) {
        goto cleanup;
    }

    if (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
        rc = 0;
    }

cleanup:
    EVP_MD_CTX_free(ctx);

    return rc;
}

int device_flow_verify_signature(device_flow *df, const char *access_token,
                                 char *errbuf, size_t errlen)
{
    if (access_token == NULL || access_token[0] == '\0') {
        snprintf(errbuf, errlen, "access token is empty");

        return FLOW_ERR_INTERNAL;
    }

    /* Split JWT into header.payload.signature. */
    const char *dot1 = strchr(access_token, '.');

    if (dot1 == NULL) {
        snprintf(errbuf, errlen, "invalid JWT format: no dots");

        return FLOW_ERR_INTERNAL;
    }

    const char *dot2 = strchr(dot1 + 1, '.');

    if (dot2 == NULL) {
        snprintf(errbuf, errlen, "invalid JWT format: expected three parts");

        return FLOW_ERR_INTERNAL;
    }

    /* Extract header segment. */
    size_t hdr_len = (size_t)(dot1 - access_token);
    char *header_b64 = malloc(hdr_len + 1);

    if (header_b64 == NULL) {
        snprintf(errbuf, errlen, "out of memory");

        return FLOW_ERR_INTERNAL;
    }

    memcpy(header_b64, access_token, hdr_len);
    header_b64[hdr_len] = '\0';

    char alg[32] = {0};
    char kid[256] = {0};

    if (parse_jwt_header(header_b64, alg, sizeof(alg), kid, sizeof(kid)) != 0) {
        free(header_b64);
        snprintf(errbuf, errlen, "failed to parse JWT header");

        return FLOW_ERR_INTERNAL;
    }

    free(header_b64);

    if (strcmp(alg, "RS256") != 0) {
        snprintf(errbuf, errlen, "unsupported signing algorithm: %s", alg);

        return FLOW_ERR_INTERNAL;
    }

    /* Fetch JWKS. */
    http_buffer buf;

    http_buffer_init(&buf);

    int status = http_get(df->hc, df->endpoints.jwks, NULL, &buf);

    if (status < 0 || buf.data == NULL) {
        http_buffer_free(&buf);
        snprintf(errbuf, errlen, "JWKS request failed");

        return FLOW_ERR_INTERNAL;
    }

    if (status != 200) {
        http_buffer_free(&buf);
        snprintf(errbuf, errlen, "JWKS request failed: status %d", status);

        return FLOW_ERR_INTERNAL;
    }

    cJSON *jwks_json = cJSON_Parse(buf.data);

    http_buffer_free(&buf);

    if (jwks_json == NULL) {
        snprintf(errbuf, errlen, "failed to parse JWKS JSON");

        return FLOW_ERR_INTERNAL;
    }

    cJSON *keys_array = cJSON_GetObjectItemCaseSensitive(jwks_json, "keys");

    if (!cJSON_IsArray(keys_array)) {
        cJSON_Delete(jwks_json);
        snprintf(errbuf, errlen, "JWKS response missing keys array");

        return FLOW_ERR_INTERNAL;
    }

    cJSON *jwk = find_signing_key(keys_array, kid);

    if (jwk == NULL) {
        cJSON_Delete(jwks_json);
        snprintf(errbuf, errlen, "no matching signing key found for kid \"%s\"", kid);

        return FLOW_ERR_INTERNAL;
    }

    /* Verify key type. */
    cJSON *jkty = cJSON_GetObjectItemCaseSensitive(jwk, "kty");

    if (!cJSON_IsString(jkty) || strcmp(jkty->valuestring, "RSA") != 0) {
        cJSON_Delete(jwks_json);
        snprintf(errbuf, errlen, "unsupported key type");

        return FLOW_ERR_INTERNAL;
    }

    cJSON *jn = cJSON_GetObjectItemCaseSensitive(jwk, "n");
    cJSON *je = cJSON_GetObjectItemCaseSensitive(jwk, "e");

    if (!cJSON_IsString(jn) || !cJSON_IsString(je)) {
        cJSON_Delete(jwks_json);
        snprintf(errbuf, errlen, "JWK missing n or e");

        return FLOW_ERR_INTERNAL;
    }

    EVP_PKEY *pkey = build_rsa_pkey(jn->valuestring, je->valuestring);

    cJSON_Delete(jwks_json);

    if (pkey == NULL) {
        snprintf(errbuf, errlen, "failed to construct RSA public key from JWK");

        return FLOW_ERR_INTERNAL;
    }

    /* Signing input is "header.payload". */
    size_t signing_input_len = (size_t)(dot2 - access_token);

    /* Decode signature. */
    const char *sig_b64 = dot2 + 1;
    size_t sig_len = 0;
    unsigned char *sig = base64url_decode(sig_b64, &sig_len);

    if (sig == NULL) {
        EVP_PKEY_free(pkey);
        snprintf(errbuf, errlen, "failed to decode JWT signature");

        return FLOW_ERR_INTERNAL;
    }

    int rc = verify_rs256(pkey, access_token, signing_input_len, sig, sig_len);

    EVP_PKEY_free(pkey);
    free(sig);

    if (rc != 0) {
        return FLOW_ERR_SIGNATURE;
    }

    return FLOW_OK;
}

int device_flow_introspect_token(device_flow *df, const char *access_token,
                                 char *errbuf, size_t errlen)
{
    if (access_token == NULL || access_token[0] == '\0') {
        snprintf(errbuf, errlen, "access token is required");

        return FLOW_ERR_INTERNAL;
    }

    /* Build form: token=<access_token>. */
    size_t form_len = strlen("token=") + strlen(access_token) + 1;
    char *form = malloc(form_len);

    if (form == NULL) {
        snprintf(errbuf, errlen, "out of memory");

        return FLOW_ERR_INTERNAL;
    }

    snprintf(form, form_len, "token=%s", access_token);

    http_buffer buf;

    http_buffer_init(&buf);

    int status = http_post_form(df->hc, df->endpoints.introspection, form,
                                df->client_id, df->client_secret,
                                1, &buf);

    free(form);

    if (status < 0 || buf.data == NULL) {
        http_buffer_free(&buf);
        snprintf(errbuf, errlen, "introspection request failed");

        return FLOW_ERR_INTERNAL;
    }

    if (status != 200) {
        http_buffer_free(&buf);
        snprintf(errbuf, errlen, "introspection request failed: status %d", status);

        return FLOW_ERR_INTERNAL;
    }

    cJSON *json = cJSON_Parse(buf.data);

    http_buffer_free(&buf);

    if (json == NULL) {
        snprintf(errbuf, errlen, "failed to parse introspection response JSON");

        return FLOW_ERR_INTERNAL;
    }

    cJSON *jactive = cJSON_GetObjectItemCaseSensitive(json, "active");
    int active = cJSON_IsTrue(jactive);

    cJSON_Delete(json);

    if (!active) {
        return FLOW_ERR_INACTIVE;
    }

    return FLOW_OK;
}
