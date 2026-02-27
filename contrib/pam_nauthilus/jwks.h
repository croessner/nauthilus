/*
 * jwks.h – JWKS fetching and JWT RS256 signature verification.
 *
 * Uses OpenSSL for RSA signature verification and base64url decoding.
 */

#ifndef PAM_NAUTHILUS_JWKS_H
#define PAM_NAUTHILUS_JWKS_H

#include "flow.h"
#include "http_client.h"

/*
 * device_flow_verify_signature fetches the JWKS from the IdP and verifies
 * the RS256 signature of the given JWT access token.
 * Returns FLOW_OK on success, FLOW_ERR_SIGNATURE on verification failure,
 * or FLOW_ERR_INTERNAL on other errors.
 */
int device_flow_verify_signature(device_flow *df, const char *access_token,
                                 char *errbuf, size_t errlen);

/*
 * device_flow_introspect_token calls the introspection endpoint and checks
 * that the token is active.
 * Returns FLOW_OK if active, FLOW_ERR_INACTIVE if not, or FLOW_ERR_INTERNAL.
 */
int device_flow_introspect_token(device_flow *df, const char *access_token,
                                 char *errbuf, size_t errlen);

#endif /* PAM_NAUTHILUS_JWKS_H */
