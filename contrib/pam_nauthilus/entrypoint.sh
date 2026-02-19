#!/bin/sh
set -eu

PAM_OPTS=""

append_opt() {
    key="$1"
    value="$2"

    if [ -z "$value" ]; then
        return 0
    fi

    if [ -z "$PAM_OPTS" ]; then
        PAM_OPTS="${key}=${value}"

        return 0
    fi

    PAM_OPTS="${PAM_OPTS} ${key}=${value}"
}

warn_missing() {
    if [ -z "${2:-}" ]; then
        echo "pam_nauthilus demo: missing ${1} (set ${3} env var)" >&2
    fi
}

: "${PAM_SCOPE:=openid}"
: "${PAM_USER_CLAIM:=preferred_username}"
: "${PAM_TIMEOUT:=5m}"
: "${PAM_REQUEST_TIMEOUT:=10s}"

warn_missing issuer "${PAM_ISSUER:-}" PAM_ISSUER
warn_missing client_id "${PAM_CLIENT_ID:-}" PAM_CLIENT_ID
warn_missing client_secret "${PAM_CLIENT_SECRET:-}" PAM_CLIENT_SECRET

append_opt issuer "${PAM_ISSUER:-}"
append_opt device_endpoint "${PAM_DEVICE_ENDPOINT:-}"
append_opt token_endpoint "${PAM_TOKEN_ENDPOINT:-}"
append_opt userinfo_endpoint "${PAM_USERINFO_ENDPOINT:-}"
append_opt jwks_endpoint "${PAM_JWKS_ENDPOINT:-}"
append_opt introspection_endpoint "${PAM_INTROSPECTION_ENDPOINT:-}"
append_opt client_id "${PAM_CLIENT_ID:-}"
append_opt client_secret "${PAM_CLIENT_SECRET:-}"
append_opt scope "${PAM_SCOPE}"
append_opt user_claim "${PAM_USER_CLAIM}"
append_opt timeout "${PAM_TIMEOUT}"
append_opt request_timeout "${PAM_REQUEST_TIMEOUT}"
append_opt ca_file "${PAM_CA_FILE:-}"
append_opt tls_server_name "${PAM_TLS_SERVER_NAME:-}"
append_opt allow_http "${PAM_ALLOW_HTTP:-}"

cat > /etc/pam.d/login <<EOF
auth required pam_nauthilus.so ${PAM_OPTS}
account required pam_permit.so
session required pam_permit.so
EOF

exec "$@"
