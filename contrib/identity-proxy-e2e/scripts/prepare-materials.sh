#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${ROOT_DIR}/.work"
CERT_DIR="${WORK_DIR}/certs"
KEY_DIR="${WORK_DIR}/keys"

mkdir -p "${CERT_DIR}" "${KEY_DIR}"

if [[ "${NAUTHILUS_E2E_FORCE:-}" != "1" && -f "${CERT_DIR}/e2e-ca.crt" && -f "${CERT_DIR}/edge-http.crt" ]]; then
  echo "Generated material already exists in ${WORK_DIR}. Set NAUTHILUS_E2E_FORCE=1 to replace it."
  exit 0
fi

rm -f "${CERT_DIR}"/* "${KEY_DIR}"/*

openssl genrsa -out "${CERT_DIR}/e2e-ca.key" 2048
openssl req -x509 -new -nodes -key "${CERT_DIR}/e2e-ca.key" -sha256 -days 30 \
  -subj "/CN=Nauthilus identity proxy E2E CA" \
  -out "${CERT_DIR}/e2e-ca.crt"

cat >"${WORK_DIR}/authority-server.openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
req_extensions = req_ext

[dn]
CN = authority

[req_ext]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = authority
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl genrsa -out "${CERT_DIR}/authority-server.key" 2048
openssl req -new -key "${CERT_DIR}/authority-server.key" \
  -out "${CERT_DIR}/authority-server.csr" \
  -config "${WORK_DIR}/authority-server.openssl.cnf"
openssl x509 -req -in "${CERT_DIR}/authority-server.csr" \
  -CA "${CERT_DIR}/e2e-ca.crt" \
  -CAkey "${CERT_DIR}/e2e-ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/authority-server.crt" \
  -days 30 \
  -sha256 \
  -extensions req_ext \
  -extfile "${WORK_DIR}/authority-server.openssl.cnf"

cat >"${WORK_DIR}/edge-http.openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
req_extensions = req_ext

[dn]
CN = split.example.test

[req_ext]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = split.example.test
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl genrsa -out "${CERT_DIR}/edge-http.key" 2048
openssl req -new -key "${CERT_DIR}/edge-http.key" \
  -out "${CERT_DIR}/edge-http.csr" \
  -config "${WORK_DIR}/edge-http.openssl.cnf"
openssl x509 -req -in "${CERT_DIR}/edge-http.csr" \
  -CA "${CERT_DIR}/e2e-ca.crt" \
  -CAkey "${CERT_DIR}/e2e-ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/edge-http.crt" \
  -days 30 \
  -sha256 \
  -extensions req_ext \
  -extfile "${WORK_DIR}/edge-http.openssl.cnf"

cat >"${WORK_DIR}/edge-client.openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
req_extensions = req_ext

[dn]
CN = edge-e2e

[req_ext]
extendedKeyUsage = clientAuth
EOF

openssl genrsa -out "${CERT_DIR}/edge-client.key" 2048
openssl req -new -key "${CERT_DIR}/edge-client.key" \
  -out "${CERT_DIR}/edge-client.csr" \
  -config "${WORK_DIR}/edge-client.openssl.cnf"
openssl x509 -req -in "${CERT_DIR}/edge-client.csr" \
  -CA "${CERT_DIR}/e2e-ca.crt" \
  -CAkey "${CERT_DIR}/e2e-ca.key" \
  -CAcreateserial \
  -out "${CERT_DIR}/edge-client.crt" \
  -days 30 \
  -sha256 \
  -extensions req_ext \
  -extfile "${WORK_DIR}/edge-client.openssl.cnf"

openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=Nauthilus split edge SAML" \
  -keyout "${CERT_DIR}/edge-saml.key" \
  -out "${CERT_DIR}/edge-saml.crt"

openssl genrsa -out "${KEY_DIR}/authority-oidc-signing.key" 2048
openssl genrsa -out "${KEY_DIR}/edge-oidc-signing.key" 2048
openssl genrsa -out "${KEY_DIR}/edge-authority-client.key" 2048
openssl rsa -in "${KEY_DIR}/edge-authority-client.key" \
  -pubout \
  -out "${KEY_DIR}/edge-authority-client.pub"

chmod 0644 "${CERT_DIR}"/* "${KEY_DIR}"/*

echo "Generated split identity-proxy E2E material in ${WORK_DIR}."
