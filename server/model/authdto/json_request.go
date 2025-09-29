// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package authdto

// Request is a data structure containing the details of a client's request in JSON format.
type Request struct {
	// Username is the identifier of the client/user sending the request.
	Username string `json:"username" binding:"required"`

	// Password is the authentication credential of the client/user sending the request.
	Password string `json:"password,omitempty"`

	// ClientIP is the IP address of the client/user making the request.
	ClientIP string `json:"client_ip,omitempty"`

	// ClientPort is the port number from which the client/user is sending the request.
	ClientPort string `json:"client_port,omitempty"`

	// ClientHostname is the hostname of the client which is sending the request.
	ClientHostname string `json:"client_hostname,omitempty"`

	// ClientID is the unique identifier of the client/user, usually assigned by the application.
	ClientID string `json:"client_id,omitempty"`

	// UserAgent optionally provides the user agent via JSON when headers are unavailable.
	UserAgent string `json:"user_agent,omitempty"`

	// LocalIP is the IP address of the server or endpoint receiving the request.
	LocalIP string `json:"local_ip,omitempty"`

	// LocalPort is the port number of the server or endpoint receiving the request.
	LocalPort string `json:"local_port,omitempty"`

	// Protocol is the application protocol used by the client (e.g., imap, smtp, pop3, http).
	Protocol string `json:"protocol,omitempty"`

	// Method is the HTTP/SASL method used in the request (e.g., PLAIN, LOGIN, etc.)
	Method string `json:"method,omitempty"`

	// AuthLoginAttempt is a flag indicating if the request is an attempt to authenticate (login). This is expressed as an unsigned integer where applicable flags/types are usually interpreted from the application's specific logic.
	AuthLoginAttempt uint `json:"auth_login_attempt,omitempty"`

	XSSL                string `json:"ssl,omitempty"`
	XSSLSessionID       string `json:"ssl_session_id,omitempty"`
	XSSLClientVerify    string `json:"ssl_client_verify,omitempty"`
	XSSLClientDN        string `json:"ssl_client_dn,omitempty"`
	XSSLClientCN        string `json:"ssl_client_cn,omitempty"`
	XSSLIssuer          string `json:"ssl_issuer,omitempty"`
	XSSLClientNotBefore string `json:"ssl_client_notbefore,omitempty"`
	XSSLClientNotAfter  string `json:"ssl_client_notafter,omitempty"`
	XSSLSubjectDN       string `json:"ssl_subject_dn,omitempty"`
	XSSLIssuerDN        string `json:"ssl_issuer_dn,omitempty"`
	XSSLClientSubjectDN string `json:"ssl_client_subject_dn,omitempty"`
	XSSLClientIssuerDN  string `json:"ssl_client_issuer_dn,omitempty"`
	XSSLProtocol        string `json:"ssl_protocol,omitempty"`
	XSSLCipher          string `json:"ssl_cipher,omitempty"`

	// SSLSerial represents the serial number of an SSL certificate as a string.
	SSLSerial string `json:"ssl_serial,omitempty"`

	// SSLFingerprint represents the fingerprint of an SSL certificate.
	SSLFingerprint string `json:"ssl_fingerprint,omitempty"`

	// OIDCCID represents the OIDC Client ID used for authentication.
	OIDCCID string `json:"oidc_cid,omitempty"`
}
