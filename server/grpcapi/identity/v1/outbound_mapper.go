// Copyright (C) 2026 Christian Rößner
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

package identityv1

import "github.com/croessner/nauthilus/v3/server/model/authdto"

// DTOToRequestContext maps the shared auth DTO to an identity request context.
func DTOToRequestContext(dto authdto.Request) *RequestContext {
	return &RequestContext{
		Username:           dto.Username,
		ClientIp:           dto.ClientIP,
		ClientPort:         dto.ClientPort,
		ClientHostname:     dto.ClientHostname,
		ClientId:           dto.ClientID,
		ExternalSessionId:  dto.ExternalSessionID,
		UserAgent:          dto.UserAgent,
		LocalIp:            dto.LocalIP,
		LocalPort:          dto.LocalPort,
		Protocol:           dto.Protocol,
		Method:             dto.Method,
		Ssl:                dto.XSSL,
		SslSessionId:       dto.XSSLSessionID,
		SslClientVerify:    dto.XSSLClientVerify,
		SslClientDn:        dto.XSSLClientDN,
		SslClientCn:        dto.XSSLClientCN,
		SslIssuer:          dto.XSSLIssuer,
		SslClientNotbefore: dto.XSSLClientNotBefore,
		SslClientNotafter:  dto.XSSLClientNotAfter,
		SslSubjectDn:       dto.XSSLSubjectDN,
		SslIssuerDn:        dto.XSSLIssuerDN,
		SslClientSubjectDn: dto.XSSLClientSubjectDN,
		SslClientIssuerDn:  dto.XSSLClientIssuerDN,
		SslProtocol:        dto.XSSLProtocol,
		SslCipher:          dto.XSSLCipher,
		SslSerial:          dto.SSLSerial,
		SslFingerprint:     dto.SSLFingerprint,
		OidcCid:            dto.OIDCCID,
		AuthLoginAttempt:   uint32(dto.AuthLoginAttempt),
	}
}
