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

package authv1

import "github.com/croessner/nauthilus/v3/server/model/authdto"

// DTOToAuthRequest maps the shared auth DTO to a gRPC authentication request.
func DTOToAuthRequest(dto authdto.Request) *AuthRequest {
	return &AuthRequest{
		Username:           dto.Username,
		Password:           dto.Password,
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

// DTOToLookupIdentityRequest maps the shared auth DTO to a trusted lookup request.
func DTOToLookupIdentityRequest(dto authdto.Request) *LookupIdentityRequest {
	request := DTOToAuthRequest(dto)

	return &LookupIdentityRequest{
		Username:           request.Username,
		ClientIp:           request.ClientIp,
		ClientPort:         request.ClientPort,
		ClientHostname:     request.ClientHostname,
		ClientId:           request.ClientId,
		ExternalSessionId:  request.ExternalSessionId,
		UserAgent:          request.UserAgent,
		LocalIp:            request.LocalIp,
		LocalPort:          request.LocalPort,
		Protocol:           request.Protocol,
		Method:             request.Method,
		Ssl:                request.Ssl,
		SslSessionId:       request.SslSessionId,
		SslClientVerify:    request.SslClientVerify,
		SslClientDn:        request.SslClientDn,
		SslClientCn:        request.SslClientCn,
		SslIssuer:          request.SslIssuer,
		SslClientNotbefore: request.SslClientNotbefore,
		SslClientNotafter:  request.SslClientNotafter,
		SslSubjectDn:       request.SslSubjectDn,
		SslIssuerDn:        request.SslIssuerDn,
		SslClientSubjectDn: request.SslClientSubjectDn,
		SslClientIssuerDn:  request.SslClientIssuerDn,
		SslProtocol:        request.SslProtocol,
		SslCipher:          request.SslCipher,
		SslSerial:          request.SslSerial,
		SslFingerprint:     request.SslFingerprint,
		OidcCid:            request.OidcCid,
	}
}

// DTOToListAccountsRequest maps the shared auth DTO to an account-listing request.
func DTOToListAccountsRequest(dto authdto.Request) *ListAccountsRequest {
	return &ListAccountsRequest{
		Username:          dto.Username,
		ClientIp:          dto.ClientIP,
		ClientPort:        dto.ClientPort,
		ClientHostname:    dto.ClientHostname,
		ClientId:          dto.ClientID,
		ExternalSessionId: dto.ExternalSessionID,
		UserAgent:         dto.UserAgent,
		LocalIp:           dto.LocalIP,
		LocalPort:         dto.LocalPort,
		Protocol:          dto.Protocol,
		Method:            dto.Method,
		OidcCid:           dto.OIDCCID,
	}
}
