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

import "github.com/croessner/nauthilus/server/model/authdto"

// AuthRequestToDTO maps a gRPC authentication request to the shared auth DTO.
func AuthRequestToDTO(request *AuthRequest) authdto.Request {
	if request == nil {
		return authdto.Request{}
	}

	dto := structuredAuthRequestToDTO(request)
	dto.Password = request.GetPassword()
	dto.AuthLoginAttempt = uint(request.GetAuthLoginAttempt())

	return dto
}

// ListAccountsRequestToDTO maps a gRPC list-accounts request to the shared auth DTO.
func ListAccountsRequestToDTO(request *ListAccountsRequest) authdto.Request {
	if request == nil {
		return authdto.Request{}
	}

	return authdto.Request{
		Username:          request.GetUsername(),
		ClientIP:          request.GetClientIp(),
		ClientPort:        request.GetClientPort(),
		ClientHostname:    request.GetClientHostname(),
		ClientID:          request.GetClientId(),
		ExternalSessionID: request.GetExternalSessionId(),
		UserAgent:         request.GetUserAgent(),
		LocalIP:           request.GetLocalIp(),
		LocalPort:         request.GetLocalPort(),
		Protocol:          request.GetProtocol(),
		Method:            request.GetMethod(),
		OIDCCID:           request.GetOidcCid(),
	}
}

// LookupIdentityRequestToDTO maps a gRPC identity lookup request to the shared auth DTO.
func LookupIdentityRequestToDTO(request *LookupIdentityRequest) authdto.Request {
	if request == nil {
		return authdto.Request{}
	}

	return structuredAuthRequestToDTO(request)
}

type structuredAuthRequest interface {
	GetUsername() string
	GetClientIp() string
	GetClientPort() string
	GetClientHostname() string
	GetClientId() string
	GetExternalSessionId() string
	GetUserAgent() string
	GetLocalIp() string
	GetLocalPort() string
	GetProtocol() string
	GetMethod() string
	GetSsl() string
	GetSslSessionId() string
	GetSslClientVerify() string
	GetSslClientDn() string
	GetSslClientCn() string
	GetSslIssuer() string
	GetSslClientNotbefore() string
	GetSslClientNotafter() string
	GetSslSubjectDn() string
	GetSslIssuerDn() string
	GetSslClientSubjectDn() string
	GetSslClientIssuerDn() string
	GetSslProtocol() string
	GetSslCipher() string
	GetSslSerial() string
	GetSslFingerprint() string
	GetOidcCid() string
}

func structuredAuthRequestToDTO(request structuredAuthRequest) authdto.Request {
	return authdto.Request{
		Username:            request.GetUsername(),
		ClientIP:            request.GetClientIp(),
		ClientPort:          request.GetClientPort(),
		ClientHostname:      request.GetClientHostname(),
		ClientID:            request.GetClientId(),
		ExternalSessionID:   request.GetExternalSessionId(),
		UserAgent:           request.GetUserAgent(),
		LocalIP:             request.GetLocalIp(),
		LocalPort:           request.GetLocalPort(),
		Protocol:            request.GetProtocol(),
		Method:              request.GetMethod(),
		XSSL:                request.GetSsl(),
		XSSLSessionID:       request.GetSslSessionId(),
		XSSLClientVerify:    request.GetSslClientVerify(),
		XSSLClientDN:        request.GetSslClientDn(),
		XSSLClientCN:        request.GetSslClientCn(),
		XSSLIssuer:          request.GetSslIssuer(),
		XSSLClientNotBefore: request.GetSslClientNotbefore(),
		XSSLClientNotAfter:  request.GetSslClientNotafter(),
		XSSLSubjectDN:       request.GetSslSubjectDn(),
		XSSLIssuerDN:        request.GetSslIssuerDn(),
		XSSLClientSubjectDN: request.GetSslClientSubjectDn(),
		XSSLClientIssuerDN:  request.GetSslClientIssuerDn(),
		XSSLProtocol:        request.GetSslProtocol(),
		XSSLCipher:          request.GetSslCipher(),
		SSLSerial:           request.GetSslSerial(),
		SSLFingerprint:      request.GetSslFingerprint(),
		OIDCCID:             request.GetOidcCid(),
	}
}
