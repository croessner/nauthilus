package authmapper

import (
	"reflect"
	"testing"

	authv1 "github.com/croessner/nauthilus/v3/api/auth/v1"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
)

func TestDTOOutboundMappersRoundTripSharedRequestFields(t *testing.T) {
	dto := expectedAuthDTO()

	authRequest := DTOToAuthRequest(dto)
	assertStructuredRequestMatchesDTO(t, authRequest, dto)

	if authRequest.GetPassword() != dto.Password || authRequest.GetAuthLoginAttempt() != uint32(dto.AuthLoginAttempt) {
		t.Fatal("authentication-only outbound fields do not match the DTO")
	}

	if got := AuthRequestToDTO(authRequest); !reflect.DeepEqual(got, dto) {
		t.Fatalf("AuthRequest round trip = %#v, want %#v", got, dto)
	}

	lookupDTO := expectedLookupDTO(dto)
	lookupRequest := DTOToLookupIdentityRequest(dto)
	assertStructuredRequestMatchesDTO(t, lookupRequest, lookupDTO)

	if got := LookupIdentityRequestToDTO(lookupRequest); !reflect.DeepEqual(got, lookupDTO) {
		t.Fatalf("LookupIdentityRequest round trip = %#v, want %#v", got, lookupDTO)
	}

	listRequest := DTOToListAccountsRequest(dto)
	assertListRequestMatchesDTO(t, listRequest, dto)

	listDTO := ListAccountsRequestToDTO(listRequest)
	if listDTO.Username != dto.Username || listDTO.ClientIP != dto.ClientIP || listDTO.Protocol != dto.Protocol {
		t.Fatalf("ListAccountsRequest mapped partial DTO = %#v", listDTO)
	}
}

// assertStructuredRequestMatchesDTO verifies fields shared by auth and lookup requests.
func assertStructuredRequestMatchesDTO(t *testing.T, request structuredAuthRequest, dto authdto.Request) {
	t.Helper()

	testCases := []struct {
		name string
		got  string
		want string
	}{
		{name: "username", got: request.GetUsername(), want: dto.Username},
		{name: "client_ip", got: request.GetClientIp(), want: dto.ClientIP},
		{name: "client_port", got: request.GetClientPort(), want: dto.ClientPort},
		{name: "client_hostname", got: request.GetClientHostname(), want: dto.ClientHostname},
		{name: "client_id", got: request.GetClientId(), want: dto.ClientID},
		{name: "external_session_id", got: request.GetExternalSessionId(), want: dto.ExternalSessionID},
		{name: "user_agent", got: request.GetUserAgent(), want: dto.UserAgent},
		{name: "local_ip", got: request.GetLocalIp(), want: dto.LocalIP},
		{name: "local_port", got: request.GetLocalPort(), want: dto.LocalPort},
		{name: "protocol", got: request.GetProtocol(), want: dto.Protocol},
		{name: "method", got: request.GetMethod(), want: dto.Method},
		{name: "ssl", got: request.GetSsl(), want: dto.XSSL},
		{name: "ssl_session_id", got: request.GetSslSessionId(), want: dto.XSSLSessionID},
		{name: "ssl_client_verify", got: request.GetSslClientVerify(), want: dto.XSSLClientVerify},
		{name: "ssl_client_dn", got: request.GetSslClientDn(), want: dto.XSSLClientDN},
		{name: "ssl_client_cn", got: request.GetSslClientCn(), want: dto.XSSLClientCN},
		{name: "ssl_issuer", got: request.GetSslIssuer(), want: dto.XSSLIssuer},
		{name: "ssl_client_notbefore", got: request.GetSslClientNotbefore(), want: dto.XSSLClientNotBefore},
		{name: "ssl_client_notafter", got: request.GetSslClientNotafter(), want: dto.XSSLClientNotAfter},
		{name: "ssl_subject_dn", got: request.GetSslSubjectDn(), want: dto.XSSLSubjectDN},
		{name: "ssl_issuer_dn", got: request.GetSslIssuerDn(), want: dto.XSSLIssuerDN},
		{name: "ssl_client_subject_dn", got: request.GetSslClientSubjectDn(), want: dto.XSSLClientSubjectDN},
		{name: "ssl_client_issuer_dn", got: request.GetSslClientIssuerDn(), want: dto.XSSLClientIssuerDN},
		{name: "ssl_protocol", got: request.GetSslProtocol(), want: dto.XSSLProtocol},
		{name: "ssl_cipher", got: request.GetSslCipher(), want: dto.XSSLCipher},
		{name: "ssl_serial", got: request.GetSslSerial(), want: dto.SSLSerial},
		{name: "ssl_fingerprint", got: request.GetSslFingerprint(), want: dto.SSLFingerprint},
		{name: "oidc_cid", got: request.GetOidcCid(), want: dto.OIDCCID},
	}

	for _, testCase := range testCases {
		if testCase.got != testCase.want {
			t.Errorf("%s = %q, want %q", testCase.name, testCase.got, testCase.want)
		}
	}
}

// assertListRequestMatchesDTO verifies every account-listing request field.
func assertListRequestMatchesDTO(t *testing.T, request *authv1.ListAccountsRequest, dto authdto.Request) {
	t.Helper()

	got := []string{
		request.GetUsername(), request.GetClientIp(), request.GetClientPort(), request.GetClientHostname(),
		request.GetClientId(), request.GetExternalSessionId(), request.GetUserAgent(), request.GetLocalIp(),
		request.GetLocalPort(), request.GetProtocol(), request.GetMethod(), request.GetOidcCid(),
	}
	want := []string{
		dto.Username, dto.ClientIP, dto.ClientPort, dto.ClientHostname, dto.ClientID, dto.ExternalSessionID,
		dto.UserAgent, dto.LocalIP, dto.LocalPort, dto.Protocol, dto.Method, dto.OIDCCID,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list-accounts outbound fields = %#v, want %#v", got, want)
	}
}

func expectedLookupDTO(dto authdto.Request) authdto.Request {
	dto.Password = ""
	dto.AuthLoginAttempt = 0

	return dto
}
