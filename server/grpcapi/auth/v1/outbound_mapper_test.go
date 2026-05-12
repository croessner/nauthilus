package authv1

import (
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/server/model/authdto"
)

func TestDTOOutboundMappersRoundTripSharedRequestFields(t *testing.T) {
	dto := expectedAuthDTO()

	authRequest := DTOToAuthRequest(dto)
	if got := AuthRequestToDTO(authRequest); !reflect.DeepEqual(got, dto) {
		t.Fatalf("AuthRequest round trip = %#v, want %#v", got, dto)
	}

	lookupDTO := expectedLookupDTO(dto)
	if got := LookupIdentityRequestToDTO(DTOToLookupIdentityRequest(dto)); !reflect.DeepEqual(got, lookupDTO) {
		t.Fatalf("LookupIdentityRequest round trip = %#v, want %#v", got, lookupDTO)
	}

	listDTO := ListAccountsRequestToDTO(DTOToListAccountsRequest(dto))
	if listDTO.Username != dto.Username || listDTO.ClientIP != dto.ClientIP || listDTO.Protocol != dto.Protocol {
		t.Fatalf("ListAccountsRequest mapped partial DTO = %#v", listDTO)
	}
}

func expectedLookupDTO(dto authdto.Request) authdto.Request {
	dto.Password = ""
	dto.AuthLoginAttempt = 0

	return dto
}
