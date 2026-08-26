// Copyright (C) 2024-2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

var (
	regLuaSubject   CapturedLuaSubject = testLuaSubject{}
	regRBLService   RBLService         = testAuthnRBLService{}
	regBF           BruteForceService  = testAuthnBruteForceService{}
	regCacheService CacheService       = testAuthnCacheService{}
	regPassVerifier PasswordVerifier   = testPasswordVerifier{}
)

func RegisterLuaSubject(subject CapturedLuaSubject) { regLuaSubject = subject }
func RegisterRBLService(service RBLService)         { regRBLService = service }
func RegisterCacheService(service CacheService)     { regCacheService = service }
func RegisterPasswordVerifier(verifier PasswordVerifier) {
	regPassVerifier = verifier
}
func RegisterBruteForceService(service BruteForceService) { regBF = service }

func getLuaSubject() CapturedLuaSubject       { return regLuaSubject }
func getRBLService() RBLService               { return regRBLService }
func getBruteForceService() BruteForceService { return regBF }
func getCacheService() CacheService           { return regCacheService }
func getPasswordVerifier() PasswordVerifier   { return regPassVerifier }
func GetRBLService() RBLService               { return getRBLService() }

// registeredAuthnHostServices snapshots test-owned implementations at fixture construction time.
func registeredAuthnHostServices() AuthnHostServices {
	services, _ := NewAuthnHostServices(AuthnHostServicesInput{
		PasswordVerifier: getPasswordVerifier(),
		Cache:            getCacheService(),
		BruteForce:       getBruteForceService(),
		Subject:          getLuaSubject(),
		RBL:              getRBLService(),
	})

	return services
}

// withRegisteredAuthnHostServices fills a missing bundle only for explicit test hosts.
func withRegisteredAuthnHostServices(deps AuthDeps) AuthDeps {
	if deps.HostServices.validate() == nil {
		return deps
	}

	deps.HostServices = registeredAuthnHostServices()

	return deps
}
