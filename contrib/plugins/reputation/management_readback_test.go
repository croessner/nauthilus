package main

import "testing"

func TestManagementReadbackRejectsDivergentStoredOverride(t *testing.T) {
	for _, field := range []string{"ttl", "creator", "reason", "origin", "created_at"} {
		t.Run(field, func(t *testing.T) {
			ttl := int64(3600)
			input := managementInput{Kind: kindIP, Band: bandBlocked, AuditID: "write", Reason: "incident", Origin: "operator", TTLSeconds: &ttl}
			snapshot := assessmentSnapshot{Audit: &managementAuditRecord{managementAudit: managementAudit{Schema: managementAuditSchema, Kind: kindIP, Operation: managementPut, AuditID: input.AuditID,
				Creator: "verified-admin", Reason: input.Reason, Origin: input.Origin, CreatedAt: 1000}},
				OperatorOverride: &overrideRecord{Schema: overrideSchema, Kind: kindIP, Band: input.Band, AuditID: input.AuditID, Creator: "verified-admin", Reason: input.Reason, Origin: input.Origin, CreatedAt: 1000, ExpiresAt: 4600}}
			requireNoError(t, verifyManagementChange(snapshot, managementPut, input, "verified-admin"))

			switch field {
			case "ttl":
				snapshot.OperatorOverride.ExpiresAt = 4601
			case "creator":
				snapshot.OperatorOverride.Creator = "different-admin"
			case "reason":
				snapshot.OperatorOverride.Reason = "other"
			case "origin":
				snapshot.OperatorOverride.Origin = "other"
			case "created_at":
				snapshot.OperatorOverride.CreatedAt = 1001
			}

			if verifyManagementChange(snapshot, managementPut, input, "verified-admin") == nil {
				t.Fatal("divergent primary override was acknowledged")
			}
		})
	}
}
