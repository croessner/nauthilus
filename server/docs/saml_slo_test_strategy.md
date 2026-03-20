# SAML SLO Teststrategie und Interop-Abnahme (SLO-014)

Stand: 2026-03-19
Owner: IdP/SAML Team

## Ziel

Produktionsreife der SAML-SLO-Implementierung ueber drei Ebenen absichern:

1. Unit-Tests fuer Parser, Validator, Replay-Schutz und Fanout-StateMachine.
2. Integrations-Tests fuer `/saml/slo` mit signierten Test-SP-Nachrichten.
3. Interop-Abnahme mit realen SP-Produkten.

## 1. Testmatrix

| Ebene       | Fokus                                                       | Nachweis                                                                  |
|-------------|-------------------------------------------------------------|---------------------------------------------------------------------------|
| Unit        | Parser/Validator/Replay/Fanout-StateMachine                 | Go-Testfaelle in `server/idp/slo` und `server/handler/frontend/idp`       |
| Integration | Endpoint-Verhalten `/saml/slo` (GET/POST, Request/Response) | End-to-End Handler-Tests mit signierten SAML-Nachrichten                  |
| Interop     | Produktuebergreifende Kompatibilitaet                       | Definierte Szenarien fuer Zabbix und Nextcloud inkl. Evidenzanforderungen |

### 1.1 Unit-Matrix

| ID               | Bereich                                     | Testreferenz                                                             |
|------------------|---------------------------------------------|--------------------------------------------------------------------------|
| U-SLO-PARSER-001 | Inbound-Routingmatrix `/saml/slo`           | `TestRouteSLOInboundMessage`                                             |
| U-SLO-PARSER-002 | Decode/Inflate Redirect+POST Payload        | `TestDecodeLogoutRequestXML`                                             |
| U-SLO-PARSER-003 | Strict-Query-Parsing inkl. Duplicate-Reject | `TestRawQueryParameterStrictSLO`                                         |
| U-SLO-PARSER-004 | Flate-Uncompress-Limit                      | `TestInflateSAMLRedirectPayload_RejectsOversizedContent`                 |
| U-SLO-VAL-001    | LogoutRequest Signaturvalidierung Redirect  | `TestSAMLHandler_validateInboundLogoutRequestSignature_Redirect`         |
| U-SLO-VAL-002    | LogoutRequest Signaturvalidierung POST      | `TestSAMLHandler_validateInboundLogoutRequestSignature_POST`             |
| U-SLO-VAL-003    | LogoutResponse Signaturvalidierung Redirect | `TestSAMLHandler_validateInboundLogoutResponseSignature_Redirect`        |
| U-SLO-VAL-004    | Protokollvalidierung LogoutRequest Felder   | `TestSAMLHandler_validateInboundLogoutRequestProtocol_FieldValidation`   |
| U-SLO-VAL-005    | Protokollvalidierung LogoutResponse Felder  | `TestSAMLHandler_validateInboundLogoutResponseProtocol_FieldValidation`  |
| U-SLO-REPLAY-001 | Replay-Schutz + Registry-Mapping            | `TestSAMLHandler_validateInboundLogoutRequestProtocol_RegistryAndReplay` |
| U-SLO-FSM-001    | Transaction Lifecycle-Transitions           | `TestSLOStatusTransitions`, `TestSLOTransactionTransitionLifecycle`      |
| U-SLO-FSM-002    | Fanout-State-Building und Guards            | `TestNewSLOFanoutTransactionState`                                       |
| U-SLO-FSM-003    | Fanout-Aggregation finaler Status           | `TestSAMLHandler_applySLOFanoutLogoutResponse_AggregatesFinalStatus`     |

### 1.2 Integrationsmatrix

| ID           | Szenario                                          | Testreferenz                                                  |
|--------------|---------------------------------------------------|---------------------------------------------------------------|
| I-SLO-EP-001 | `/saml/slo` Dispatch + Fehlerpfade                | `TestSAMLHandler_SLOPayloadValidationAndDispatch`             |
| I-SLO-EP-002 | SP-initiiert: signierte LogoutResponse (Redirect) | `TestSAMLHandler_SLOSignedLogoutResponse`                     |
| I-SLO-EP-003 | SP-initiiert: signierte LogoutResponse (POST)     | `TestSAMLHandler_SLOSignedLogoutResponse_POST`                |
| I-SLO-EP-004 | Partial-Logout auf SAML-Status gemappt            | `TestSAMLHandler_SLOSignedLogoutResponse_PartialLogoutStatus` |
| I-SLO-EP-005 | Fanout-Response-Verarbeitung (Redirect)           | `TestSAMLHandler_SLO_LogoutResponse_CompletesFanout`          |
| I-SLO-EP-006 | Fanout-Response-Verarbeitung (POST)               | `TestSAMLHandler_SLO_LogoutResponse_CompletesFanout_POST`     |

### 1.3 Interop-Matrix (manuelle Abnahme)

| ID            | Produkt               | Flow                                | Erwartung                                                                                                |
|---------------|-----------------------|-------------------------------------|----------------------------------------------------------------------------------------------------------|
| X-SLO-ZBX-001 | Zabbix (SAML)         | SP-initiiertes Logout (Redirect)    | Zabbix sendet gueltige `LogoutRequest`, IdP antwortet signierte `LogoutResponse`, Zabbix-Session beendet |
| X-SLO-ZBX-002 | Zabbix (SAML)         | IdP-initiiertes Logout              | Zabbix verarbeitet IdP-`LogoutRequest`, Rueckantwort korreliert via `InResponseTo`                       |
| X-SLO-NXC-001 | Nextcloud `user_saml` | SP-initiiertes Logout (POST)        | POST-signierte `LogoutRequest` wird akzeptiert, Session in IdP + SP beendet                              |
| X-SLO-NXC-002 | Nextcloud `user_saml` | Fehlerszenario (tampered signature) | IdP weist Anfrage mit 4xx ab, kein lokales Logout ohne valide Signatur                                   |

## 2. Ausfuehrung der automatisierten SLO-Tests

```bash
GOEXPERIMENT=runtimesecret go test ./server/idp/slo -count=1
GOEXPERIMENT=runtimesecret go test ./server/handler/frontend/idp -run '^(TestRouteSLOInboundMessage|TestDecodeLogoutRequestXML|TestDecodeLogoutRequestPayload|TestDecodeLogoutResponsePayload|TestDecodeLogoutPayload_InvalidXMLRejected|TestRawQueryParameterStrictSLO|TestInflateSAMLRedirectPayload_RejectsOversizedContent|TestNewSLOFanoutTransactionState|TestSLOFanoutTransactionState_OutcomeCounts|TestAggregateSLOFanoutTerminalStatus|TestSAMLHandler_validateInboundLogoutRequestSignature_Redirect|TestSAMLHandler_validateInboundLogoutRequestSignature_POST|TestSAMLHandler_validateInboundLogoutRequestProtocol_FieldValidation|TestSAMLHandler_validateInboundLogoutRequestProtocol_RegistryAndReplay|TestSAMLHandler_SLOPayloadValidationAndDispatch|TestSAMLHandler_SLOSignedLogoutResponse|TestSAMLHandler_SLOSignedLogoutResponse_POST|TestSAMLHandler_SLOSignedLogoutResponse_PartialLogoutStatus|TestSAMLHandler_SLO_LogoutResponse_CompletesFanout|TestSAMLHandler_SLO_LogoutResponse_CompletesFanout_POST|TestSAMLHandler_validateInboundLogoutResponseSignature_Redirect|TestSAMLHandler_validateInboundLogoutResponseProtocol_FieldValidation|TestSAMLHandler_applySLOFanoutLogoutResponse_AggregatesFinalStatus|TestSAMLHandler_storeSLOFanoutTransactionState_PersistsPendingRequests|TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_Redirect|TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_POST|TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_NoParticipants|TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_BackChannelSuccess|TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_BackChannelFallbackToFrontChannel|TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_DisabledChannels|TestSAMLHandler_orchestrateIDPInitiatedSLOFanout_MaxParticipantsLimit|TestSAMLHandler_performLocalSLOCleanup_Idempotent|TestSAMLHandler_deleteSLOParticipantSessionsByAccount|TestSAMLHandler_newValidatedSLOTransaction|TestValidateSingleSLOParam_RejectsOversizedPayload|TestSAMLHandler_SLO_RateLimitAbuseGuard|TestSLOObservabilityMetrics|TestSLOTerminalStatusFromCleanup)$' -count=1
```

## 3. Interop-Abnahmeprotokoll

Jedes Interop-Szenario gilt nur als bestanden, wenn folgende Evidenz archiviert ist:

1. Zeitstempel + Produktversion.
2. SP- und IdP-Logauszug mit `transaction_id`/`request_id`.
3. Browser-Network-Trace der SLO-Nachrichten.
4. Finaler Session-Status in SP und IdP.

Empfohlene Ablage: `test-results/saml-slo-interop/<datum>/<produkt>/`.

## 4. Exit-Kriterien (DoD SLO-014)

1. Unit-Matrix ist gruen.
2. Integrationsmatrix ist gruen.
3. Interop-Szenarien X-SLO-ZBX-* und X-SLO-NXC-* sind mit Evidenz als `passed` dokumentiert.
