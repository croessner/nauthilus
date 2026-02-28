# Implementierungsplan: `require_mfa` Parameter

## Übersicht

Der `require_mfa`-Parameter ermöglicht es, pro OIDC-Client bzw. SAML-Service-Provider festzulegen,
welche MFA-Methoden ein Benutzer zwingend registriert haben muss, bevor ein Authorization Flow
abgeschlossen werden kann. Fehlt eine oder mehrere Methoden, wird der Benutzer unmittelbar nach
der erfolgreichen Authentifizierung zur Registrierung weitergeleitet – bevor der Authorization Code
bzw. das SAML-Assertion ausgestellt wird.

Unterstützte Flows:
- OIDC Authorization Code Flow
- OIDC Device Code Flow (via `OIDCClient`)
- SAML2 SSO Flow (via `SAML2ServiceProvider`)

---

## 1. Konfiguration

### Datei: `server/config/idp.go`

#### `OIDCClient` – neues Feld

```go
type OIDCClient struct {
    // ... bestehende Felder ...
    RequireMFA []string `mapstructure:"require_mfa"`
}
```

Getter:
```go
func (c *OIDCClient) GetRequireMFA() []string {
    if c == nil {
        return nil
    }
    return c.RequireMFA
}
```

#### `SAML2ServiceProvider` – neues Feld

```go
type SAML2ServiceProvider struct {
    // ... bestehende Felder ...
    RequireMFA []string `mapstructure:"require_mfa"`
}
```

Getter:
```go
func (s *SAML2ServiceProvider) GetRequireMFA() []string {
    if s == nil {
        return nil
    }
    return s.RequireMFA
}
```

#### Beispiel-Konfiguration (YAML)

```yaml
idp:
  oidc:
    clients:
      - client_id: "secure_app"
        require_mfa:
          - totp
          - webauthn

  saml2:
    service_providers:
      - entity_id: "https://app.example.com/saml"
        require_mfa:
          - totp
```

Gültige Werte: `totp`, `webauthn`
Leere Liste (oder Feld weggelassen) = keine Pflicht.

---

## 2. Neue Session-Keys

### Datei: `server/definitions/const.go`

Zwei neue Konstanten in den bestehenden `SessionKey*`-Block einfügen:

```go
// SessionKeyRequireMFAFlow indicates that the user must register missing MFA methods
// before the IdP flow can be completed.
SessionKeyRequireMFAFlow = "require_mfa_flow"

// SessionKeyRequireMFAPending holds a comma-separated list of MFA methods
// that still need to be registered (e.g. "totp,webauthn" or "webauthn").
SessionKeyRequireMFAPending = "require_mfa_pending"
```

---

## 3. Backend-Logik

### Datei: `server/handler/frontend/idp/frontend.go`

#### 3.1 Eingriffspunkt: `finalizeMFALogin()`

Nach dem bestehenden Aufruf `CleanupMFAState(mgr)` und **vor** `redirectToIdPEndpoint()` wird
eingefügt:

```go
if h.checkRequiredMFARegistration(ctx, mgr, user) {
    return // Redirect zur Registrierung wurde bereits ausgeführt
}
h.redirectToIdPEndpoint(ctx, mgr)
```

#### 3.2 Neue Hilfsfunktion: `getRequiredMFAMethods()`

Liest den aktuellen Flow-Typ aus dem Cookie und gibt die konfigurierte `require_mfa`-Liste zurück.

```go
func (h *FrontendHandler) getRequiredMFAMethods(mgr cookie.Manager) []string {
    flowType := mgr.GetString(definitions.SessionKeyIdPFlowType, "")

    switch flowType {
    case definitions.ProtoOIDC:
        clientID := mgr.GetString(definitions.SessionKeyIdPClientID, "")
        if clientID == "" {
            return nil
        }
        idpInstance := idp.NewNauthilusIdP(h.deps)
        client, ok := idpInstance.FindClient(clientID)
        if !ok {
            return nil
        }
        return client.GetRequireMFA()

    case definitions.ProtoSAML:
        entityID := mgr.GetString(definitions.SessionKeyIdPSAMLEntityID, "")
        if entityID == "" {
            return nil
        }
        idpInstance := idp.NewNauthilusIdP(h.deps)
        sp, ok := idpInstance.FindSAMLServiceProvider(entityID)
        if !ok {
            return nil
        }
        return sp.GetRequireMFA()
    }

    return nil
}
```

#### 3.3 Neue Funktion: `checkRequiredMFARegistration()`

Vergleicht die konfigurierten Pflicht-Methoden mit den tatsächlich vorhandenen Methoden des Benutzers
und setzt den Forced-Flow auf, falls Methoden fehlen.

```go
func (h *FrontendHandler) checkRequiredMFARegistration(
    ctx *gin.Context,
    mgr cookie.Manager,
    user *backend.User,
) bool {
    if mgr == nil {
        return false
    }

    // Nur prüfen wenn ein aktiver IdP-Flow vorliegt
    if !mgr.GetBool(definitions.SessionKeyIdPFlowActive, false) {
        return false
    }

    required := h.getRequiredMFAMethods(mgr)
    if len(required) == 0 {
        return false
    }

    protocol := mgr.GetString(definitions.SessionKeyProtocol, "")

    var missing []string
    for _, method := range required {
        switch method {
        case "totp":
            if !h.hasTOTP(user) {
                missing = append(missing, "totp")
            }
        case "webauthn":
            if !h.hasWebAuthn(ctx, user, protocol) {
                missing = append(missing, "webauthn")
            }
        }
    }

    if len(missing) == 0 {
        return false
    }

    // Forced-Registration-Flow aktivieren
    mgr.Set(definitions.SessionKeyRequireMFAFlow, true)
    mgr.Set(definitions.SessionKeyRequireMFAPending, strings.Join(missing, ","))

    // Zur ersten fehlenden Registrierung weiterleiten
    return h.redirectToNextMFARegistration(ctx, mgr)
}
```

#### 3.4 Neue Hilfsfunktion: `redirectToNextMFARegistration()`

Liest die erste ausstehende Methode aus `SessionKeyRequireMFAPending` und leitet weiter.

```go
func (h *FrontendHandler) redirectToNextMFARegistration(ctx *gin.Context, mgr cookie.Manager) bool {
    pending := mgr.GetString(definitions.SessionKeyRequireMFAPending, "")
    if pending == "" {
        return false
    }

    methods := strings.SplitN(pending, ",", 2)
    switch methods[0] {
    case "totp":
        ctx.Redirect(http.StatusFound, definitions.MFARoot+"/totp/register")
        return true
    case "webauthn":
        ctx.Redirect(http.StatusFound, definitions.MFARoot+"/webauthn/register")
        return true
    }

    return false
}
```

#### 3.5 Anpassung: `PostRegisterTOTP()`

Direkt nach dem bestehenden Success-Block (Setzen von `SessionKeyHaveTOTP`, Löschen von
`SessionKeyTOTPSecret`), aber **vor** der letzten `HX-Redirect`-Zeile:

```go
// Forced-MFA-Flow: Prüfen ob noch weitere Methoden ausstehen
if mgr != nil && mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false) {
    pending := mgr.GetString(definitions.SessionKeyRequireMFAPending, "")
    remaining := removeFromMFAPendingList(pending, "totp")
    mgr.Set(definitions.SessionKeyRequireMFAPending, remaining)

    // HX-Redirect zu /mfa/register/continue (GET), der dann normal weiterleitet
    ctx.Header("HX-Redirect", definitions.MFARoot+"/register/continue")
    ctx.Status(http.StatusOK)

    return
}

// Bisheriges Verhalten (Self-Service)
ctx.Header("HX-Redirect", definitions.MFARoot+"/register/home")
ctx.Status(http.StatusOK)
```

> **Warum `/mfa/register/continue` statt direktem Redirect?**
> `PostRegisterTOTP` wird via HTMX aufgerufen. HTMX ignoriert `302`-Responses und folgt ihnen
> nicht als vollständige Seitennavigation. Der Header `HX-Redirect` hingegen weist den Browser
> an, eine vollständige Navigation durchzuführen. Der `continue`-Endpoint ist dann ein normaler
> GET-Handler, der regulär mit `302` weiterleiten kann.

#### 3.6 Neue Route: `GET /mfa/register/continue`

**Handler `ContinueRequiredMFARegistration()`:**

```go
func (h *FrontendHandler) ContinueRequiredMFARegistration(ctx *gin.Context) {
    mgr := cookie.GetManager(ctx)
    if mgr == nil {
        ctx.Redirect(http.StatusFound, "/")
        return
    }

    pending := mgr.GetString(definitions.SessionKeyRequireMFAPending, "")

    if pending == "" {
        // Alle Pflicht-Methoden registriert – Flow fortsetzen
        mgr.Delete(definitions.SessionKeyRequireMFAFlow)
        mgr.Delete(definitions.SessionKeyRequireMFAPending)
        h.redirectToIdPEndpoint(ctx, mgr)
        return
    }

    // Nächste ausstehende Methode: ersten Eintrag abarbeiten, Rest zurückschreiben
    methods := strings.SplitN(pending, ",", 2)
    if len(methods) > 1 {
        mgr.Set(definitions.SessionKeyRequireMFAPending, methods[1])
    } else {
        mgr.Set(definitions.SessionKeyRequireMFAPending, "")
    }

    switch methods[0] {
    case "totp":
        ctx.Redirect(http.StatusFound, definitions.MFARoot+"/totp/register")
    case "webauthn":
        ctx.Redirect(http.StatusFound, definitions.MFARoot+"/webauthn/register")
    default:
        // Unbekannte Methode überspringen – Flow fortsetzen
        mgr.Delete(definitions.SessionKeyRequireMFAFlow)
        mgr.Delete(definitions.SessionKeyRequireMFAPending)
        h.redirectToIdPEndpoint(ctx, mgr)
    }
}
```

> **Hinweis zur Pending-Liste-Logik:**
> Das Entfernen aus der Liste und der Redirect zu `continue` überschneiden sich im Verhalten.
> Beim ersten Aufruf von `continue` leitet er zur nächsten *verbleibenden* Methode weiter.
> Erst wenn `pending` leer ist, wird `redirectToIdPEndpoint()` aufgerufen. So kann der Handler
> idempotent und einfach gehalten werden.

#### 3.7 Neue Route: `GET /mfa/register/cancel`

**Handler `CancelRequiredMFARegistration()`:**

```go
func (h *FrontendHandler) CancelRequiredMFARegistration(ctx *gin.Context) {
    mgr := cookie.GetManager(ctx)

    if mgr != nil {
        // Forced-Flow-State entfernen
        mgr.Delete(definitions.SessionKeyRequireMFAFlow)
        mgr.Delete(definitions.SessionKeyRequireMFAPending)

        // Gesamten IdP-Flow-State entfernen
        CleanupIdPFlowState(mgr)

        // Benutzer ausloggen
        mgr.Delete(definitions.SessionKeyAccount)
        mgr.Delete(definitions.SessionKeyUniqueUserID)
        mgr.Delete(definitions.SessionKeyDisplayName)
        mgr.Delete(definitions.SessionKeySubject)
        mgr.Delete(definitions.SessionKeyMFACompleted)
    }

    ctx.Redirect(http.StatusFound, "/logged_out")
}
```

> **Warum ausloggen?**
> Ohne Ausloggen würde der nächste Authorize-Request den Benutzer als bereits angemeldet
> erkennen, direkt `redirectToIdPEndpoint()` aufrufen, und `checkRequiredMFARegistration()`
> würde sofort wieder die Registrierungspflicht auslösen – Endlosschleife.
> Der Benutzer muss also sauber ausgeloggt werden.
>
> **Bereits abgeschlossene Registrierungen bleiben erhalten** – z.B. wenn TOTP bereits
> registriert wurde und der Benutzer danach beim WebAuthn abbricht, bleibt das TOTP im
> Backend gespeichert. Beim nächsten Login muss dann nur noch WebAuthn registriert werden.

#### 3.8 Anpassung: `CleanupIdPFlowState()` (in `oidc.go`)

Die neuen Keys werden zum Cleanup hinzugefügt, damit sie auch bei normalem Flow-Abschluss
sauber entfernt werden:

```go
func CleanupIdPFlowState(mgr cookie.Manager) {
    if mgr == nil {
        return
    }

    // ... bestehende Deletes ...

    // Forced-MFA-Registration-Flow-Keys
    mgr.Delete(definitions.SessionKeyRequireMFAFlow)
    mgr.Delete(definitions.SessionKeyRequireMFAPending)
}
```

#### 3.9 Routen-Registrierung (in `SetupRoutes()`)

In der `authGroup`:

```go
authGroup.GET("/register/continue", h.ContinueRequiredMFARegistration)
authGroup.GET("/register/continue/:languageTag", h.ContinueRequiredMFARegistration)
authGroup.GET("/register/cancel", h.CancelRequiredMFARegistration)
authGroup.GET("/register/cancel/:languageTag", h.CancelRequiredMFARegistration)
```

Beide Routen liegen in der `authGroup` und nutzen die bestehende `AuthMiddleware()` (Session-Prüfung).

---

## 4. Templates

### 4.1 `static/templates/idp_totp_register.html`

Cancel-Button und ein neuer Hinweistext für den Forced-Flow werden hinzugefügt:

```html
{{if .RequireMFAFlow}}
<div class="alert alert-info mb-6">
    <span>{{ .RequireMFAMessage }}</span>
</div>
{{end}}

<!-- ... bestehender Inhalt ... -->

{{if .RequireMFAFlow}}
<div class="form-control mt-3">
    <a class="btn btn-ghost" href="/mfa/register/cancel">{{ .Cancel }}</a>
</div>
{{end}}
```

### 4.2 `static/templates/idp_webauthn_register.html`

Cancel-Button (analog zu TOTP), **plus** Änderung der JavaScript-Redirect-URL nach erfolgreicher
Registrierung:

```html
{{if .RequireMFAFlow}}
<div class="alert alert-info mb-6">
    <span>{{ .RequireMFAMessage }}</span>
</div>
{{end}}

<!-- ... bestehender Button ... -->

{{if .RequireMFAFlow}}
<div class="form-control mt-3">
    <a class="btn btn-ghost" href="/mfa/register/cancel">{{ .Cancel }}</a>
</div>
{{end}}
```

Im JavaScript-Block – die bisherige Zeile:

```javascript
// War:
window.location.href = "/mfa/register/home";
```

wird ersetzt durch:

```javascript
// Neu:
window.location.href = {{if .RequireMFAFlow}}"/mfa/register/continue"{{else}}"/mfa/register/home"{{end}};
```

### 4.3 Template-Variablen aus den Handlern

`RegisterTOTP()` und `RegisterWebAuthn()` müssen die neuen Variablen befüllen:

```go
data["RequireMFAFlow"] = mgr != nil && mgr.GetBool(definitions.SessionKeyRequireMFAFlow, false)
data["RequireMFAMessage"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger,
    "You must set up this authentication method to continue")
data["Cancel"] = frontend.GetLocalized(ctx, h.deps.Cfg, h.deps.Logger, "Cancel")
```

---

## 5. Vollständiger Flow (Gesamtübersicht)

```
Client → /oidc/authorize (oder /saml/sso)
  │
  ↓ (User nicht eingeloggt)
/login → POST /login (Username + Password)
  │
  ↓ (Auth OK)
Existierendes MFA vorhanden?
  ├─ Ja → /login/totp oder /login/webauthn (Verifikation)
  └─ Nein → direkt weiter
  │
  ↓
finalizeMFALogin()
  │
  ↓
checkRequiredMFARegistration()
  ├─ require_mfa leer oder alle Methoden bereits vorhanden
  │     └─ redirectToIdPEndpoint() → normaler Flow (Consent → Code → Client)
  │
  └─ Methoden fehlen (z.B. totp, webauthn):
        SessionKeyRequireMFAFlow = true
        SessionKeyRequireMFAPending = "totp,webauthn"
        │
        ↓ Redirect
        /mfa/totp/register
          │  User scannt QR, gibt Code ein
          ↓ POST /mfa/totp/register (HTMX)
          HX-Redirect → /mfa/register/continue
          │
          ↓ GET /mfa/register/continue
          pending = "webauthn" → Redirect
          │
          ↓
          /mfa/webauthn/register
            │  User registriert Security Key
            ↓ POST /mfa/webauthn/register/finish (JSON)
            JS: window.location.href = "/mfa/register/continue"
            │
            ↓ GET /mfa/register/continue
            pending = "" → Cleanup → redirectToIdPEndpoint()
            │
            ↓
          /oidc/authorize → Consent? → Authorization Code → Client
```

### Cancel-Pfad

```
/mfa/totp/register  (oder /mfa/webauthn/register)
  │  User klickt "Abbrechen"
  ↓
/mfa/register/cancel
  ├─ Löscht: SessionKeyRequireMFAFlow, SessionKeyRequireMFAPending
  ├─ Löscht: IdP-Flow-State (CleanupIdPFlowState)
  └─ Löscht: Account, UniqueUserID, DisplayName, Subject (= Logout)
  │
  ↓
/logged_out  (bestehende Seite)
```

---

## 6. Neue Hilfsfunktion: `removeFromMFAPendingList()`

Kleine Utility-Funktion zum Entfernen eines Eintrags aus der komma-separierten Pending-Liste:

```go
func removeFromMFAPendingList(pending, method string) string {
    if pending == "" {
        return ""
    }

    parts := strings.Split(pending, ",")
    var remaining []string

    for _, p := range parts {
        if strings.TrimSpace(p) != method {
            remaining = append(remaining, p)
        }
    }

    return strings.Join(remaining, ",")
}
```

---

## 7. Zusammenfassung der Änderungen

| Datei | Art der Änderung |
|-------|-----------------|
| `server/config/idp.go` | `RequireMFA []string` zu `OIDCClient` und `SAML2ServiceProvider` + Getter |
| `server/definitions/const.go` | 2 neue `SessionKey*`-Konstanten |
| `server/handler/frontend/idp/frontend.go` | Eingriffspunkt in `finalizeMFALogin`, 5 neue Funktionen/Handler, Anpassungen an `PostRegisterTOTP`, `RegisterTOTP`, `RegisterWebAuthn`, 2 neue Routen |
| `server/handler/frontend/idp/oidc.go` | `CleanupIdPFlowState` um 2 Keys erweitert |
| `static/templates/idp_totp_register.html` | Cancel-Button + Hinweistext |
| `static/templates/idp_webauthn_register.html` | Cancel-Button + Hinweistext + JS-Redirect-Logik |

---

## 8. Offene Punkte / Designentscheidungen

### 8.1 Reihenfolge der Methoden

Die Reihenfolge der Registrierung folgt der Reihenfolge in der `require_mfa`-Liste in der Config.
Wer also `[webauthn, totp]` konfiguriert, bekommt zuerst WebAuthn, dann TOTP.

### 8.2 Validation der `require_mfa`-Werte

Es empfiehlt sich, in der Config-Validierung zu prüfen, dass nur `totp` und `webauthn` als Werte
erlaubt sind (z.B. via `validate:"omitempty,dive,oneof=totp webauthn"`).

### 8.3 Recovery Codes

Recovery Codes sind bewusst **nicht** in `require_mfa` aufgenommen. Sie setzen voraus, dass
mindestens TOTP oder WebAuthn bereits vorhanden ist, und sind kein eigenständiger Anmeldefaktor.
Sie könnten als separates Feature (`require_recovery_codes`) ergänzt werden.

### 8.4 Verhalten bei Self-Service-Aufruf der Registrierungsseiten

`RegisterTOTP()` prüft bereits `SessionKeyHaveTOTP` und leitet bei vorhandenem TOTP zu
`/mfa/register/home` weiter. Dieses Verhalten bleibt unverändert – es greift aber nur im
Self-Service-Kontext (kein aktiver `RequireMFAFlow`). Im Forced-Flow darf die Seite auch dann
angezeigt werden, wenn TOTP bereits existiert... Nein: Im Forced-Flow ist TOTP nur dann in der
Pending-Liste, wenn es **noch nicht** vorhanden ist. Die Prüfung in
`checkRequiredMFARegistration()` schließt vorhandene Methoden bereits aus.
