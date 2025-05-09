# Nauthilus Workshop

## Einführung in Nauthilus

Nauthilus ist eine universelle Authentifizierungs- und Autorisierungsplattform, die in Go geschrieben wurde. Sie dient als zentrale Anlaufstelle für verschiedene Authentifizierungsanfragen, beispielsweise von Mailservern oder Webseiten. Nauthilus bietet eine flexible und erweiterbare Architektur, die es ermöglicht, verschiedene Backends für die Authentifizierung zu nutzen und das Verhalten durch Lua-Skripte anzupassen.

### Hauptmerkmale

- **Universelle Authentifizierung**: Unterstützt verschiedene Protokolle und Dienste
- **Flexible Backend-Anbindung**: LDAP, Datenbanken, und benutzerdefinierte Lua-Backends
- **Erweiterbarkeit durch Lua**: Features und Filter können in Lua implementiert werden
- **Monitoring und Metriken**: Integration mit Prometheus und Grafana
- **Brute-Force-Erkennung**: Schutz vor Brute-Force-Angriffen
- **Geolokalisierung**: Filterung basierend auf geografischem Standort
- **Hochverfügbarkeit**: Unterstützung für Clustering und Load-Balancing

### Architektur von Nauthilus

Nauthilus besteht aus mehreren Komponenten, die zusammenarbeiten, um eine flexible und erweiterbare Authentifizierungsplattform zu bilden:

1. **HTTP-Server**: Empfängt Authentifizierungsanfragen über HTTP/HTTPS
2. **Backend-Systeme**: Verbinden sich mit verschiedenen Authentifizierungsquellen (LDAP, Datenbanken, etc.)
3. **Lua-Skript-Engine**: Ermöglicht die Erweiterung und Anpassung des Verhaltens
   - **Features**: Erweitern die Funktionalität während der Anfrageverarbeitung
   - **Filter**: Validieren Anfragen nach der Backend-Verarbeitung
   - **Post-Actions**: Führen asynchrone Aktionen nach Abschluss der Hauptverarbeitung aus
   - **Custom Hooks**: Ermöglichen benutzerdefinierte HTTP-Endpunkte mit eigener Logik
4. **Redis-Cache**: Speichert Sitzungsinformationen und Zwischenergebnisse
5. **Monitoring-System**: Sammelt Metriken und ermöglicht die Überwachung

Die Architektur folgt einem modularen Ansatz, bei dem verschiedene Komponenten unabhängig voneinander entwickelt und konfiguriert werden können:

```
+----------------+     +----------------+     +----------------+
|                |     |                |     |                |
| Mailserver     |     | Webserver      |     | Andere Dienste |
| (Postfix,      |     | (Nginx,        |     |                |
|  Dovecot)      |     |  Apache)       |     |                |
|                |     |                |     |                |
+-------+--------+     +-------+--------+     +-------+--------+
        |                      |                      |
        v                      v                      v
+---------------------------------------------------------------+
|                                                               |
|                      HTTP/HTTPS API                           |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                         Nauthilus                             |
|                                                               |
|  +---------------+    +---------------+    +---------------+  |
|  |               |    |               |    |               |  |
|  | Lua Features  |    | Lua Filter    |    | Lua Backends  |  |
|  |               |    |               |    |               |  |
|  +---------------+    +---------------+    +---------------+  |
|                                                               |
|  +---------------+    +---------------+                       |
|  |               |    |               |                       |
|  | Post-Actions  |    | Custom Hooks  |                       |
|  |               |    |               |                       |
|  +---------------+    +---------------+                       |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                       Redis Cache                             |
|                                                               |
+---------------------------------------------------------------+
        |                      |                      |
        v                      v                      v
+----------------+     +----------------+     +----------------+
|                |     |                |     |                |
| LDAP Server    |     | Datenbank      |     | Externe APIs   |
|                |     |                |     |                |
+----------------+     +----------------+     +----------------+
```

### Anfrageverarbeitung

Wenn eine Authentifizierungsanfrage bei Nauthilus eingeht, durchläuft sie mehrere Verarbeitungsschritte:

1. **Empfang der Anfrage**: Die Anfrage wird über HTTP/HTTPS empfangen
2. **Feature-Verarbeitung**: Lua-Features werden ausgeführt, um zusätzliche Funktionalität bereitzustellen
3. **Backend-Verarbeitung**: Die Anfrage wird an das konfigurierte Backend weitergeleitet
4. **Filter-Verarbeitung**: Lua-Filter werden angewendet, um die Anfrage zu validieren
5. **Antwort-Generierung**: Eine Antwort wird generiert und zurückgesendet
6. **Post-Actions**: Nach Abschluss der Hauptverarbeitung werden asynchrone Aktionen ausgeführt

Die Post-Actions werden asynchron ausgeführt, nachdem die Antwort bereits an den Client gesendet wurde. Sie können für verschiedene Zwecke verwendet werden, wie z.B.:

- Logging von Authentifizierungsversuchen
- Benachrichtigungen über erfolgreiche oder fehlgeschlagene Anmeldeversuche
- Aktualisierung von Statistiken oder Metriken
- Integration mit externen Systemen

Neben der regulären Anfrageverarbeitung bietet Nauthilus auch **Custom Hooks**, die es ermöglichen, benutzerdefinierte HTTP-Endpunkte mit eigener Logik zu erstellen. Diese Hooks werden über spezielle URLs aufgerufen und können für verschiedene Zwecke verwendet werden, wie z.B.:

- Bereitstellung von benutzerdefinierten APIs
- Integration mit anderen Systemen
- Implementierung von speziellen Funktionen, die nicht Teil des Standardauthentifizierungsprozesses sind

Diese Verarbeitungskette ermöglicht eine flexible Anpassung des Authentifizierungsprozesses an spezifische Anforderungen.

## Installation und Einrichtung

### Voraussetzungen

- Go 1.24.x oder höher
- Redis (für Caching und Session-Management)
- Optional: MySQL/MariaDB (für Datenbankbackend)
- Optional: LDAP-Server (für LDAP-Backend)

### Installation

#### Über Docker

Die einfachste Methode, Nauthilus zu installieren, ist über Docker:

```bash
docker pull ghcr.io/croessner/nauthilus:latest
```

Starten Sie den Container mit:

```bash
docker run -d --name nauthilus \
  -p 8080:8080 \
  -v /path/to/config:/etc/nauthilus \
  ghcr.io/croessner/nauthilus:latest
```

#### Docker Compose

Für eine komplexere Umgebung mit Redis können Sie Docker Compose verwenden:

```yaml
version: '3'

services:
  nauthilus:
    image: ghcr.io/croessner/nauthilus:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/nauthilus
      - ./lua-plugins.d:/etc/nauthilus/lua-plugins.d
    environment:
      - TZ=Europe/Berlin
      - NAUTHILUS_EXPERIMENTAL_ML=true
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

Speichern Sie diese Konfiguration in einer Datei namens `docker-compose.yml` und starten Sie die Dienste mit:

```bash
docker-compose up -d
```

#### Manuelle Installation

1. Klonen Sie das Repository:

```bash
git clone https://github.com/croessner/nauthilus.git
cd nauthilus
```

2. Kompilieren Sie das Projekt:

```bash
make build
```

3. Installieren Sie die Binärdatei:

```bash
sudo make install
```

### Konfiguration

Die Hauptkonfigurationsdatei befindet sich unter `/etc/nauthilus/nauthilus.yml`. Hier ein Beispiel für eine grundlegende Konfiguration:

```yaml
server:
  address: "0.0.0.0:8080"
  instance_name: "nauthilus"
  log:
    level: "info"
    json: true
  backends: [ cache, ldap, lua ]
  features: [ brute_force, tls_encryption, rbl, relay_domains, lua ]

redis:
  master:
    address: "localhost:6379"
  database_number: 0
  prefix: nt_
  pool_size: 10
  positive_cache_ttl: 3600
  negative_cache_ttl: 7200

ldap:
  config:
    number_of_workers: 100
    lookup_pool_size: 4
    lookup_idle_pool_size: 1
    auth_pool_size: 4
    auth_idle_pool_size: 2
    server_uri: "ldaps://ldap.example.com:636/"
    tls_skip_verify: true
    bind_dn: "cn=nauthilus,ou=services,dc=example,dc=com"
    bind_pw: "geheim"
```

### Erweiterte Konfigurationsoptionen

#### TLS-Konfiguration

Für eine sichere Kommunikation können Sie TLS aktivieren:

```yaml
server:
  tls:
    enabled: true
    cert_file: "/etc/nauthilus/ssl/certs/tls.crt"
    key_file: "/etc/nauthilus/ssl/private/tls.key"
    http_client_skip_verify: true
```

#### Brute-Force-Erkennung

Nauthilus bietet Schutz vor Brute-Force-Angriffen:

```yaml
brute_force:
  ip_whitelist:
    - 127.0.0.0/8
    - ::1
    - 192.168.0.0/16
    - 172.16.0.0/12
    - 10.0.0.0/8
    - fd00::/8
    - 169.254.0.0/16
    - fe80::/10

  neural_network:
    max_training_records: 30000
    hidden_neurons: 20
    activation_function: relu

  tolerate_percent: 3
  tolerate_ttl: 30m

  buckets:
    - { name: b_1m_ipv4_32,  period: 1m,   cidr: 32, ipv4: true, failed_requests: 10 }
    - { name: b_1h_ipv4_24,  period: 1h,   cidr: 24, ipv4: true, failed_requests: 15 }
    - { name: b_1d_ipv4_24,  period: 24h,  cidr: 24, ipv4: true, failed_requests: 25 }
    - { name: b_1w_ipv4_24,  period: 168h, cidr: 24, ipv4: true, failed_requests: 40 }

    - { name: b_1m_ipv6_128, period: 1m,   cidr: 128, ipv6: true, failed_requests: 10 }
    - { name: b_1h_ipv6_64,  period: 1h,   cidr: 64,  ipv6: true, failed_requests: 15 }
    - { name: b_1d_ipv6_64,  period: 24h,  cidr: 64,  ipv6: true, failed_requests: 25 }
    - { name: b_1w_ipv6_64,  period: 168h, cidr: 64,  ipv6: true, failed_requests: 40 }
```

> **Hinweis:** Die Nutzung des neuronalen Netzwerks zur Brute-Force-Erkennung erfordert, dass die Umgebungsvariable `NAUTHILUS_EXPERIMENTAL_ML` auf `true` gesetzt ist.

#### Mehrere LDAP-Pools

Sie können mehrere LDAP-Pools für verschiedene Domänen konfigurieren:

```yaml
ldap:
  config:
    number_of_workers: 100
    lookup_pool_size: 4
    lookup_idle_pool_size: 1
    auth_pool_size: 4
    auth_idle_pool_size: 2
    server_uri: "ldaps://ldap.example.com:636/"
    tls_skip_verify: true
    bind_dn: "cn=nauthilus,ou=services,dc=example,dc=com"
    bind_pw: "geheim"

  optional_ldap_pools:
    mail:
      number_of_workers: 100
      lookup_pool_size: 8
      lookup_idle_pool_size: 4
      auth_pool_size: 16
      auth_idle_pool_size: 5
      server_uri: "ldaps://ldap.mail.example.com:636/"
      tls_skip_verify: true
      sasl_external: false
      tls_ca_cert: "/etc/nauthilus/ssl/certs/ca.crt"
      bind_dn: "cn=authserv,ou=people,ou=it,dc=example,dc=com"
      bind_pw: "geheim2"

  search:
    - protocol: [ default, http ]
      cache_name: http
      base_dn: "ou=people,ou=it,dc=example,dc=com"
      filter:
        user: |
          (|
            (uniqueIdentifier=%L{user})
            (mail=%L{user})
          )
      mapping:
        account_field: mail
      attribute: mail
```

### Fehlerbehebung bei der Installation

#### Redis-Verbindungsprobleme

Wenn Nauthilus keine Verbindung zu Redis herstellen kann, überprüfen Sie:

1. Ob Redis läuft: `redis-cli ping` sollte `PONG` zurückgeben
2. Die Redis-Konfiguration in `nauthilus.yml`
3. Firewall-Einstellungen, die den Zugriff auf Redis blockieren könnten

#### LDAP-Verbindungsprobleme

Bei Problemen mit der LDAP-Verbindung:

1. Testen Sie die LDAP-Verbindung mit `ldapsearch`
2. Überprüfen Sie die LDAP-Konfiguration in `nauthilus.yml`
3. Stellen Sie sicher, dass der LDAP-Server erreichbar ist
4. Überprüfen Sie die Bind-DN und das Passwort

#### Logging-Probleme

Wenn Sie Probleme mit dem Logging haben:

1. Setzen Sie das Log-Level auf `debug` für detailliertere Informationen
2. Überprüfen Sie die Berechtigungen des Log-Verzeichnisses
3. Stellen Sie sicher, dass genügend Speicherplatz vorhanden ist

## Lua-Backends

Nauthilus ermöglicht die Implementierung von benutzerdefinierten Authentifizierungsbackends in Lua. Diese Backends können mit verschiedenen Datenquellen interagieren, wie z.B. Datenbanken oder APIs.

### Grundlegende Konzepte

Ein Lua-Backend besteht aus mindestens einer der folgenden Funktionen:

- `nauthilus_backend_verify_password(request)`: Überprüft Benutzeranmeldedaten
- `nauthilus_backend_list_accounts()`: Listet verfügbare Konten auf

### Beispiel: MySQL-Backend

Hier ist ein einfaches Beispiel für ein MySQL-Backend:

```lua
local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_password")
local nauthilus_password = require("nauthilus_password")

dynamic_loader("nauthilus_gll_db")
local db = require("db")

local config = {
    shared = true,
    max_connections = 100,
    read_only = false,
}

function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local mysql, err_open = db.open("mysql", "benutzer:passwort@tcp(127.0.0.1)/datenbank", config)
    nauthilus_util.if_error_raise(err_open)

    local result, err_query = mysql:query(
        "SELECT account, password FROM benutzer WHERE username = \"" .. request.username .. "\";"
    )
    nauthilus_util.if_error_raise(err_query)

    local attributes = {}

    for _, row in pairs(result.rows) do
        for id, name in pairs(result.columns) do
            if name == "password" then
                if not request.no_auth then
                    local match, err = nauthilus_password.compare_passwords(row[id], request.password)
                    nauthilus_util.if_error_raise(err)

                    b:authenticated(match)
                end
            else
                if name == "account" then
                    b:account_field("account")
                    b:user_found(true)
                end

                attributes[name] = row[id]
            end
        end
    end

    b:attributes(attributes)

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end
```

Dieses Skript definiert eine Funktion `nauthilus_backend_verify_password`, die eine Benutzeranfrage entgegennimmt, eine Datenbankabfrage durchführt und das Ergebnis zurückgibt. Es überprüft das Passwort und setzt verschiedene Attribute im Ergebnisobjekt.

### Erweitertes Beispiel: Backend mit zusätzlichen Attributen

Hier ist ein erweitertes Beispiel, das zusätzliche Benutzerattribute verarbeitet:

```lua
function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local mysql, err_open = db.open("mysql", "benutzer:passwort@tcp(127.0.0.1)/datenbank", config)
    nauthilus_util.if_error_raise(err_open)

    local result, err_query = mysql:query(
        "SELECT account, password, uniqueid, display_name FROM benutzer WHERE username = \"" .. request.username .. "\" OR account = \"" .. request.username .. "\";"
    )
    nauthilus_util.if_error_raise(err_query)

    local attributes = {}

    for _, row in pairs(result.rows) do
        for id, name in pairs(result.columns) do
            if name == "password" then
                if not request.no_auth then
                    local match, err = nauthilus_password.compare_passwords(row[id], request.password)
                    nauthilus_util.if_error_raise(err)

                    b:authenticated(match)
                end
            else
                if name == "account" then
                    b:account_field("account")
                    b:user_found(true)
                end

                if name == "uniqueid" and row[id] ~= "" then
                    b:unique_user_id_field("uniqueid")
                end

                if name == "display_name" and row[id] ~= "" then
                    b:display_name_field("display_name")
                end

                attributes[name] = row[id]
            end
        end
    end

    b:attributes(attributes)

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end
```

### Verfügbare Funktionen im Backend-Kontext

Im Backend-Kontext stehen verschiedene Funktionen und Objekte zur Verfügung:

#### nauthilus_backend_result

Das `nauthilus_backend_result`-Objekt bietet Methoden zum Setzen von Ergebnisattributen:

- `new()`: Erstellt ein neues Ergebnisobjekt
- `authenticated(bool)`: Setzt den Authentifizierungsstatus
- `user_found(bool)`: Gibt an, ob der Benutzer gefunden wurde
- `account_field(string)`: Setzt das Feld für den Kontonamen
- `unique_user_id_field(string)`: Setzt das Feld für die eindeutige Benutzer-ID
- `display_name_field(string)`: Setzt das Feld für den Anzeigenamen
- `attributes(table)`: Setzt zusätzliche Attribute

#### request-Objekt

Das `request`-Objekt enthält Informationen über die Authentifizierungsanfrage:

- `username`: Der Benutzername aus der Anfrage
- `password`: Das Passwort aus der Anfrage
- `protocol`: Das verwendete Protokoll (z.B. "dovecot", "nginx")
- `client_ip`: Die IP-Adresse des Clients
- `no_auth`: Flag, das angibt, ob eine Authentifizierung erforderlich ist

### Einrichtung eines Lua-Backends

1. Erstellen Sie ein Verzeichnis für Ihr Backend:

```bash
mkdir -p /etc/nauthilus/lua-plugins.d/backend
```

2. Erstellen Sie Ihre Backend-Datei, z.B. `mysql.lua`:

```bash
vim /etc/nauthilus/lua-plugins.d/backend/mysql.lua
```

3. Fügen Sie Ihren Lua-Code ein und speichern Sie die Datei.

4. Aktualisieren Sie Ihre Nauthilus-Konfiguration, um das Lua-Backend zu aktivieren:

```yaml
server:
  backends:
    - lua
```

### Übung: Einfaches Lua-Backend erstellen

In dieser Übung erstellen wir ein einfaches Lua-Backend, das Benutzer gegen eine hartcodierte Liste authentifiziert.

1. Erstellen Sie eine Datei `/etc/nauthilus/lua-plugins.d/backend/simple.lua`:

```lua
local nauthilus_util = require("nauthilus_util")

-- Hartcodierte Benutzerliste (in der Praxis würde man eine Datenbank verwenden)
local users = {
    ["user1"] = {password = "password1", account = "user1@example.com"},
    ["user2"] = {password = "password2", account = "user2@example.com"}
}

function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local user = users[request.username]

    if user then
        b:user_found(true)
        b:account_field("account")

        if not request.no_auth then
            b:authenticated(user.password == request.password)
        end

        b:attributes({account = user.account})
    else
        b:user_found(false)
        b:authenticated(false)
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end

function nauthilus_backend_list_accounts()
    local accounts = {}

    for _, user in pairs(users) do
        table.insert(accounts, user.account)
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, accounts
end
```

2. Aktualisieren Sie Ihre Nauthilus-Konfiguration:

```yaml
server:
  backends:
    - lua
```

3. Starten Sie Nauthilus neu:

```bash
# Wenn Sie Docker Compose verwenden:
docker-compose restart nauthilus

# Wenn Sie Docker direkt verwenden:
docker restart nauthilus
```

4. Testen Sie die Authentifizierung:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"127.0.0.1","service":"http"}' http://localhost:8080/api/v1/auth/json
```

## Lua-Filter

Filter in Nauthilus werden verwendet, um Authentifizierungsanfragen zu verarbeiten und zu entscheiden, ob sie akzeptiert oder abgelehnt werden sollen. Filter können in Lua implementiert werden, um benutzerdefinierte Logik hinzuzufügen.

### Grundlegende Konzepte

Ein Lua-Filter besteht aus einer Funktion `nauthilus_call_filter(request)`, die eine Anfrage entgegennimmt und entscheidet, ob sie akzeptiert oder abgelehnt werden soll. Die Funktion gibt zwei Werte zurück:

1. Eine Entscheidung: `FILTER_ACCEPT` oder `FILTER_REJECT`
2. Ein Ergebnis: `FILTER_RESULT_OK` oder `FILTER_RESULT_FAIL`

### Beispiel: Einfacher Filter

Hier ist ein einfaches Beispiel für einen Filter, der Anfragen basierend auf der IP-Adresse filtert:

```lua
function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Überprüfen, ob die IP routbar ist
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    -- Frühzeitige Beendigung für nicht routbare Adressen
    if not is_routable then
        if request.authenticated then
            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
        else
            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    -- Hier könnte weitere Filterlogik stehen

    -- Die Anfrage sollte nur akzeptiert werden, wenn sie authentifiziert wurde
    if request.authenticated then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    else
        return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
    end
end
```

Dieser Filter überprüft, ob die IP-Adresse des Clients routbar ist, und entscheidet entsprechend, ob die Anfrage akzeptiert oder abgelehnt werden soll.

### Erweitertes Beispiel: Geolokalisierungsfilter

Hier ist ein erweitertes Beispiel für einen Filter, der Anfragen basierend auf dem geografischen Standort filtert:

```lua
function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Überprüfen, ob die IP routbar ist
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    -- Frühzeitige Beendigung für nicht routbare Adressen
    if not is_routable then
        if request.authenticated then
            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
        else
            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    if request.authenticated then
        dynamic_loader("nauthilus_gluahttp")
        local http = require("glua_http")

        dynamic_loader("nauthilus_gll_json")
        local json = require("json")

        local t = {}

        t.key = "client"
        t.value = {
            address = request.client_ip,
            sender = request.account
        }

        local payload, json_encode_err = json.encode(t)
        nauthilus_util.if_error_raise(json_encode_err)

        -- Senden einer Anfrage an einen Geolokalisierungsdienst
        local result, request_err = http.post("https://geoip.example.com/check", {
            timeout = "10s",
            headers = {
                Accept = "*/*",
                ["User-Agent"] = "Nauthilus",
                ["Content-Type"] = "application/json",
            },
            body = payload,
        })
        nauthilus_util.if_error_raise(request_err)

        local response, err_jdec = json.decode(result.body)
        nauthilus_util.if_error_raise(err_jdec)

        -- Überprüfen, ob das Land auf der Blockliste steht
        if response.country_code and response.country_code == "XY" then
            nauthilus_builtin.custom_log_add("geoip_blocked_country", response.country_code)
            nauthilus_builtin.status_message_set("Zugriff aus diesem Land nicht erlaubt")

            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    else
        -- Nicht authentifizierte Anfragen ablehnen
        return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Die Anfrage sollte akzeptiert werden
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
```

Dieser Filter sendet eine Anfrage an einen Geolokalisierungsdienst, um den Standort des Clients zu ermitteln, und lehnt Anfragen aus bestimmten Ländern ab.

### Verfügbare Funktionen im Filter-Kontext

Im Filter-Kontext stehen verschiedene Funktionen und Objekte zur Verfügung:

#### nauthilus_builtin

Das `nauthilus_builtin`-Objekt bietet Konstanten und Funktionen für Filter:

- `FILTER_ACCEPT`: Konstante für die Akzeptanz einer Anfrage
- `FILTER_REJECT`: Konstante für die Ablehnung einer Anfrage
- `FILTER_RESULT_OK`: Konstante für ein erfolgreiches Filterergebnis
- `FILTER_RESULT_FAIL`: Konstante für ein fehlgeschlagenes Filterergebnis
- `custom_log_add(key, value)`: Fügt einen benutzerdefinierten Logeintrag hinzu
- `status_message_set(message)`: Setzt eine Statusmeldung

#### request-Objekt

Das `request`-Objekt enthält Informationen über die Authentifizierungsanfrage:

- `username`: Der Benutzername aus der Anfrage
- `account`: Das authentifizierte Konto (nach erfolgreicher Authentifizierung)
- `authenticated`: Flag, das angibt, ob die Anfrage authentifiziert wurde
- `protocol`: Das verwendete Protokoll (z.B. "dovecot", "nginx")
- `client_ip`: Die IP-Adresse des Clients
- `no_auth`: Flag, das angibt, ob eine Authentifizierung erforderlich ist
- `session`: Die Sitzungs-ID (falls vorhanden)
- `user_agent`: Der User-Agent des Clients (falls vorhanden)
- `client_id`: Die Client-ID (falls vorhanden)
- `debug`: Flag, das angibt, ob der Debug-Modus aktiviert ist
- `log_format`: Das Format für Logausgaben

### Einrichtung eines Lua-Filters

1. Erstellen Sie ein Verzeichnis für Ihren Filter:

```bash
mkdir -p /etc/nauthilus/lua-plugins.d/filters
```

2. Erstellen Sie Ihre Filter-Datei, z.B. `ip_filter.lua`:

```bash
vim /etc/nauthilus/lua-plugins.d/filters/ip_filter.lua
```

3. Fügen Sie Ihren Lua-Code ein und speichern Sie die Datei.

4. Aktualisieren Sie Ihre Nauthilus-Konfiguration, um den Lua-Filter zu aktivieren:

```yaml
lua:
  filters:
    - name: "ip_filter"
      path: "/etc/nauthilus/lua-plugins.d/filters/ip_filter.lua"
```

### Übung: Einfachen IP-Filter erstellen

In dieser Übung erstellen wir einen einfachen Filter, der Anfragen von bestimmten IP-Adressen blockiert.

1. Erstellen Sie eine Datei `/etc/nauthilus/lua-plugins.d/filters/ip_blocklist.lua`:

```lua
function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Liste der blockierten IP-Adressen
    local blocked_ips = {
        "192.168.1.100",
        "10.0.0.50"
    }

    -- Überprüfen, ob die Client-IP in der Blockliste ist
    for _, ip in ipairs(blocked_ips) do
        if request.client_ip == ip then
            nauthilus_builtin.custom_log_add("blocked_ip", request.client_ip)
            nauthilus_builtin.status_message_set("IP-Adresse blockiert")

            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    -- Die Anfrage sollte akzeptiert werden
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
```

2. Aktualisieren Sie Ihre Nauthilus-Konfiguration:

```yaml
lua:
  filters:
    - name: "ip_blocklist"
      path: "/etc/nauthilus/lua-plugins.d/filters/ip_blocklist.lua"
```

3. Starten Sie Nauthilus neu:

```bash
# Wenn Sie Docker Compose verwenden:
docker-compose restart nauthilus

# Wenn Sie Docker direkt verwenden:
docker restart nauthilus
```

4. Testen Sie den Filter:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"192.168.1.100","service":"http"}' http://localhost:8080/api/v1/auth/json
```

## Lua-Features

Features in Nauthilus sind Erweiterungen, die zusätzliche Funktionalität bieten. Sie können in Lua implementiert werden, um benutzerdefinierte Logik hinzuzufügen.

### Grundlegende Konzepte

Ein Lua-Feature besteht aus einer Funktion `nauthilus_call_feature(request)`, die eine Anfrage entgegennimmt und zusätzliche Funktionalität bereitstellt. Die Funktion gibt drei Werte zurück:

1. Ein Trigger-Flag: `FEATURE_TRIGGER_YES` oder `FEATURE_TRIGGER_NO`
2. Ein Abbruch-Flag: `FEATURES_ABORT_YES` oder `FEATURES_ABORT_NO`
3. Ein Ergebnis: `FEATURE_RESULT_OK` oder `FEATURE_RESULT_FAIL`

### Einrichtung eines Lua-Features

1. Erstellen Sie ein Verzeichnis für Ihr Feature:

```bash
mkdir -p /etc/nauthilus/lua-plugins.d/features
```

2. Erstellen Sie Ihre Feature-Datei, z.B. `blocklist.lua`:

```bash
vim /etc/nauthilus/lua-plugins.d/features/blocklist.lua
```

3. Fügen Sie Ihren Lua-Code ein und speichern Sie die Datei.

4. Aktualisieren Sie Ihre Nauthilus-Konfiguration, um das Lua-Feature zu aktivieren:

```yaml
lua:
  features:
    - name: "blocklist"
      path: "/etc/nauthilus/lua-plugins.d/features/blocklist.lua"
```

### Beispiel: Blocklist-Feature

Hier ist ein Beispiel für ein Feature, das überprüft, ob eine IP-Adresse auf einer Blocklist steht:

```lua
function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_gluahttp")
    local http = require("glua_http")

    dynamic_loader("nauthilus_gll_json")
    local json = require("json")

    local t = {}
    t.ip = request.client_ip

    local payload, json_encode_err = json.encode(t)
    nauthilus_util.if_error_raise(json_encode_err)

    local result, request_err = http.post("https://blocklist.example.com/check", {
        timeout = "10s",
        headers = {
            Accept = "*/*",
            ["User-Agent"] = "Nauthilus",
            ["Content-Type"] = "application/json",
        },
        body = payload,
    })
    nauthilus_util.if_error_raise(request_err)

    if result.status_code ~= 200 then
        nauthilus_util.if_error_raise("blocklist_status_code=" .. tostring(result.status_code))
    end

    local response, err_jdec = json.decode(result.body)
    nauthilus_util.if_error_raise(err_jdec)

    if response.found then
        nauthilus_builtin.custom_log_add("blocklist_ip", request.client_ip)
        nauthilus_builtin.status_message_set("IP-Adresse blockiert")

        return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_YES, nauthilus_builtin.FEATURE_RESULT_OK
    end

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
```

Dieses Feature sendet eine Anfrage an einen Blocklist-Dienst, um zu überprüfen, ob die IP-Adresse des Clients auf einer Blocklist steht. Wenn ja, wird die Anfrage abgelehnt.

### Erweitertes Beispiel: Neural Network Feature mit ipapi.com

> **Hinweis:** Für die Nutzung der neuronalen Netzwerkfunktionen muss die Umgebungsvariable `NAUTHILUS_EXPERIMENTAL_ML` auf `true` gesetzt sein. Ohne diese Einstellung werden die ML-Funktionen nicht initialisiert.

> **Hinweis zur API:** Für die Nutzung von ipapi.com benötigen Sie einen API-Key. Sie können sich kostenlos auf [ipapi.com](https://ipapi.com/) registrieren, um einen kostenlosen API-Key zu erhalten. Der kostenlose Plan bietet eine begrenzte Anzahl von Anfragen pro Monat, was für Testzwecke ausreichend ist.

> **Wichtig:** Dieses Beispiel verwendet Prometheus-Metriken, die in einer init.lua-Datei initialisiert werden müssen, bevor das Skript ausgeführt werden kann. Ohne diese Initialisierung wird das Skript mit einem Fehler fehlschlagen. Hier ist ein Beispiel für eine init.lua-Datei, die die benötigten Prometheus-Vektoren initialisiert:

```lua
-- init.lua
function nauthilus_run_hook(logging)
    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    -- Initialisierung des Gauge-Vektors für HTTP-Client-Anfragen
    nauthilus_prometheus.create_gauge_vec("http_client_concurrent_requests_total", "Measure the number of total concurrent HTTP client requests", { "service" })

    -- Initialisierung des Histogram-Vektors für ipapi-Anfragen
    nauthilus_prometheus.create_histogram_vec("ipapi_duration_seconds", "HTTP request to the ipapi service", { "http" })

    local result = {
        level = "info",
        caller = "init.lua",
        status = "finished"
    }

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end
end
```

Hier ist ein erweitertes Beispiel, das ipapi.com verwendet, um Geolokalisierungsdaten zu sammeln und diese für das neuronale Netzwerk zu normalisieren:

```lua
function nauthilus_call_neural_network(request)
    if request.no_auth then
        return
    end

    local nauthilus_util = require("nauthilus_util")

    -- Überprüfen, ob die IP routbar ist
    local is_routable = false

    if request.client_ip then
        is_routable = nauthilus_util.is_routable_ip(request.client_ip)
    end

    -- Frühzeitige Beendigung für nicht routbare Adressen
    if not is_routable then
        return
    end

    local logs = {}
    logs.caller = "ipapi.lua"
    logs.level = "info"

    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    dynamic_loader("nauthilus_gluahttp")
    local http = require("glua_http")

    dynamic_loader("nauthilus_gll_json")
    local json = require("json")

    -- Prometheus-Metriken für HTTP-Anfragen
    local HCCR = "http_client_concurrent_requests_total"
    nauthilus_prometheus.increment_gauge(HCCR, { service = "ipapi" })

    -- Anfrage an ipapi.com senden
    local timer = nauthilus_prometheus.start_histogram_timer("ipapi_duration_seconds", { http = "get" })
    local api_key = os.getenv("IPAPI_API_KEY") or "YOUR_API_KEY_HERE"
    local result, request_err = http.get("http://api.ipapi.com/api/" .. request.client_ip .. "?access_key=" .. api_key, {
        timeout = "5s",
        headers = {
            Accept = "*/*",
            ["User-Agent"] = "Nauthilus",
        }
    })

    nauthilus_prometheus.stop_timer(timer)
    nauthilus_prometheus.decrement_gauge(HCCR, { service = "ipapi" })
    nauthilus_util.if_error_raise(request_err)

    if result.status_code ~= 200 then
        nauthilus_util.if_error_raise("ipapi_status_code=" .. tostring(result.status_code))
    end

    local response, err_jdec = json.decode(result.body)
    nauthilus_util.if_error_raise(err_jdec)

    if response.error == nil then
        -- Extrahieren und Normalisieren der Daten für das neuronale Netzwerk
        local features = {}

        -- Land und Kontinent als kategorische Features
        features.country_code = response.country_code or "unknown"
        features.continent_code = response.continent_code or "unknown"

        -- Numerische Features normalisieren auf [0, 1]

        -- Breitengrad normalisieren: von [-90, 90] auf [0, 1]
        if response.latitude then
            features.latitude_normalized = (response.latitude + 90) / 180
        end

        -- Längengrad normalisieren: von [-180, 180] auf [0, 1]
        if response.longitude then
            features.longitude_normalized = (response.longitude + 180) / 360
        end

        -- Zeitzone normalisieren: von [-12, 14] auf [0, 1]
        if response.timezone and response.timezone.gmt_offset then
            features.timezone_normalized = (response.timezone.gmt_offset + 12) / 26
        end

        -- Sicherheitsbewertung (falls vorhanden) normalisieren: von [0, 100] auf [0, 1]
        if response.security and response.security.threat_score then
            features.threat_score_normalized = response.security.threat_score / 100
        end

        -- ASN-Nummer als kategorisches Feature
        if response.connection and response.connection.asn then
            features.asn = "AS" .. tostring(response.connection.asn)
        end

        -- Verbindungstyp als kategorisches Feature
        if response.connection and response.connection.type then
            features.connection_type = response.connection.type
        end

        -- Logs für Debugging
        for k, v in pairs(features) do
            logs[k] = v
            nauthilus_builtin.custom_log_add("ipapi_" .. k, tostring(v))
        end

        -- Ausgabe der Logs
        nauthilus_util.print_result({ log_format = "json" }, logs)

        -- Zum neuronalen Netzwerk hinzufügen
        dynamic_loader("nauthilus_neural")
        local nauthilus_neural = require("nauthilus_neural")
        nauthilus_neural.add_additional_features(features)
    end

    return
end
```

Dieses erweiterte Beispiel zeigt, wie man Daten von ipapi.com abruft und für das neuronale Netzwerk aufbereitet:

1. **Abrufen der Geolokalisierungsdaten**: Die Funktion sendet eine Anfrage an ipapi.com, um Informationen über die IP-Adresse des Clients zu erhalten.

2. **Normalisierung numerischer Werte**: Numerische Werte wie Breitengrad, Längengrad und Zeitzone werden auf den Bereich [0, 1] normalisiert, damit sie vom neuronalen Netzwerk effektiv verarbeitet werden können:
   - Breitengrad: von [-90, 90] auf [0, 1]
   - Längengrad: von [-180, 180] auf [0, 1]
   - Zeitzone: von [-12, 14] auf [0, 1]
   - Sicherheitsbewertung: von [0, 100] auf [0, 1]

3. **Kategorische Features**: Werte wie Ländercode, Kontinentcode, ASN-Nummer und Verbindungstyp werden als kategorische Features hinzugefügt. Diese werden vom neuronalen Netzwerk automatisch mittels One-Hot-Encoding verarbeitet.

4. **Logging und Metriken**: Die Funktion protokolliert alle extrahierten Features und misst die Dauer der API-Anfrage mit Prometheus-Metriken.

Die Normalisierung auf den Bereich [0, 1] ist wichtig, da neuronale Netzwerke am besten mit Eingabewerten in einem konsistenten Bereich arbeiten. Durch die Normalisierung wird sichergestellt, dass kein Feature aufgrund seiner Größenordnung überbewertet wird.


### Verfügbare Funktionen im Feature-Kontext (nauthilus_call_feature)

Die folgenden Funktionen und Objekte stehen nur im Kontext von Features zur Verfügung, die die Funktion `nauthilus_call_feature` implementieren:

#### nauthilus_builtin

Das `nauthilus_builtin`-Objekt bietet Konstanten und Funktionen für Features:

- `FEATURE_TRIGGER_YES`: Konstante für das Auslösen eines Features
- `FEATURE_TRIGGER_NO`: Konstante für das Nicht-Auslösen eines Features
- `FEATURES_ABORT_YES`: Konstante für den Abbruch der Feature-Verarbeitung
- `FEATURES_ABORT_NO`: Konstante für die Fortsetzung der Feature-Verarbeitung
- `FEATURE_RESULT_OK`: Konstante für ein erfolgreiches Feature-Ergebnis
- `FEATURE_RESULT_FAIL`: Konstante für ein fehlgeschlagenes Feature-Ergebnis
- `custom_log_add(key, value)`: Fügt einen benutzerdefinierten Logeintrag hinzu
- `status_message_set(message)`: Setzt eine Statusmeldung

#### request-Objekt

Das `request`-Objekt enthält Informationen über die Authentifizierungsanfrage, ähnlich wie im Filter-Kontext.

### Verfügbare Funktionen im Neural-Network-Kontext (nauthilus_call_neural_network)

Für Features, die die Funktion `nauthilus_call_neural_network` implementieren, stehen andere Funktionen zur Verfügung:

#### nauthilus_builtin

Das `nauthilus_builtin`-Objekt bietet in diesem Kontext nur die folgenden Funktionen:

- `custom_log_add(key, value)`: Fügt einen benutzerdefinierten Logeintrag hinzu

#### nauthilus_neural

Das `nauthilus_neural`-Objekt bietet Funktionen für die Interaktion mit dem neuronalen Netzwerk:

- `add_additional_features(features)`: Fügt zusätzliche Features zum neuronalen Netzwerk hinzu

#### request-Objekt

Das `request`-Objekt enthält Informationen über die Authentifizierungsanfrage, ähnlich wie im Feature-Kontext.

> **Hinweis:** Im Gegensatz zu `nauthilus_call_feature` gibt die Funktion `nauthilus_call_neural_network` keine Werte zurück. Sie wird nur verwendet, um zusätzliche Features für das neuronale Netzwerk zu sammeln.

### Übung: Einfaches Logging-Feature erstellen

In dieser Übung erstellen wir ein einfaches Feature, das Authentifizierungsversuche protokolliert.

1. Erstellen Sie eine Datei `/etc/nauthilus/lua-plugins.d/features/logging.lua`:

```lua
function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Protokollieren des Authentifizierungsversuchs
    nauthilus_builtin.custom_log_add("auth_attempt_username", request.username)
    nauthilus_builtin.custom_log_add("auth_attempt_ip", request.client_ip)
    nauthilus_builtin.custom_log_add("auth_attempt_protocol", request.protocol)

    if request.user_agent then
        nauthilus_builtin.custom_log_add("auth_attempt_user_agent", request.user_agent)
    end

    -- Feature auslösen, aber Verarbeitung fortsetzen
    return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
```

2. Aktualisieren Sie Ihre Nauthilus-Konfiguration:

```yaml
lua:
  features:
    - name: "logging"
      path: "/etc/nauthilus/lua-plugins.d/features/logging.lua"
```

3. Starten Sie Nauthilus neu:

```bash
# Wenn Sie Docker Compose verwenden:
docker-compose restart nauthilus

# Wenn Sie Docker direkt verwenden:
docker restart nauthilus
```

4. Testen Sie das Feature:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"127.0.0.1","service":"http"}' http://localhost:8080/api/v1/auth/json
```

## Monitoring und Debugging

Nauthilus bietet verschiedene Möglichkeiten zum Monitoring und Debugging:

### Prometheus-Metriken

Nauthilus exportiert Metriken im Prometheus-Format. Diese können mit Prometheus gesammelt und mit Grafana visualisiert werden.

Aktivieren Sie die Prometheus-Metriken in Ihrer Konfiguration:

```yaml
server:
  monitoring:
    prometheus:
      enabled: true
      endpoint: "/metrics"
```

#### Wichtige Metriken

Nauthilus exportiert verschiedene Metriken, darunter:

- `nauthilus_http_requests_total`: Gesamtzahl der HTTP-Anfragen
- `nauthilus_authentication_attempts_total`: Gesamtzahl der Authentifizierungsversuche
- `nauthilus_authentication_success_total`: Gesamtzahl der erfolgreichen Authentifizierungen
- `nauthilus_authentication_failure_total`: Gesamtzahl der fehlgeschlagenen Authentifizierungen
- `nauthilus_backend_request_duration_seconds`: Dauer der Backend-Anfragen
- `nauthilus_filter_duration_seconds`: Dauer der Filter-Verarbeitung
- `nauthilus_feature_duration_seconds`: Dauer der Feature-Verarbeitung

### Grafana-Dashboard

Nauthilus bietet ein vorgefertigtes Grafana-Dashboard, das Sie importieren können:

1. Installieren Sie Grafana:

```bash
docker run -d --name grafana -p 3000:3000 grafana/grafana
```

2. Konfigurieren Sie eine Prometheus-Datenquelle in Grafana.

3. Importieren Sie das Nauthilus-Dashboard aus dem Repository:

```
/path/to/nauthilus/contrib/grafana/dashboard.json
```

### Logging

Nauthilus unterstützt verschiedene Log-Level und -Formate:

```yaml
server:
  log:
    level: "debug"  # Optionen: debug, info, warn, error
    format: "json"  # Optionen: json, text
    use_color: true
```

#### Log-Level

- `debug`: Ausführliche Debugging-Informationen
- `info`: Informative Meldungen
- `warn`: Warnungen
- `error`: Fehlermeldungen

#### Log-Formate

- `json`: Strukturierte Logs im JSON-Format
- `text`: Menschenlesbare Logs im Textformat

### Debugging von Lua-Skripten

Für das Debugging von Lua-Skripten können Sie die `print`-Funktion verwenden, die Ausgaben in die Nauthilus-Logs schreibt:

```lua
nauthilus_util.print_result({ log_format = "json" }, { message = "Debug-Nachricht", level = "debug" })
```

Sie können auch benutzerdefinierte Logeinträge hinzufügen:

```lua
nauthilus_builtin.custom_log_add("debug_key", "debug_value")
```

### Übung: Monitoring einrichten

In dieser Übung richten wir Prometheus und Grafana für das Monitoring von Nauthilus ein.

1. Erstellen Sie eine Docker Compose-Datei für Prometheus und Grafana:

```yaml
version: '3'

services:
  nauthilus:
    image: ghcr.io/croessner/nauthilus:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/nauthilus
      - ./lua-plugins.d:/etc/nauthilus/lua-plugins.d
    environment:
      - TZ=Europe/Berlin
      - NAUTHILUS_EXPERIMENTAL_ML=true
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus:/etc/prometheus
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
    restart: unless-stopped

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    depends_on:
      - prometheus
    restart: unless-stopped

volumes:
  redis-data:
  prometheus-data:
  grafana-data:
```

2. Erstellen Sie eine Prometheus-Konfigurationsdatei `prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'nauthilus'
    static_configs:
      - targets: ['nauthilus:8080']
    metrics_path: /metrics
```

3. Starten Sie die Dienste:

```bash
docker-compose up -d
```

4. Öffnen Sie Grafana unter http://localhost:3000 (Standard-Anmeldedaten: admin/admin).

5. Fügen Sie Prometheus als Datenquelle hinzu (URL: http://prometheus:9090).

6. Importieren Sie das Nauthilus-Dashboard.

## Post-Actions

Post-Actions in Nauthilus sind Lua-Skripte, die asynchron nach Abschluss der Hauptverarbeitung einer Authentifizierungsanfrage ausgeführt werden. Sie ermöglichen es, zusätzliche Aktionen durchzuführen, ohne die Antwortzeit der Hauptanfrage zu beeinflussen.

### Grundlegende Konzepte

Post-Actions werden in der Konfiguration unter dem Abschnitt `lua.actions` definiert:

```yaml
lua:
  actions:
    - type: post
      name: "Logging"
      script_path: "/etc/nauthilus/lua-plugins.d/actions/logging.lua"
    - type: post
      name: "Benachrichtigung"
      script_path: "/etc/nauthilus/lua-plugins.d/actions/notification.lua"
```

Jede Post-Action hat einen Typ (`post`), einen Namen und einen Pfad zum Lua-Skript. Das Skript wird asynchron ausgeführt, nachdem die Antwort an den Client gesendet wurde.

### Beispiel: Logging-Post-Action

Hier ist ein einfaches Beispiel für eine Post-Action, die erfolgreiche und fehlgeschlagene Anmeldeversuche protokolliert:

```lua
function nauthilus_run_hook(logging)
    local nauthilus_util = require("nauthilus_util")

    local result = {}
    result.level = "info"
    result.caller = "logging.lua"

    -- Protokolliere Authentifizierungsversuch
    if request.authenticated then
        result.message = "Erfolgreiche Anmeldung"
        result.status = "success"
    else
        result.message = "Fehlgeschlagene Anmeldung"
        result.status = "failure"
    end

    result.username = request.username
    result.client_ip = request.client_ip
    result.timestamp = nauthilus_util.get_current_timestamp()

    -- Ausgabe des Ergebnisses
    nauthilus_util.print_result(logging, result)
end
```

## Custom Hooks

Custom Hooks in Nauthilus ermöglichen es, benutzerdefinierte HTTP-Endpunkte mit eigener Logik zu erstellen. Sie werden über spezielle URLs aufgerufen und können für verschiedene Zwecke verwendet werden.

### Grundlegende Konzepte

Custom Hooks werden in der Konfiguration unter dem Abschnitt `lua.custom_hooks` definiert:

```yaml
lua:
  custom_hooks:
    - http_location: "/postfix/map"
      http_method: POST
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/postfix_map.lua"
    - http_location: "/status/check"
      http_method: GET
      script_path: "/etc/nauthilus/lua-plugins.d/hooks/status_check.lua"
```

Jeder Custom Hook hat einen HTTP-Pfad (`http_location`), eine HTTP-Methode (`http_method`) und einen Pfad zum Lua-Skript. Das Skript wird ausgeführt, wenn der entsprechende Endpunkt aufgerufen wird.

### Beispiel: Status-Check-Hook

Hier ist ein einfaches Beispiel für einen Custom Hook, der den Status des Systems überprüft:

```lua
function nauthilus_run_hook(logging)
    local nauthilus_util = require("nauthilus_util")

    -- Überprüfe Redis-Verbindung
    dynamic_loader("nauthilus_redis")
    local nauthilus_redis = require("nauthilus_redis")

    local redis_status = "ok"
    local _, err_redis = nauthilus_redis.redis_ping("default")
    if err_redis then
        redis_status = "error: " .. err_redis
    end

    -- Erstelle Statusbericht
    local status = {
        status = "ok",
        components = {
            redis = redis_status,
            server = "ok"
        },
        timestamp = nauthilus_util.get_current_timestamp()
    }

    return status
end
```

Dieser Hook gibt einen JSON-Status zurück, wenn der Endpunkt `/api/v1/custom/status/check` mit der GET-Methode aufgerufen wird.

## Fortgeschrittene Themen

### Load-Balancing und Hochverfügbarkeit

Nauthilus kann in einer Hochverfügbarkeitsumgebung betrieben werden, indem mehrere Instanzen hinter einem Load-Balancer bereitgestellt werden:

```
                    +----------------+
                    |                |
                    | Load Balancer  |
                    |                |
                    +-------+--------+
                            |
            +---------------+---------------+
            |               |               |
  +---------v-----+  +------v------+  +-----v-------+
  |               |  |             |  |             |
  | Nauthilus 1   |  | Nauthilus 2 |  | Nauthilus 3 |
  |               |  |             |  |             |
  +-------+-------+  +------+------+  +------+------+
          |                 |                |
          +--------+--------+--------+-------+
                   |                 |
         +---------v---------+ +-----v-----------+
         |                   | |                 |
         | Redis Cluster     | | LDAP/Datenbank  |
         |                   | |                 |
         +-------------------+ +-----------------+
```

Konfigurieren Sie Redis für die Sitzungspersistenz:

```yaml
redis:
  # Wenn Redis auf 127.0.0.1:6379 läuft, ist keine Konfiguration nötig
  # Für andere Ziele muss master: und replica: konfiguriert werden
  master:
    address: "redis-master:6379"

  replica:
    addresses:
      - "redis-replica:6379"
```

### Sicherheitsempfehlungen

#### TLS-Konfiguration

Verwenden Sie TLS für die Kommunikation:

```yaml
server:
  tls:
    enabled: true
    cert_file: "/etc/nauthilus/cert.pem"
    key_file: "/etc/nauthilus/key.pem"
```

#### Sichere Redis-Konfiguration

Schützen Sie Redis mit einem Passwort und nutzen Sie Cluster oder Sentinels für Hochverfügbarkeit:

```yaml
redis:
  pool_size: 30
  idle_pool_size: 20
  database_number: 0
  prefix: nt_

  # Option 1: Master/Replica mit Passwort
  master:
    address: "redis-master:6379"
    username: "redis-user"
    password: "sicheres-passwort"

  # Option 2: Redis Sentinel
  sentinels:
    master: "myMaster"
    addresses:
      - "redis-sentinel-1:26379"
      - "redis-sentinel-2:26379"
    username: "sentinel-user"
    password: "sicheres-passwort"

  # Option 3: Redis Cluster
  cluster:
    addresses:
      - "redis-node-1:6379"
      - "redis-node-2:6379"
      - "redis-node-3:6379"
```

#### Sichere LDAP-Konfiguration

Verwenden Sie TLS für die LDAP-Verbindung:

```yaml
ldap:
  config:
    server_uri: "ldaps://ldap.example.com:636/"
    tls_skip_verify: false
    sasl_external: true
    tls_ca_cert: "/etc/nauthilus/ssl/certs/ca.crt"
    tls_client_cert: "/etc/nauthilus/ssl/certs/tls.crt"
    tls_client_key: "/etc/nauthilus/ssl/private/tls.key"
```

#### HTTP Basic Authentication

Schützen Sie die API-Endpunkte von Nauthilus mit HTTP Basic Authentication:

```yaml
server:
  basic_auth:
    enabled: true
    username: authserv
    password: sicheres-passwort
```

Diese Konfiguration aktiviert die HTTP Basic Authentication für alle API-Endpunkte unter `/api/v1`. Clients müssen gültige Anmeldeinformationen bereitstellen, um auf diese Endpunkte zugreifen zu können. Wenn nur `enabled: true` angegeben wird, müssen Benutzername und Passwort über Umgebungsvariablen oder andere Konfigurationsmechanismen bereitgestellt werden.

Die HTTP Basic Authentication bietet eine einfache, aber effektive Methode, um unbefugten Zugriff auf Ihre Nauthilus-API zu verhindern. Es wird empfohlen, diese Funktion in Produktionsumgebungen zu aktivieren und ein sicheres Passwort zu verwenden.

> **Hinweis:** Verwenden Sie HTTP Basic Authentication immer in Kombination mit TLS, da die Anmeldeinformationen sonst im Klartext übertragen werden.

### Leistungsoptimierung

#### Redis-Optimierung

Optimieren Sie die Redis-Konfiguration für bessere Leistung:

```yaml
redis:
  pool_size: 30
  idle_pool_size: 20
  database_number: 0
  prefix: nt_
  positive_cache_ttl: 3600
  negative_cache_ttl: 7200
```

#### LDAP-Verbindungspooling

Optimieren Sie das LDAP-Verbindungspooling:

```yaml
ldap:
  config:
    number_of_workers: 100
    lookup_pool_size: 8
    lookup_idle_pool_size: 4
    auth_pool_size: 16
    auth_idle_pool_size: 5
```

#### Lua-Skript-Optimierung

Optimieren Sie Ihre Lua-Skripte für bessere Leistung:

- Vermeiden Sie unnötige HTTP-Anfragen
- Verwenden Sie Caching, wo möglich
- Minimieren Sie die Anzahl der dynamisch geladenen Module

### Fehlerbehebung

#### Häufige Probleme und Lösungen

1. **Redis-Verbindungsprobleme**:
   - Überprüfen Sie die Redis-Konfiguration
   - Stellen Sie sicher, dass Redis läuft
   - Überprüfen Sie Firewall-Einstellungen

2. **LDAP-Verbindungsprobleme**:
   - Überprüfen Sie die LDAP-Konfiguration
   - Testen Sie die LDAP-Verbindung mit `ldapsearch`
   - Überprüfen Sie Firewall-Einstellungen

3. **Lua-Skript-Fehler**:
   - Überprüfen Sie die Syntax Ihrer Lua-Skripte
   - Fügen Sie Debugging-Ausgaben hinzu
   - Überprüfen Sie die Nauthilus-Logs auf Fehlermeldungen

4. **Leistungsprobleme**:
   - Überprüfen Sie die Redis-Leistung
   - Optimieren Sie Ihre Lua-Skripte
   - Erhöhen Sie die Anzahl der Nauthilus-Instanzen

## Beispielanwendungen

### Authentifizierung für einen Mailserver

Hier ist ein Beispiel für die Konfiguration von Nauthilus zur Authentifizierung für einen Postfix/Dovecot-Mailserver:

1. Konfigurieren Sie Nauthilus mit einem LDAP-Backend:

```yaml
server:
  backends:
    - ldap

ldap:
  pools:
    - name: "default"
      servers:
        - host: "ldap.example.com"
          port: 389
      bind_dn: "cn=nauthilus,ou=services,dc=example,dc=com"
      bind_password: "geheim"
      base_dn: "dc=example,dc=com"
      user_filter: "(&(objectClass=person)(uid=%s))"
      account_attribute: "uid"
```

2. Konfigurieren Sie Postfix für die Authentifizierung über Nauthilus:

```
# /etc/postfix/main.cf
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
```

3. Konfigurieren Sie Dovecot für die Authentifizierung über Nauthilus:

```
# /etc/dovecot/conf.d/10-auth.conf
auth_mechanisms = plain login
passdb {
  driver = lua
  args = file=/etc/dovecot/auth-nauthilus.lua
}
userdb {
  driver = lua
  args = file=/etc/dovecot/auth-nauthilus.lua
}
```

Erstellen Sie die Lua-Skriptdatei für die Authentifizierung:

```lua
-- dovecot-auth.lua
--
-- Beispiel-Skript für die Dovecot-Authentifizierung mit Nauthilus

--
-- START Einstellungen
--

-- Debug-Modus für HTTP-Anfragen aktivieren/deaktivieren
local http_debug = false;
-- Pfad zur Datei mit dem HTTP Basic Auth Passwort
local http_basicauthfile = "/etc/dovecot/http-auth.secret"
-- URL zum Nauthilus API-Endpunkt (ersetzen Sie dies mit Ihrer tatsächlichen Nauthilus-URL)
local http_uri = "https://example.com/api/v1/auth/json"
-- Nachricht, die angezeigt wird, wenn ein Konto deaktiviert ist
local http_access_denied = "Account not enabled"

--
-- ENDE Einstellungen
--

-- JSON-Bibliothek für die Verarbeitung von Anfragen und Antworten
local json = require('cjson')

-- Konstanten für die Unterscheidung zwischen Passwort- und Benutzerabfragen
local PASSDB = "passdb"
local USERDB = "userdb"

-- HTTP-Client-Konfiguration
local http_basicauthpassword -- Wird in init_http() aus der Datei gelesen
local http_client = dovecot.http.client{
    timeout = 300;           -- Timeout in Sekunden
    max_attempts = 3;        -- Anzahl der Wiederholungsversuche
    debug = http_debug;      -- Debug-Modus aus den Einstellungen
    user_agent = "Dovecot/2.3"; -- User-Agent-Header
}

-- Funktion zum Initialisieren der HTTP-Authentifizierung
-- Liest das Passwort für die HTTP Basic Auth aus der konfigurierten Datei
local function init_http()
    -- Öffne die Datei mit dem Passwort
    local file = assert (io.open(http_basicauthfile))

    -- Lese den Inhalt der Datei (Base64-kodiertes Passwort)
    http_basicauthpassword = file:read("*all")

    -- Schließe die Datei
    file:close()
end

-- Hauptfunktion für die Kommunikation mit Nauthilus
-- Parameter:
--   request: Dovecot-Anfrageobjekt mit Benutzerinformationen
--   password: Passwort des Benutzers (leer bei userdb-Anfragen)
--   dbtype: Art der Anfrage (PASSDB oder USERDB)
-- Rückgabe:
--   Dovecot-Authentifizierungsergebnis und zusätzliche Felder
local function query_db(request, password, dbtype)
    -- Extrahiere Verbindungsinformationen aus der Anfrage
    local remote_ip = request.remote_ip       -- IP-Adresse des Clients
    local remote_port = request.remote_port   -- Port des Clients
    local local_ip = request.local_ip         -- Lokale IP-Adresse des Servers
    local local_port = request.local_port     -- Lokaler Port des Servers
    local client_id = request.client_id       -- Client-ID (falls vorhanden)
    local qs_noauth = ""                      -- Query-String für no-auth-Modus
    local extra_fields = {}                   -- Zusätzliche Felder für die Antwort

    -- Hilfsfunktion zum Hinzufügen von Feldern zur Antwort
    -- pf: Präfix für das Feld (z.B. "userdb_")
    -- key: Schlüssel des Feldes
    -- value: Wert des Feldes
    local function add_extra_field(pf, key, value)
        if value ~= nil and value:len()>0 then
            extra_fields[pf .. key] = value
        end
    end

    -- Bei userdb-Anfragen wird der no-auth-Modus verwendet
    -- (keine Passwortüberprüfung, nur Benutzerinformationen abrufen)
    if dbtype == USERDB then
        qs_noauth = "?mode=no-auth"
    end
    -- Erstelle eine HTTP-Anfrage an den Nauthilus-Server
    local auth_request = http_client:request {
        url = http_uri .. qs_noauth;  -- URL mit optionalem no-auth-Parameter
        method = "POST";              -- HTTP-Methode POST für Authentifizierungsanfragen
    }

    -- Füge HTTP Basic Authentication hinzu
    -- Das Passwort wurde zuvor aus der Datei gelesen
    auth_request:add_header("Authorization", "Basic " .. http_basicauthpassword)

    -- Setze den Content-Type-Header auf application/json
    auth_request:add_header("Content-Type", "application/json")

    -- Setze Standardwerte für fehlende Parameter
    -- Dies stellt sicher, dass die Anfrage auch funktioniert,
    -- wenn nicht alle Informationen verfügbar sind
    if remote_ip == nil then
        remote_ip = "127.0.0.1"  -- Lokale IP als Fallback
    end
    if remote_port == nil then
        remote_port = "0"        -- Standardport als Fallback
    end
    if local_ip == nil then
        local_ip = "127.0.0.1"   -- Lokale IP als Fallback
    end
    if local_port == nil then
        local_port = "0"         -- Standardport als Fallback
    end
    if client_id == nil then
        client_id = ""           -- Leerer String als Fallback
    end

    -- Spezielle Behandlung für Master-User-Authentifizierung
    -- Ein Master-User kann sich als ein anderer Benutzer authentifizieren
    if dbtype == PASSDB then
        -- Prüfe, ob es sich um einen Master-User handelt (auth_user != user)
        if request.auth_user:lower() ~= request.user:lower() then
            -- Füge den Zielbenutzer zu den Extra-Feldern hinzu
            add_extra_field("", "user", request.user)

            -- Führe eine userdb-Abfrage für den Zielbenutzer durch
            local userdb_status = query_db(request, "", USERDB)

            -- Behandle verschiedene Ergebnisse der userdb-Abfrage
            if userdb_status == dovecot.auth.USERDB_RESULT_USER_UNKNOWN then
                -- Benutzer nicht gefunden
                return dovecot.auth.PASSDB_RESULT_USER_UNKNOWN, ""
            elseif userdb_status == dovecot.auth.USERDB_RESULT_INTERNAL_FAILURE then
                -- Interner Fehler
                return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, ""
            else
                -- Benutzer gefunden, erlaube Zugriff
                return dovecot.auth.PASSDB_RESULT_OK, extra_fields
            end
        end
    end

    -- Erstelle das JSON-Anfrageobjekt für Nauthilus
    local req = {}

    -- Füge alle relevanten Informationen zur Anfrage hinzu
    req.username = request.user       -- Benutzername
    req.password = password           -- Passwort (leer bei userdb-Anfragen)
    req.client_ip = remote_ip         -- IP-Adresse des Clients
    req.client_port = remote_port     -- Port des Clients
    req.client_id = client_id         -- Client-ID (falls vorhanden)
    req.local_ip = local_ip           -- Lokale IP-Adresse des Servers
    req.local_port = local_port       -- Lokaler Port des Servers
    req.service = request.service     -- Dienst (imap, pop3, etc.)
    req.method = request.mech:lower() -- Authentifizierungsmethode (plain, login, etc.)

    -- Füge TLS-Informationen hinzu, falls die Verbindung gesichert ist
    if request.secured == "TLS" or request.secured == "secured" then
        req.ssl = "1"                 -- TLS ist aktiviert
        req.ssl_protocol = request.secured  -- TLS-Protokoll

        -- Füge Client-Zertifikatsinformationen hinzu, falls vorhanden
        if request.cert ~= "" then
            req.ssl_client_verify = "1"  -- Client-Zertifikat wurde verifiziert
        end
    end

    -- Füge Sitzungsinformationen hinzu, falls vorhanden
    if request.session ~= nil then
        auth_request:add_header("X-Dovecot-Session", request.session)
    end

    -- Setze den JSON-Payload für die Anfrage
    auth_request:set_payload(json.encode(req))

    -- Sende die Anfrage an den Nauthilus-Server
    local auth_response = auth_request:submit()

    -- Verarbeite die Antwort
    local auth_status_code = auth_response:status()     -- HTTP-Statuscode
    local auth_status_message = auth_response:header("Auth-Status")  -- Authentifizierungsstatus

    -- Extrahiere wichtige Header aus der Antwort
    local dovecot_account = auth_response:header("Auth-User")  -- Tatsächlicher Benutzername
    local nauthilus_session = auth_response:header("X-Nauthilus-Session")  -- Sitzungs-ID

    -- Protokolliere die Anfrage und Antwort für Debugging-Zwecke
    dovecot.i_info("request=" .. dbtype .. " service=" .. request.service .. " user=<" .. request.user ..  "> auth_status_code=" .. tostring(auth_status_code) .. " auth_status_message=<" .. auth_status_message .. "> nauthilus_session=" .. nauthilus_session)

    -- Behandle erfolgreiche Anmeldungen (HTTP-Statuscode 200)
    if auth_status_code == 200 then
        -- Dekodiere den JSON-Antworttext
        local resp = json.decode(auth_response:payload())
        local pf = ""  -- Präfix für userdb-Felder

        -- Wenn ein anderer Benutzername zurückgegeben wurde, verwende diesen
        if dovecot_account and dovecot_account ~= "" then
            add_extra_field("", "user", dovecot_account)
        end

        -- Bei passdb-Anfragen werden userdb-Felder mit einem Präfix versehen
        if dbtype == PASSDB then
            pf = "userdb_"
        end

        -- Verarbeite die Attribute aus der Antwort
        if resp and resp.attributes then
            -- Quota-Informationen
            if resp.attributes.rnsMSQuota then
                add_extra_field(pf, "quota_rule=*:bytes", resp.attributes.rnsMSQuota[1])
            end

            -- Quota-Überschreitung
            if resp.attributes.rnsMSOverQuota then
                add_extra_field(pf, "quota_over_flag", resp.attributes.rnsMSOverQuota[1])
            end

            -- Mailbox-Pfad
            if resp.attributes.rnsMSMailPath then
                add_extra_field(pf, "mail", resp.attributes.rnsMSMailPath[1])
            end

            -- ACL-Gruppen
            if resp.attributes["ACL-Groups"] then
                add_extra_field(pf, "acl_groups", resp.attributes["ACL-Groups"][1])
            end
        end

        -- Erfolgreiche Antwort zurückgeben
        if dbtype == PASSDB then
            return dovecot.auth.PASSDB_RESULT_OK, extra_fields
        else
            return dovecot.auth.USERDB_RESULT_OK, extra_fields
        end
    end

    -- Behandle fehlgeschlagene Anmeldungen (HTTP-Statuscode 403)
    if auth_status_code == 403 then
        if dbtype == PASSDB then
            -- Prüfe, ob das Konto deaktiviert ist
            if auth_status_message == http_access_denied then
                return dovecot.auth.PASSDB_RESULT_USER_DISABLED, auth_status_message
            end

            -- Andernfalls ist das Passwort falsch
            return dovecot.auth.PASSDB_RESULT_PASSWORD_MISMATCH, auth_status_message
        else
            -- Bei userdb-Anfragen bedeutet 403, dass der Benutzer unbekannt ist
            return dovecot.auth.USERDB_RESULT_USER_UNKNOWN, auth_status_message
        end
    end

    -- Behandle Kommunikationsfehler mit Nauthilus (HTTP-Statuscodes 50X)
    if dbtype == PASSDB then
        return dovecot.auth.PASSDB_RESULT_INTERNAL_FAILURE, ""
    else
        return dovecot.auth.USERDB_RESULT_INTERNAL_FAILURE, ""
    end
end

-- Funktion für userdb-Lookups (Benutzerinformationen abrufen)
-- Diese Funktion wird von Dovecot aufgerufen, um Benutzerinformationen abzurufen
-- Parameter:
--   request: Dovecot-Anfrageobjekt
-- Rückgabe:
--   Dovecot-Authentifizierungsergebnis und zusätzliche Felder
function auth_userdb_lookup(request)
    -- Rufe query_db mit leerem Passwort und USERDB-Typ auf
    return query_db(request, "", USERDB)
end

-- Funktion für passdb-Lookups ohne Passwortüberprüfung
-- Diese Funktion wird von Dovecot aufgerufen, wenn nur die Existenz eines Benutzers geprüft werden soll
-- Parameter:
--   request: Dovecot-Anfrageobjekt
-- Rückgabe:
--   Dovecot-Authentifizierungsergebnis und zusätzliche Felder
function auth_passdb_lookup(request)
    -- Rufe query_db mit leerem Passwort und USERDB-Typ auf
    local result, extra_fields = query_db(request, "", USERDB)

    -- Setze das nopassword-Flag, um anzuzeigen, dass keine Passwortüberprüfung stattfinden soll
    if type(extra_fields) == "table" then
        extra_fields.nopassword = "y"
    else
        extra_fields = { nopassword = "y" }
    end

    return result, extra_fields
end

-- Funktion für Passwortüberprüfung
-- Diese Funktion wird von Dovecot aufgerufen, um ein Passwort zu überprüfen
-- Parameter:
--   request: Dovecot-Anfrageobjekt
--   password: Das zu überprüfende Passwort
-- Rückgabe:
--   Dovecot-Authentifizierungsergebnis und zusätzliche Felder
function auth_password_verify(request, password)
    -- Rufe query_db mit dem Passwort und PASSDB-Typ auf
    return query_db(request, password, PASSDB)
end

-- Initialisierungsfunktion für das Skript
-- Diese Funktion wird von Dovecot beim Laden des Skripts aufgerufen
-- Rückgabe:
--   0 bei Erfolg, andere Werte bei Fehler
function script_init()
    -- Initialisiere die HTTP-Authentifizierung
    init_http()

    return 0
end

-- Aufräumfunktion für das Skript
-- Diese Funktion wird von Dovecot beim Entladen des Skripts aufgerufen
function script_deinit()
    -- Hier könnten Aufräumarbeiten stattfinden, falls nötig
end

-- Funktion zum Auflisten aller Benutzerkonten
-- Diese Funktion wird von Dovecot aufgerufen, um alle verfügbaren Benutzerkonten abzurufen
-- Rückgabe:
--   Liste der Benutzerkonten
function auth_userdb_iterate()
    local user_accounts = {}

    -- Erstelle eine HTTP-Anfrage an den Nauthilus-Server
    -- mit dem mode=list-accounts Parameter
    local list_request = http_client:request {
        url = http_uri .. "?mode=list-accounts";
        method = "GET";
    }

    -- Füge HTTP Basic Authentication hinzu
    list_request:add_header("Authorization", "Basic " .. http_basicauthpassword)

    -- Setze den Accept-Header auf application/json
    list_request:add_header("Accept", "application/json")

    -- Sende die Anfrage und verarbeite die Antwort
    local list_response = list_request:submit()
    local resp_status = list_response:status()

    -- Bei erfolgreicher Antwort, dekodiere die JSON-Antwort
    if resp_status == 200 then
        user_accounts = json.decode(list_response:payload())
    end

    return user_accounts
end
```

### Authentifizierung mit Keycloak

Hier ist ein Beispiel für die Integration von Nauthilus mit Keycloak, basierend auf dem [nauthilus-keycloak](https://github.com/croessner/nauthilus-keycloak) Projekt:

#### Überblick

Nauthilus kann als Authentifizierungsbackend für Keycloak dienen. Dabei wird ein spezieller Authenticator für Keycloak verwendet, der Authentifizierungsanfragen an Nauthilus weiterleitet. Nach erfolgreicher Authentifizierung gibt Nauthilus einen Kontonamen zurück, der einem bekannten Benutzer in Keycloak entsprechen muss.

Der Authentifizierungsablauf sieht wie folgt aus:

1. Benutzer öffnet die Keycloak-Anmeldeseite
2. Benutzer gibt Anmeldedaten ein
3. Keycloak leitet die Authentifizierungsanfrage an Nauthilus weiter
4. Nauthilus überprüft die Anmeldedaten und gibt eine Antwort zurück
5. Bei erfolgreicher Authentifizierung fährt Keycloak mit dem Benutzernamen fort
6. Bei fehlgeschlagener Authentifizierung zeigt Keycloak eine Fehlermeldung an

#### Installation und Konfiguration

1. Bauen Sie den Nauthilus-Authenticator für Keycloak:

```bash
git clone https://github.com/croessner/nauthilus-keycloak.git
cd nauthilus-keycloak
mvn clean package
```

2. Kopieren Sie die JAR-Datei in Ihre Keycloak-Umgebung und starten Sie den Dienst neu.

3. Konfigurieren Sie den Authenticator mit Umgebungsvariablen oder über die Keycloak-Benutzeroberfläche:

**Option 1: Umgebungsvariablen**

```bash
export NAUTHILUS_LOGIN_URL=https://login.example.com/api/v1/auth/json
export NAUTHILUS_PROTOCOL=keycloak
# Falls Nauthilus HTTP Basic-Authentifizierung erfordert
export NAUTHILUS_USERNAME=username
export NAUTHILUS_PASSWORD=password
```

**Option 2: Keycloak-Benutzeroberfläche**

Klicken Sie auf das Einstellungsrad neben dem Nauthilus-Schritt und fügen Sie Ihre Werte entsprechend hinzu.

4. Konfigurieren Sie Nauthilus für die Verwendung mit Keycloak:

```yaml
ldap:
  config:
    server_uri: ldap://ldap.example.com:389/
    starttls: true
  search:
    - protocol: keycloak
      cache_name: keycloak
      base_dn: ou=people,dc=example,dc=com
      filter:
        user: |
          (&
            (objectClass=inetOrgPerson)
            (uniqueIdentifier=%L{user})
          )
      mapping:
        account_field: uniqueIdentifier
      attribute:
        - uniqueIdentifier
```

5. Konfigurieren Sie den Authentifizierungsablauf in Keycloak:

- Gehen Sie zu "Authentication" > "Flows"
- Kopieren Sie den "browser"-Flow
- Ersetzen Sie den "Username Password Form"-Authenticator durch den "Nauthilus authenticator"
- Konfigurieren Sie den Nauthilus-Authenticator mit den entsprechenden Einstellungen

#### Hinweise

- Nauthilus gibt einen Kontonamen zurück, der einem bekannten Benutzer in Keycloak entsprechen muss
- Die LDAP-Konfiguration in Nauthilus muss mit den Einstellungen in Keycloak übereinstimmen
- Stellen Sie sicher, dass die Benutzer-Federation in Keycloak korrekt konfiguriert ist

## Workshop-Übungen

### Übung 1: Vollständige Nauthilus-Installation

In dieser Übung installieren wir Nauthilus mit Docker Compose und konfigurieren es für die Authentifizierung mit einem Lua-Backend.

1. Erstellen Sie ein Verzeichnis für das Projekt:

```bash
mkdir -p nauthilus-workshop
cd nauthilus-workshop
```

2. Erstellen Sie eine Docker Compose-Datei:

```yaml
version: '3'

services:
  nauthilus:
    image: ghcr.io/croessner/nauthilus:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/nauthilus
      - ./lua-plugins.d:/etc/nauthilus/lua-plugins.d
    environment:
      - TZ=Europe/Berlin
      - NAUTHILUS_EXPERIMENTAL_ML=true
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

3. Erstellen Sie die Konfigurationsdateien:

```bash
mkdir -p config lua-plugins.d/backend lua-plugins.d/filters lua-plugins.d/features
```

4. Erstellen Sie eine Konfigurationsdatei `config/nauthilus.yml`:

```yaml
server:
  address: "0.0.0.0:8080"
  instance_name: "nauthilus-workshop"
  log:
    level: "info"
    format: "json"
  backends:
    - lua

redis:
  # Wenn Redis auf 127.0.0.1:6379 läuft, ist keine Konfiguration nötig
  # Für andere Ziele muss master: und replica: konfiguriert werden
  master:
    address: "redis:6379"
  replica:
    addresses:
      - "redis:6379"
```

5. Erstellen Sie ein einfaches Lua-Backend in `lua-plugins.d/backend/simple.lua`:

```lua
local nauthilus_util = require("nauthilus_util")

-- Hartcodierte Benutzerliste
local users = {
    ["user1"] = {password = "password1", account = "user1@example.com"},
    ["user2"] = {password = "password2", account = "user2@example.com"}
}

function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()

    local user = users[request.username]

    if user then
        b:user_found(true)
        b:account_field("account")

        if not request.no_auth then
            b:authenticated(user.password == request.password)
        end

        b:attributes({account = user.account})
    else
        b:user_found(false)
        b:authenticated(false)
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end
```

6. Starten Sie die Dienste:

```bash
docker-compose up -d
```

7. Testen Sie die Authentifizierung:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"127.0.0.1","service":"http"}' http://localhost:8080/api/v1/auth/json
```

### Übung 2: Implementierung eines IP-Filters

In dieser Übung implementieren wir einen Filter, der Anfragen von bestimmten IP-Adressen blockiert.

1. Erstellen Sie eine Datei `lua-plugins.d/filters/ip_blocklist.lua`:

```lua
function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Liste der blockierten IP-Adressen
    local blocked_ips = {
        "192.168.1.100",
        "10.0.0.50"
    }

    -- Überprüfen, ob die Client-IP in der Blockliste ist
    for _, ip in ipairs(blocked_ips) do
        if request.client_ip == ip then
            nauthilus_builtin.custom_log_add("blocked_ip", request.client_ip)
            nauthilus_builtin.status_message_set("IP-Adresse blockiert")

            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    -- Die Anfrage sollte akzeptiert werden
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
```

2. Aktualisieren Sie Ihre Nauthilus-Konfiguration in `config/nauthilus.yml`:

```yaml
lua:
  filters:
    - name: "ip_blocklist"
      path: "/etc/nauthilus/lua-plugins.d/filters/ip_blocklist.lua"
```

3. Starten Sie Nauthilus neu:

```bash
docker-compose restart nauthilus
```

4. Testen Sie den Filter:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"192.168.1.100","service":"http"}' http://localhost:8080/api/v1/auth/json
```

### Übung 3: Implementierung eines Logging-Features

In dieser Übung implementieren wir ein Feature, das Authentifizierungsversuche protokolliert.

1. Erstellen Sie eine Datei `lua-plugins.d/features/logging.lua`:

```lua
function nauthilus_call_feature(request)
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    -- Protokollieren des Authentifizierungsversuchs
    nauthilus_builtin.custom_log_add("auth_attempt_username", request.username)
    nauthilus_builtin.custom_log_add("auth_attempt_ip", request.client_ip)
    nauthilus_builtin.custom_log_add("auth_attempt_protocol", request.protocol)

    if request.user_agent then
        nauthilus_builtin.custom_log_add("auth_attempt_user_agent", request.user_agent)
    end

    -- Feature auslösen, aber Verarbeitung fortsetzen
    return nauthilus_builtin.FEATURE_TRIGGER_YES, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
```

2. Aktualisieren Sie Ihre Nauthilus-Konfiguration in `config/nauthilus.yml`:

```yaml
lua:
  features:
    - name: "logging"
      path: "/etc/nauthilus/lua-plugins.d/features/logging.lua"
  filters:
    - name: "ip_blocklist"
      path: "/etc/nauthilus/lua-plugins.d/filters/ip_blocklist.lua"
```

3. Starten Sie Nauthilus neu:

```bash
docker-compose restart nauthilus
```

4. Testen Sie das Feature:

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"user1","password":"password1","client_ip":"127.0.0.1","service":"http"}' http://localhost:8080/api/v1/auth/json
```

## Zusammenfassung

In diesem Workshop haben wir die folgenden Themen behandelt:

1. **Einführung in Nauthilus**: Wir haben die Architektur und Hauptmerkmale von Nauthilus kennengelernt.
2. **Installation und Einrichtung**: Wir haben verschiedene Methoden zur Installation und Konfiguration von Nauthilus kennengelernt.
3. **Lua-Backends**: Wir haben gelernt, wie man benutzerdefinierte Authentifizierungsbackends in Lua implementiert.
4. **Lua-Filter**: Wir haben gelernt, wie man Filter implementiert, um Authentifizierungsanfragen zu validieren.
5. **Lua-Features**: Wir haben gelernt, wie man Features implementiert, um zusätzliche Funktionalität bereitzustellen.
6. **Monitoring und Debugging**: Wir haben verschiedene Möglichkeiten zum Monitoring und Debugging von Nauthilus kennengelernt.
7. **Fortgeschrittene Themen**: Wir haben fortgeschrittene Themen wie Load-Balancing, Sicherheit und Leistungsoptimierung behandelt.
8. **Beispielanwendungen**: Wir haben gesehen, wie Nauthilus in verschiedenen Szenarien eingesetzt werden kann.
9. **Praktische Übungen**: Wir haben praktische Übungen durchgeführt, um das Gelernte anzuwenden.

Nauthilus ist eine leistungsstarke und flexible Authentifizierungs- und Autorisierungsplattform, die sich an verschiedene Anwendungsfälle anpassen lässt. Durch die Verwendung von Lua-Skripten können Sie das Verhalten von Nauthilus erweitern und anpassen, um Ihren spezifischen Anforderungen gerecht zu werden.

## Weiterführende Ressourcen

- **Offizielle Website**: [https://nauthilus.org](https://nauthilus.org)
- **GitHub-Repository**: [https://github.com/croessner/nauthilus](https://github.com/croessner/nauthilus)
- **Dokumentation**: [https://nauthilus.org/docs/intro](https://nauthilus.org/docs/intro)
- **Mailing-Listen**: [https://lists.nauthilus.org](https://lists.nauthilus.org)

## Anhang

### Nützliche Lua-Funktionen

#### nauthilus_util

- `exists_in_table(tbl, element)`: Prüft, ob ein Element in einer Tabelle existiert
- `get_current_timestamp()`: Gibt einen Zeitstempel zurück
- `table_length(tbl)`: Berechnet die Länge einer Tabelle
- `if_error_raise(err)`: Wirft einen Fehler, wenn ein Fehler aufgetreten ist
- `is_table(object)`: Prüft, ob ein Objekt eine Tabelle ist
- `is_string(object)`: Prüft, ob ein Objekt ein String ist
- `is_number(object)`: Prüft, ob ein Objekt eine Zahl ist
- `toboolean(str)`: Konvertiert einen String in einen booleschen Wert
- `generate_random_string(length)`: Generiert einen zufälligen String
- `is_routable_ip(ip)`: Prüft, ob eine IP-Adresse routbar ist
- `print_result(logging, result, err_string)`: Gibt ein Ergebnis aus

#### nauthilus_builtin

- `custom_log_add(key, value)`: Fügt einen benutzerdefinierten Logeintrag hinzu
- `status_message_set(message)`: Setzt eine Statusmeldung

#### nauthilus_context

- `context_get(key)`: Holt einen Wert aus dem Kontext
- `context_set(key, value)`: Setzt einen Wert im Kontext

#### nauthilus_prometheus

- `increment_counter(name, labels)`: Erhöht einen Zähler
- `increment_gauge(name, labels)`: Erhöht eine Gauge
- `decrement_gauge(name, labels)`: Verringert eine Gauge
- `start_histogram_timer(name, labels)`: Startet einen Timer für ein Histogramm
- `stop_timer(timer)`: Stoppt einen Timer

### Beispiel: Vollständige Nauthilus-Konfiguration

```yaml
server:
  address: "0.0.0.0:8080"
  haproxy_v2: false
  max_concurrent_requests: 1000
  max_password_history_entries: 50

  basic_auth:
    enabled: true
    username: authserv
    password: authserv

  instance_name: "nauthilus"

  log:
    json: true
    color: false
    level: info
    debug_modules:
      - auth
      - lua

  backends: [ cache, ldap, lua ]
  features: [ brute_force, tls_encryption, rbl, relay_domains, lua ]
  brute_force_protocols: [ imap, imaps, submission, smtp, smtps ]

  dns:
    resolver: 10.0.118.1
    timeout: 3
    resolve_client_ip: false

  insights:
    enable_pprof: true
    enable_block_profile: true

  tls:
    enabled: true
    cert_file: "/etc/nauthilus/cert.pem"
    key_file: "/etc/nauthilus/key.pem"
    http_client_skip_verify: true

  monitoring:
    prometheus:
      enabled: true
      endpoint: "/metrics"

  master_user:
    enabled: true
    delimiter: "*"

redis:
  # Wenn Redis auf 127.0.0.1:6379 läuft, ist keine Konfiguration nötig
  # Für andere Ziele muss master: und replica: konfiguriert werden
  master:
    address: "127.0.0.1:6379"

  replica:
    addresses:
      - "127.0.0.1:6379"

  database_number: 0
  prefix: nt_
  pool_size: 10
  idle_pool_size: 5
  positive_cache_ttl: 3600
  negative_cache_ttl: 7200

realtime_blackhole_lists:
  threshold: 10

  lists:
    - name: SpamRats AuthBL
      rbl: auth.spamrats.com
      ipv4: true
      ipv6: true
      return_code: 127.0.0.43
      weight: 10
      allow_failure: true

  ip_whitelist:
    - 127.0.0.0/8
    - ::1
    - 192.168.0.0/16
    - 172.16.0.0/12
    - 10.0.0.0/8
    - fd00::/8
    - 169.254.0.0/16
    - fe80::/10

ldap:
  config:
    number_of_workers: 100
    lookup_pool_size: 4
    lookup_idle_pool_size: 1
    auth_pool_size: 4
    auth_idle_pool_size: 2
    server_uri: "ldaps://ldap.example.com:636/"
    tls_skip_verify: true
    bind_dn: "cn=nauthilus,ou=services,dc=example,dc=com"
    bind_pw: "geheim"

  search:
    - protocol: [ default, http ]
      cache_name: http
      base_dn: "ou=people,ou=it,dc=example,dc=com"
      filter:
        user: |
          (|
            (uniqueIdentifier=%L{user})
            (mail=%L{user})
          )
      mapping:
        account_field: mail
      attribute: mail

brute_force:
  ip_whitelist:
    - 127.0.0.0/8
    - ::1
    - 192.168.0.0/16
    - 172.16.0.0/12
    - 10.0.0.0/8
    - fd00::/8
    - 169.254.0.0/16
    - fe80::/10

  neural_network:
    max_training_records: 30000
    hidden_neurons: 20
    activation_function: relu

  buckets:
    - { name: b_1m_ipv4_32,  period: 1m,   cidr: 32, ipv4: true, failed_requests: 10 }
    - { name: b_1h_ipv4_24,  period: 1h,   cidr: 24, ipv4: true, failed_requests: 15 }
    - { name: b_1d_ipv4_24,  period: 24h,  cidr: 24, ipv4: true, failed_requests: 25 }
    - { name: b_1w_ipv4_24,  period: 168h, cidr: 24, ipv4: true, failed_requests: 40 }

    - { name: b_1m_ipv6_128, period: 1m,   cidr: 128, ipv6: true, failed_requests: 10 }
    - { name: b_1h_ipv6_64,  period: 1h,   cidr: 64,  ipv6: true, failed_requests: 15 }
    - { name: b_1d_ipv6_64,  period: 24h,  cidr: 64,  ipv6: true, failed_requests: 25 }
    - { name: b_1w_ipv6_64,  period: 168h, cidr: 64,  ipv6: true, failed_requests: 40 }

lua:
  features:
    - name: "blocklist"
      script_path: "/etc/nauthilus/lua-plugins.d/features/blocklist.lua"
    - name: "neural"
      script_path: "/etc/nauthilus/lua-plugins.d/features/neural.lua"

  filters:
    - name: "geoip"
      script_path: "/etc/nauthilus/lua-plugins.d/filters/geoip.lua"

  config:
    package_path: "/etc/nauthilus/lua/lib/?.lua"
```

Dieses umfassende Workshop-Dokument bietet Ihnen alle Informationen, die Sie benötigen, um Nauthilus zu verstehen, zu installieren, zu konfigurieren und zu erweitern. Wir hoffen, dass Sie diesen Workshop genießen und Nauthilus für Ihre Authentifizierungs- und Autorisierungsanforderungen nutzen können.
