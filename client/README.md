# Nauthilus Test Client

Ein CSV-gesteuerter Test-/Last-Client für Nauthilus. Erstellt JSON-Requests entsprechend `server/model/authdto/json_request.go` und validiert die Antwort.

## Features
- CSV-Input mit Spalten wie `username`, `password`, `client_ip`, `user_agent`, `protocol`, `method`, SSL-Felder (`ssl`, `ssl_protocol`, `ssl_cipher`, `ssl_client_verify`, ...)
- Erwartungsprüfung per `expected_ok` (bool) in der CSV
- Parallelität (`--concurrency`), Ratenlimit (`--rps`), Jitter (`--jitter-ms`), Delay (`--delay-ms`)
- Zeit-/Zyklensteuerung: Gesamtlaufzeit (`--duration`, z. B. 5m) – der Client loopt solange über die CSV; alternativ Anzahl Durchläufe (`--loops`) und optional Mindestdauer pro Zyklus (`--cycle-min`)
- Optionales Shuffling, Timeout, Zusatz-Header
- Antwortvalidierung über JSON-Feld `{ "ok": true|false }` oder via HTTP-Status

## Verzeichnisstruktur
```
client/
  main.go
  go.mod
  logins.csv   # Beispiel-CSV
  README.md    # diese Datei
server/
  lua-plugins.d/
    init/
      testing_csv_loader.lua
    backend/
      testing_csv_backend.lua
```

## CSV-Format
Pflicht: Kopfzeile und Spalte `expected_ok`.

Beispiel `client/logins.csv`:
```
username,password,client_ip,expected_ok,user_agent,protocol,method,ssl,ssl_protocol,ssl_cipher,ssl_client_verify,ssl_client_cn
alice,secret,198.51.100.10,true,MyTestClient/1.0,imap,PLAIN,on,TLSv1.3,TLS_AES_128_GCM_SHA256,SUCCESS,alice-cn
bob,badpass,198.51.100.11,false,MyTestClient/1.0,imap,PLAIN,on,TLSv1.3,TLS_AES_128_GCM_SHA256,FAIL,bob-cn
```
Alle unbekannten Spalten werden ignoriert. Der Client sendet nur Schlüssel, die im Server in `authdto.Request` definiert sind.

## Build
Voraussetzung: Go 1.25.x

```
cd client
go build -o nauthilus-testclient
```

## Run
```
./nauthilus-testclient \
  --csv ./logins.csv \
  --url http://localhost:8080/auth \
  --concurrency 32 \
  --rps 200 \
  --jitter-ms 50 \
  --json-ok
```

- `--headers` erlaubt zusätzliche Header, getrennt per `||` (Standard: `Content-Type: application/json`).
- Der Client setzt zusätzlich `X-Forwarded-For` aus der CSV-Spalte `client_ip`.

## Server mit Test-Konfiguration starten
Eine lauffähige Beispielkonfiguration liegt unter `client/nauthilus.yml`. Sie aktiviert den Lua‑Backendpfad und lädt die CSV über das Init‑Plugin in den Go‑Cache.

Start des Servers mit der Testkonfiguration:
```
TESTING_CSV=client/logins.csv \
./nauthilus -config client/nauthilus.yml -config-format yaml
```

Hinweise:
- `server.address` ist auf `0.0.0.0:8080` gesetzt. Der Client erwartet standardmäßig `http://localhost:8080/auth`.
- Das Lua‑Backend ist auf `server/lua-plugins.d/backend/testing_csv_backend.lua` verdrahtet und lädt beim Start `server/lua-plugins.d/init/testing_csv_loader.lua`.
- Redis wird lokal auf `127.0.0.1:6379` erwartet (siehe `server.redis`).

## cURL-Beispiel (Server)
```
curl -sS -X POST http://localhost:8080/auth \
 -H 'Content-Type: application/json' \
 -H 'X-Forwarded-For: 198.51.100.10' \
 -d '{
  "username":"alice",
  "password":"secret",
  "client_ip":"198.51.100.10",
  "user_agent":"MyTestClient/1.0",
  "protocol":"imap",
  "method":"PLAIN",
  "ssl":"on",
  "ssl_protocol":"TLSv1.3",
  "ssl_cipher":"TLS_AES_128_GCM_SHA256",
  "ssl_client_verify":"SUCCESS",
  "ssl_client_cn":"alice-cn"
}'
```

## Hinweise
- Die Server-Antwort sollte `{ "ok": true|false }` enthalten, wenn `--json-ok` verwendet wird.
- Alternativ kann mit `--json-ok=false` über HTTP-Status (Default: 200) validiert werden.
- Testdaten niemals produktiv verwenden.


## Große CSV generieren (z. B. 10.000 Zeilen)
Die CSV kann nun direkt vom Client erzeugt werden. Alle Spalten werden passend gefüllt und die Datei `client/logins.csv` wird überschrieben.

Voraussetzung: Go 1.25.x

Beispiel (10.000 Zeilen):
```
./nauthilus-testclient --generate-csv --generate-count 10000 --csv client/logins.csv
```

oder ohne vorherigen Build:
```
cd client
go run . --generate-csv --generate-count 10000 --csv ./logins.csv
```

Details:
- Es werden deterministische Daten erzeugt (`user00001` bis `userNNNNN`).
- Spalten: `username,password,client_ip,expected_ok,user_agent,protocol,method,ssl,ssl_protocol,ssl_cipher,ssl_client_verify,ssl_client_cn`.
- Werte sind deterministisch (abwechselndes `expected_ok`, rotierende IPs in 198.51.100.0/24, wechselnde Protokolle/Methoden/SSL-Parameter).
- Der Lua-Init-Loader (`server/lua-plugins.d/init/testing_csv_loader.lua`) und der Go-Client erwarten standardmäßig `client/logins.csv`. Die Generierung schreibt genau dieses Format.

Hinweis: Das Repository enthält bewusst nur eine kleine Beispiel-CSV. Für Lasttests die Generierung wie oben nutzen.
