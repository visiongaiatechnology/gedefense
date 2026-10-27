# L7 Inline Producer — first-class traffic path without a web-server plugin

**Status:** verbindlich für GeDefense Linux 5.1.0-beta.1
**Gilt für:** `control/l7_edge.go`, `control/l7_types.go`
**Ziel:** Der Inline-Edge-Pfad ist ein vollwertiger L7-Produzent. Es ist **kein** zusätzliches
Webserver-Plugin, kein separates Paket und kein externer Producer-Daemon nötig: der
Webserver (oder ein Edge-Proxy) leitet den HTTP-Verkehr über den Unix-Socket
`/run/vgt-gedefense-l7/edge.sock`. Die L7-Engine inspiziert den Request, blockt
Payloads und leitet erlaubte Requests an den in `gedefense.toml` konfigurierten
Upstream weiter.

---

## 1. Was der Inline-Edge leistet

```
Client ──TLS──▶ nginx/Apache/Envoy ──HTTP über Unix-Socket──▶ GeDefense L7 Edge
                                                                  │  Inspect (block/allow)
                                                                  ▼
                                                   http://127.0.0.1:<app-port> (Upstream)
```

- **Request-Inspektion:** dieselbe L7-Engine wie der Socket-Producer (Normalisierung,
  Detektoren, Release-Gate, Rate-Limit, Findings).
- **Blocking:** `mode = "block"` und freigegebenes Release-Gate ⇒ HTTP 403, der Upstream
  wird **nicht** kontaktiert.
- **Response-Inspektion:** Antwort-Prefix (inkl. gzip/deflate, mit Byte-Limit) wird
  inspiziert; der Wire-Body bleibt unverändert.
- **Peer-Bindung:** Der Socket ist nur für User/Gruppen aus `l7.allowed_peer_uids` /
  `l7.allowed_peer_gids` bzw. die Socket-Gruppe `l7.socket_group` nutzbar
  (SO_PEERCRED, Linux). Der reservierte Self-Test-Pfad `/__gedefense_selftest__` ist
  ausschließlich für die eigene Control-Prozess-Identität nutzbar.
- **Status:** Der Inline-Edge zählt als angehängter Produzent, sobald er aktiv Traffic
  inspiziert hat. Ein gebundener, aber stiller Socket ist „attached“, aber nicht
  „verified“ und nicht „producer“.

---

## 2. Status-Semantik (API `GET /api/v1/status`, Feld `l7`)

| Feld | Bedeutung |
|---|---|
| `producer_attached` | `true`, wenn **entweder** der Socket-Producer Traffic geliefert hat **oder** der Inline-Edge verifizierten Traffic inspiziert hat (`inline_requests_total > 0` und `inline_healthy`) |
| `inline_producer_attached` | `true` nur, wenn Inline-Edge aktiviert, **healthy** und mindestens ein Request inspiziert wurde |
| `inline_attachment_reason` | Klartextgrund: disabled / unhealthy / awaiting first request / verified |
| `traffic_path_attached` | Ein Pfad ist verdrahtet und nutzbar (Inline-Listener gesund, Socket-Producer-Traffic oder TLS-Telemetrie) |
| `traffic_path_verified` | Abgeleitetes Coverage-Verdikt `TRAFFIC_ACTIVE`; ohne beobachteten HTTP-Traffic nie `true` |
| `requests_total` | **aggregiert**: Socket-Producer + Inline-Edge |
| `findings_total` | **aggregiert**: Socket-Findings + Inline-Request-Findings + Response-Findings |
| `blocked_total` | **aggregiert**: Socket-Blocks + Inline-Blocks |
| `rate_limited_total` | Socket-Rate-Limits (der Inline-Edge hat keinen eigenen Rate-Limiter) |
| `inline_requests_total` / `inline_blocked_total` / `inline_findings_total` | Inline-Teilmenge, unverändert separat ausgewiesen |
| `inline_last_request_at` | Zeitpunkt des letzten über den Edge inspizierten Requests |
| `last_inspection` / `last_producer_seen` | letzter beobachteter Request-Zeitpunkt; `last_producer_seen` nur bei angehängtem Produzenten |

Erwartet auf einem reinen Inline-Host nach echtem Traffic:

```json
{
  "producer_attached": true,
  "inline_producer_attached": true,
  "traffic_path_attached": true,
  "traffic_path_verified": true,
  "coverage": "TRAFFIC_ACTIVE",
  "inline_requests_total": 17,
  "requests_total": 17,
  "inline_blocked_total": 1,
  "blocked_total": 1,
  "inline_attachment_reason": "inline listener has inspected request traffic (17 request(s) inspected)"
}
```

---

## 3. Webserver-Konfiguration

### 3.1 Voraussetzungen

1. `l7.inline_enabled = true` und `l7.inline_upstream = "http://127.0.0.1:<app-port>"`.
2. Der Upstream muss ein **Loopback-Ziel** sein (der Validator lehnt Nicht-Loopback ab).
3. Der Webserver-User (bzw. eine seiner Gruppen) muss in `l7.socket_group` oder
   `l7.allowed_peer_gids` stehen; der Runtime-Parent `/run/vgt-gedefense-l7` muss
   existieren, darf nicht world/group-writable sein und wird vom Control-Prozess
   vorbereitet.
4. Der Unix-Socket ist **kein** TLS-Endpunkt. TLS terminiert weiterhin der Webserver.

### 3.2 nginx — direkter Upstream (empfohlen)

```nginx
# /etc/nginx/conf.d/gedefense-l7-upstream.conf
upstream gedefense_l7_edge {
    server unix:/run/vgt-gedefense-l7/edge.sock;
    keepalive 16;
}
```

```nginx
# In dem EXISTING server-Block, der TLS für diese Site terminiert:
location / {
    proxy_http_version 1.1;
    proxy_set_header Host                   $host;
    proxy_set_header X-Gedefense-Client-Ip $remote_addr;
    proxy_set_header X-Gedefense-Original-Scheme $scheme;
    proxy_set_header Connection             "";

    proxy_connect_timeout 3s;
    proxy_send_timeout    30s;
    proxy_read_timeout    30s;
    proxy_pass http://gedefense_l7_edge;
}
```

Kurzform ohne `upstream`-Block (identische Semantik):

```nginx
location / {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Gedefense-Client-Ip $remote_addr;
    proxy_set_header X-Gedefense-Original-Scheme $scheme;
    proxy_set_header Connection "";
    proxy_pass http://unix:/run/vgt-gedefense-l7/edge.sock:/;
}
```

> Der `:/`-Teil der `proxy_pass`-URI ist nginx-Syntax für „Socket-Pfad + leerer
> Path-Teil“. Er ist nicht der Anwendungspfad; der Pfad des Original-Requests bleibt
> erhalten.

### 3.3 nginx + PHP-FPM (interner Loopback-Origin)

Wenn nginx FastCGI zu PHP-FPM spricht, braucht der Upstream eine interne
Loopback-Origin, die nur über den Edge erreichbar ist:

```nginx
server {
    listen 127.0.0.1:8080;
    server_name _;
    root /var/www/html;
    index index.php index.html;

    location / { try_files $uri $uri/ /index.php?$args; }
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php-fpm.sock;
    }
}
```

`l7.inline_upstream` zeigt dann auf `http://127.0.0.1:8080`. Die öffentliche Site leitet
mit dem Block aus 3.2 an den Edge. Der interne Block darf niemals auf `0.0.0.0`
wechseln.

### 3.4 Apache httpd 2.4.7+ (mod_proxy, UDS)

```apache
# a2enmod proxy proxy_http headers ssl

<VirtualHost *:443>
    ServerName example.test
    # TLS-Konfiguration bleibt hier.

    ProxyRequests Off
    ProxyPreserveHost On

    RequestHeader set X-Gedefense-Client-Ip "%{REMOTE_ADDR}s"
    RequestHeader set X-Gedefense-Original-Scheme "https"

    # Edge-Socket ist das einzige Origin, das Apache kennt.
    ProxyPass        / "unix:/run/vgt-gedefense-l7/edge.sock|http://127.0.0.1/"
    ProxyPassReverse / "http://127.0.0.1/"
</VirtualHost>
```

Der rechte Teil (`|http://127.0.0.1/`) ist nur der synthetische URL-Kontext für
`ProxyPassReverse`; das Ziel ist ausschließlich der Unix-Socket.

### 3.5 Envoy (Pipe-Cluster)

```yaml
clusters:
  - name: gedefense_l7_edge
    connect_timeout: 1s
    type: STATIC
    load_assignment:
      cluster_name: gedefense_l7_edge
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  pipe:
                    path: /run/vgt-gedefense-l7/edge.sock
    transport_socket:
      name: envoy.transport_sockets.raw_buffer
```

```yaml
http_filters:
  - name: envoy.filters.http.router

route_config:
  name: local_route
  virtual_hosts:
    - name: main
      domains: ["*"]
      routes:
        - match: { prefix: "/" }
          route:
            cluster: gedefense_l7_edge
            timeout: 30s
            request_headers_to_add:
              - header:
                  key: "X-Gedefense-Client-Ip"
                  value: "%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%"
              - header:
                  key: "X-Gedefense-Original-Scheme"
                  value: "%REQ(X-FORWARDED-PROTO)%"
```

Envoy muss als User/Gruppe laufen, der/die laut `l7.socket_group` bzw.
`l7.allowed_peer_gids` zugelassen ist.

### 3.6 Caddy 2

```caddyfile
example.test {
    # TLS bleibt bei Caddy.
    reverse_proxy unix//run/vgt-gedefense-l7/edge.sock {
        header_up X-Gedefense-Client-Ip {remote_host}
        header_up X-Gedefense-Original-Scheme {scheme}
        transport http {
            dial_timeout 3s
            response_header_timeout 30s
        }
    }
}
```

---

## 4. Sicherheitsinvarianten (nicht abschwächen)

Der Inline-Edge ändert nichts an den folgenden Grenzen:

- **Peer-Credentials sind Pflicht.** Ein Request ohne SO_PEERCRED (Linux) oder von einer
  Identität außerhalb der Allowlist wird mit 403 abgelehnt, bevor inspiziert wird.
- **Kein Vertrauen in Client-Header.** `X-Gedefense-Client-Ip` und
  `X-Gedefense-Original-Scheme` werden nur ausgewertet, wenn der Peer autorisiert ist;
  sie werden **nicht** an den Upstream weitergegeben.
- **Header-Härtung:** `Forwarded`, `X-Forwarded-*`, `X-Real-Ip` werden entfernt und
  durch peer-belegte Werte ersetzt (`X-Forwarded-For` = Client-IP,
  `X-Forwarded-Proto` = Origin-Schema). Alle Hop-by-Hop-Header (inkl. der per
  `Connection` nominierten Felder) werden entfernt.
- **Body-/Header-Limits:** `l7.max_body_bytes`, `l7.max_header_bytes`,
  `l7.max_envelope_bytes` greifen vor der Weiterleitung. Ein zu großer Body ⇒ 413,
  ein zu großer Header-Block ⇒ HTTP-Server-Abbruch vor dem Upstream.
- **Timeouts:** `l7.request_timeout_millis` begrenzt Admission und Inspektion; der
  Upstream-Dial hat 3 s, Response-Header 30 s, Idle-Connections 90 s.
- **Upstream-Isolation:** Der Transport dialt ausschließlich das konfigurierte
  Loopback-Ziel (kein Proxy, keine Redirects); `Host` bleibt der Original-Host.
- **SSRF:** Der Validator akzeptiert nur `http`/`https`, Loopback-Host und expliziten
  Port, ohne Credentials/Query/Fragment.

---

## 5. Verifikation auf dem Host

### 5.1 Benign request (muss durchgehen)

```bash
curl -sS -i --unix-socket /run/vgt-gedefense-l7/edge.sock \
  -H 'Host: example.test' \
  -H 'X-Gedefense-Client-Ip: 203.0.113.10' \
  -H 'X-Gedefense-Original-Scheme: https' \
  http://localhost/health
# erwartet: HTTP/1.1 200 (oder der Status des App-Endpunkts); Upstream-Access-Log +1
```

### 5.2 Blocking-Payloads (müssen 403 liefern, Upstream bleibt unberührt)

```bash
# SQLi (UNION SELECT, doppelt url-kodiert)
curl -sS -o /dev/null -w '%{http_code}\n' --unix-socket /run/vgt-gedefense-l7/edge.sock \
  -H 'Host: example.test' -H 'X-Gedefense-Client-Ip: 203.0.113.10' \
  -H 'X-Gedefense-Original-Scheme: https' \
  'http://localhost/?q=%2555NION%2520SELECT%2520password%2520FROM%2520users--'
# erwartet: 403

# XSS
curl -sS -o /dev/null -w '%{http_code}\n' --unix-socket /run/vgt-gedefense-l7/edge.sock \
  -H 'Host: example.test' -H 'X-Gedefense-Client-Ip: 203.0.113.10' \
  -H 'X-Gedefense-Original-Scheme: https' \
  'http://localhost/?x=%3Cscript%3Ealert(1)%3C/script%3E'
# erwartet: 403

# Path-Traversal/LFI (Stream-Wrapper + Traversal)
curl -sS -o /dev/null -w '%{http_code}\n' --unix-socket /run/vgt-gedefense-l7/edge.sock \
  -H 'Host: example.test' -H 'X-Gedefense-Client-Ip: 203.0.113.10' \
  -H 'X-Gedefense-Original-Scheme: https' \
  'http://localhost/?file=php://filter/convert.base64-encode/resource=../../etc/passwd'
# erwartet: 403
```

Hinweis: Der Edge antwortet auf Block mit `403` und
`{"error":"request rejected"}`. Der Upstream darf im Access-Log keinen korrespondierenden
Eintrag zeigen.

### 5.3 Status prüfen

```bash
# Default-Credential des Control-API (siehe gedefense.toml `dashboard.token_file`)
TOKEN=$(sudo cat /var/lib/vgt/gedefense/dashboard.token)
curl -sS -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:9844/api/v1/status \
  | jq '.l7 | {coverage, producer_attached, inline_producer_attached, traffic_path_verified,
                inline_attachment_reason, requests_total, inline_requests_total,
                blocked_total, inline_blocked_total, inline_last_request_at}'
```

Erwartung nach 5.1 + 5.2:

```
coverage: "TRAFFIC_ACTIVE"
producer_attached: true
inline_producer_attached: true
traffic_path_verified: true
inline_attachment_reason: "inline listener has inspected request traffic (...)"
requests_total >= 3   # aggregiert, inkl. der geblockten Requests
inline_requests_total >= 3
blocked_total >= 3
```

### 5.4 Self-Test

```bash
TOKEN=$(sudo cat /var/lib/vgt/gedefense/dashboard.token)
curl -sS -X POST -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' -d '{}' \
  http://127.0.0.1:9844/api/v1/l7/selftest | jq
```

Der Self-Test nutzt den reservierten Pfad über den echten Edge-Socket; ein PASS setzt
`inline_healthy=true` und bewegt `inline_requests_total`.

---

## 6. Betriebs-/Troubleshooting-Hinweise

| Symptom | Ursache / Abhilfe |
|---|---|
| `403 request rejected` bereits bei benignem Traffic | Peer-Identität nicht in `l7.allowed_peer_uids`/`l7.allowed_peer_gids`/`l7.socket_group`; Webserver-User prüfen |
| `502 upstream unavailable` | `l7.inline_upstream` zeigt auf ein nicht lauschendes Loopback-Ziel; App-Port prüfen |
| `413 request body rejected` | Body > `l7.max_body_bytes`; Limit bewusst anheben oder Upload am Edge vorbei (nicht empfohlen) |
| `503 request inspection busy` | Admission-Budget erschöpft (Engine-Sättigung); Rate/Budget prüfen |
| `producer_attached=false` trotz Traffic | Edge nicht über den Socket angesprochen (Webserver-Block nicht aktiv) oder Status aus altem Build; `inline_requests_total` prüfen |
| `inline_producer_attached=false`, aber `traffic_path_attached=true` | Listener gebunden, aber noch kein Request inspiziert — normal im Leerlauf |
| `traffic_path_verified=false` | Kein HTTP-Traffic beobachtet oder Inline-Pfad unhealthy (`inline_last_error` prüfen) |

---

## 7. Bewusste Grenzen

- Der Edge terminiert **kein** TLS und spricht **kein** FastCGI. TLS/FastCGI bleiben
  Aufgabe des Webservers.
- `l7.inline_upstream` muss Loopback sein; ein Remote-Upstream wird abgelehnt.
- Der Inline-Edge hat keinen eigenen Rate-Limiter; `rate_limited_total` bleibt der
  Socket-Producer-Zähler.
- Consumer, die `requests_total` bisher selbst um `inline_requests_total` ergänzt haben,
  müssen auf den aggregierten Wert umgestellt werden (sonst Doppelzählung). Betroffen ist
  die Web-UI (`control/web/l7.js`), die außerhalb des Änderungsumfangs dieses Tasks
  liegt.
