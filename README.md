# blueferry-plugin-shortcuts

iOS Shortcuts bridge for BlueFerry: clipboard, links and battery from your iPhone.

A plugin for [BlueFerry](https://github.com/joshii-h/blueferry). iOS
Shortcuts can send HTTP requests; this plugin is the receiver on the PC. It
runs a small HTTPS endpoint in your LAN and shows what arrives through
BlueFerry's generic plugin surfaces (plugin API 1.2, settings form 1.3): a **card** on the
phone page and desktop **notifications**. It runs as its own process on the
session bus and talks to BlueFerry only through `blueferry.plugin_api`.

| Request | What happens on the PC |
| --- | --- |
| `POST /clipboard` | Text (optionally an image) goes to the desktop clipboard via `wl-copy`, marked as sensitive so clipboard managers keep it out of their history (wl-clipboard 2.3+). Notification "Clipboard from iPhone". |
| `GET /clipboard` | Returns the PC clipboard as text, so a shortcut can copy it to the iPhone. **Off by default.** |
| `POST /link` | Notification with the host name and an "Open" button that opens the full URL (http/https only). Sign-in data in the link (`https://user:password@host/…`) is removed first and the notification says so. |
| `POST /battery` | Card item "iPhone battery 87 % ⚡ charging" with the time of the report. |
| `GET /ca.crt`, `GET /ca.mobileconfig` | The plugin's CA certificate, raw or as an iOS profile (no token needed; it is public). |
| `GET /setup/<nonce>`, `GET /setup`, `POST /setup/test` | The guided setup (one-time link, then a 30-minute session cookie). |
| `GET /` | A plain page pointing to "Set up iPhone" in BlueFerry. |

## Install

```sh
blueferry plugins install https://github.com/joshii-h/blueferry-plugin-shortcuts
```

or pick "iOS Shortcuts bridge" in BlueFerry's settings, Plugins. This needs a
BlueFerry whose clients understand plugin API 1.2 (`card`, `notify`).

The endpoint must be running for the iPhone to reach it. BlueFerry starts
the plugin through D-Bus when it shows the phone card. To have it running
from login on, without a BlueFerry window:

```sh
blueferry plugins shortcuts setup --autostart     # or: blueferry-shortcuts setup --autostart
```

`blueferry-shortcuts show` prints the URL, token and certificate
fingerprint; `forget` removes token, settings and certificates.

## Settings

BlueFerry's settings, Plugins > iOS Shortcuts bridge, or
`blueferry plugins config io.weirdware.blueferry.shortcuts --set KEY=VALUE`.
The form groups the settings under "Options" and "Advanced"; **Test
connection** (`--test` in the CLI) asks the running endpoint for its
certificate like the iPhone would ("Reachable at https://192.168.1.20:47801."),
or, for a new address or port, checks that it is free. Nothing is saved or
restarted by the test.

| Setting | Default | Meaning |
| --- | --- | --- |
| `bind_address` | empty | IP address or interface name to listen on. Empty: the IPv4 address of the interface that carries the default route; a VPN or tunnel (wg*, tun*, tap*, ppp* or that type) is passed over for a LAN interface, and the card shows a hint. Followed automatically when that address changes. |
| `allow_all_interfaces` | off | Required for `0.0.0.0` / `::`. Without it a wildcard address is refused. |
| `port` | 47801 | TCP port. |
| `token` | generated | Access token (`Authorization: Bearer <token>`). Created on first start; "New token" on the card replaces it. |
| `allow_clipboard_read` | off | Enables `GET /clipboard`. Anyone with the token could then read what you copy. |
| `accept_images` | off | Accept PNG, JPEG, GIF or WebP images up to 10 MB on `POST /clipboard`. |
| `shortcut_url` | empty | iCloud link of the shared "BlueFerry" shortcut, offered on the setup page. |
| `allow_http` | off | Plain HTTP in approved networks only; see *Unencrypted in the home network*. |
| `http_port` | 47800 | Port of the plain-HTTP listener. |
| `http_networks` | empty | Approved NetworkManager profiles (names; delete one to remove it). |

## Security

- Listens on one LAN address only, never on all interfaces without opt-in.
- HTTPS with a private CA created on this PC (ECDSA P-256; CA 10 years,
  server certificate 397 days, renewed automatically and re-issued when the
  address changes; the iPhone trusts the CA once).
- Every endpoint except `/`, `/ca.crt`, `/ca.mobileconfig` and the setup
  pages needs the token; it is compared in constant time. The setup page
  shows the token only after a one-time link: 128 random bits, valid ten
  minutes, spent by its first use and turned into an HttpOnly session
  cookie (30 minutes); wrong links count as failed logins. The page is
  self-contained with a strict Content-Security-Policy (`default-src
  'none'`, style and script by hash). The PC page with the QR code listens
  on 127.0.0.1 only, under a random path, and checks the `Host` header.
- While a setup runs, a probe on the next port (47802) with its own
  certificate from the same CA tells the setup page whether the iPhone
  trusts the CA. 30 requests per minute per address; after 5 failed tokens
  in 10 minutes the address is locked out for the rest of the window.
- Limits: text 64 KB, images 10 MB (opt-in), other bodies 8 KB; bodies need
  `Content-Length`; at most 8 connections and two per address, one request
  per connection. Each request has a total deadline (20 s for handshake and
  headers; a body gets 20 s more plus one second per 32 KiB), so a client
  trickling bytes cannot hold a connection.
- No request content is logged, and nothing is forwarded to the network:
  requests only reach the clipboard, the card and notifications.
  Notifications for the clipboard show the length, not the text; links show
  only the host, never path or query. User name and password in a link are
  stripped before the link reaches BlueFerry and are never logged.
- Failed TLS handshakes (for example an iPhone that does not trust the CA
  yet) are logged at debug level with the TLS reason only, no address.
- Token, settings and keys are owner-only files in
  `~/.config/blueferry/plugins/io.weirdware.blueferry.shortcuts/`. The token is
  not kept in the keyring on purpose: you need to read it to type it into
  the Shortcuts app, and the card shows it (masked until you reveal it,
  hidden again after two minutes).

## Set up your iPhone (English)

iPhone and PC must be in the same network.

1. In BlueFerry, on the phone card at **Shortcuts bridge**, choose
   **Set up iPhone**. Your browser opens a page on the PC with a **QR code**.
2. Scan it with the iPhone's **Camera** and tap the link. Safari warns once
   that the connection is not private: *Show Details* > *visit this website*
   > *Visit Website*. That is expected before the certificate is installed.
   The link works **once** and for **ten minutes**; the PC page renews it.
3. The setup page on the iPhone walks you through:
   - **Install the certificate**: *Download profile* > *Allow*, then
     *Settings* > *Profile Downloaded* > *Install*. Then the one step iOS
     insists on for every self-installed root certificate: *Settings* >
     *General* > *About* > *Certificate Trust Settings* > switch on
     "BlueFerry Shortcuts CA (…)". The page notices by itself when the trust
     is active and shows ✅.
   - **Add the shortcut**: *Add the "BlueFerry" shortcut* opens the iCloud
     link; Shortcuts asks two questions (address and token); the page has a
     big *Copy* button for each. The first run asks whether Shortcuts may
     find devices on your local network: *Allow*.
   - **Test now**: the PC shows the notification "iPhone connected ✅".
   - Optional: automations that send the battery level when the charger is
     connected or disconnected (iOS cannot import automations, so the page
     explains the three taps).
4. The card shows the state: *iPhone not set up yet*, *Certificate probably
   missing on the iPhone* (the iPhone refused the TLS connection), or
   *iPhone last connected 5 min ago*.

Opening `https://<PC>:47801/` without the setup link only shows a page that
points to "Set up iPhone"; the token is only ever shown after a valid
one-time link.

### The BlueFerry shortcut

One shortcut, "BlueFerry", does everything: a menu (*Clipboard → PC*,
*PC → Clipboard*, *Link → PC*, *Battery → PC*), the share sheet (links from
Safari and other apps) and the input words `battery`, `battery-charging`
and `battery-unplugged` for automations. Unsigned `.shortcut` files cannot
be imported since iOS 15 and signing needs a Mac, so the shortcut is shared
as an **iCloud link with import questions** for address and token.

The setting **Shortcut link** (`shortcut_url`) holds that iCloud link; the
setup page offers it as *Add shortcut*. Without a link the page says so and
still shows address and token to copy; build the shortcut as described
under *Advanced: manual setup* below.

### Unencrypted in the home network

The certificate is the biggest hurdle. If you accept the trade-off, turn on
**Allow unencrypted in the home network (HTTP)** (`allow_http`, Advanced,
**off by default**). Then anyone in the same Wi-Fi can read what the
shortcuts send. The rules:

- A second listener speaks plain HTTP on `http_port` (47800). It accepts
  only private and link-local peers (10/8, 172.16/12, 192.168/16,
  169.254/16, fc00::/7, fe80::/10, loopback); the token is still required.
- **Reading the PC clipboard (`GET /clipboard`) is always refused over
  HTTP** (403), whatever the settings say.
- It listens **per network**: turning it on approves the NetworkManager
  connection profile that carries the default route now. Profiles are
  identified by UUID, not by SSID, so an evil twin "Home" in a café is a
  different, foreign network. In any other network the listener closes at
  once (NetworkManager signals) and the card shows *Unencrypted paused:
  foreign network* with **Approve this network**.
- **Open Wi-Fi** (no password, WEP or OWE) is never accepted, not even when
  approved. **Without NetworkManager** plain HTTP is not available.
- The approved networks are listed in the setting *Approved networks*
  (delete a name to remove it) and with
  `blueferry-shortcuts networks [list|allow-current|remove NAME]`.

With HTTP active in an approved network, the QR code points to the HTTP
address, Safari opens the setup page without a warning, and the
certificate step is marked *optional, recommended*. When the certificate
is trusted later, the page switches the shown address to HTTPS.

### Advanced: manual setup

You need the **URL** (e.g. `https://192.168.1.20:47801`), the **token** and
the **fingerprint**. In BlueFerry open the phone card, "Shortcuts bridge" >
"Show setup data" ("Reveal" shows the token), or run `blueferry-shortcuts show`.

#### Step 0: trust the certificate (once)

1. On the iPhone open **Safari** at `https://<PC address>:47801/ca.crt`.
   Safari warns that the connection is not private (expected: the phone does
   not know the CA yet): *Show Details* > *visit this website* > *Visit Website*.
2. *Allow* the download of the configuration profile.
3. **Settings** > *Profile Downloaded* (or *General* > *VPN & Device Management*)
   > "BlueFerry Shortcuts CA (…)" > *Install*. Under *More Details* the
   certificate's **SHA-256** must match the fingerprint BlueFerry shows.
4. **Settings** > *General* > *About* > *Certificate Trust Settings*: switch on
   full trust for "BlueFerry Shortcuts CA (…)".

Without step 4 every shortcut fails with an SSL error.

#### The request action

All three shortcuts use **Get Contents of URL**. Tap the arrow (*Show More*)
to see the options:

| Field | Value |
| --- | --- |
| URL | `https://<PC address>:47801/<endpoint>` |
| Method | `POST` (or `GET` for "From PC") |
| Headers | key `Authorization`, value `Bearer <token>` (one space after `Bearer`) |
| Request Body | `JSON`, fields as below |

#### Shortcut 1: "To PC: Clipboard"

1. New shortcut, name it **To PC: Clipboard**.
2. Action **Get Clipboard**.
3. Action **Get Contents of URL**: URL `https://<PC>:47801/clipboard`, Method
   `POST`, header as above, Request Body `JSON` with one field:
   key `text`, type **Text**, value: the magic variable **Clipboard**.
4. Optional: action **Show Notification** "Sent".

Images (with `accept_images` on): use Request Body **File** with the
clipboard image instead of JSON. The plugin accepts PNG, JPEG, GIF and WebP;
HEIC photos need a **Convert Image** (JPEG) action first.

Links: a variant with URL `…/link` and JSON field `url` (type Text) sends a
link; turn on *Show in Share Sheet* (Shortcut details) and use
*Shortcut Input* as the value to send the current Safari page.

#### Shortcut 2: "From PC: Clipboard"

Needs `allow_clipboard_read` on.

1. New shortcut **From PC: Clipboard**.
2. Action **Get Contents of URL**: URL `https://<PC>:47801/clipboard`, Method
   `GET`, header `Authorization` = `Bearer <token>`, no body.
3. Action **Copy to Clipboard** with *Contents of URL*.

#### Shortcut 3: "To PC: Battery"

1. New shortcut **To PC: Battery**.
2. Action **Get Battery Level**.
3. Action **Get Contents of URL**: URL `https://<PC>:47801/battery`, Method
   `POST`, header as above, Request Body `JSON` with
   - key `level`, type **Number**, value *Battery Level*
   - key `charging`, type **Boolean**: see the automations below.

`charging` is optional: if it is missing, the PC keeps the last known state.

Automations (*Automation* tab > *New Automation*, choose *Run Immediately*):

- **Charger** > *Is Connected*: run the actions above with `charging` = **True**.
- **Charger** > *Is Disconnected*: the same with `charging` = **False**.
- Every half hour: iOS has no interval trigger. Create **Time of Day**
  automations for the times you want (e.g. 08:00, 08:30, …) that run
  **To PC: Battery** without the `charging` field; on recent iOS versions you
  can fill it with the action **Is Charging** instead. A **Battery Level**
  automation (*Falls Below* 50 % / 20 %) is a lighter alternative.

## iPhone einrichten (Deutsch)

iPhone und PC müssen im selben Netz sein.

1. In BlueFerry auf der Telefonkarte bei **Kurzbefehle-Brücke** auf
   **iPhone einrichten** tippen. Auf dem PC öffnet sich eine Seite mit einem
   **QR-Code**.
2. Mit der **Kamera** des iPhones scannen und den Link antippen. Safari warnt
   einmal, die Verbindung sei nicht privat: *Details einblenden* > *diese
   Website besuchen* > *Website besuchen*. Das ist vor dem Zertifikat normal.
   Der Link gilt **einmal** und **zehn Minuten**; die PC-Seite erneuert ihn.
3. Die Einrichtungsseite auf dem iPhone führt durch:
   - **Zertifikat installieren**: *Profil laden* > *Erlauben*, dann
     *Einstellungen* > *Profil geladen* > *Installieren*. Danach der eine
     Schritt, den iOS für jedes selbst installierte Stammzertifikat
     verlangt: *Einstellungen* > *Allgemein* > *Info* >
     *Zertifikatsvertrauenseinstellungen* > „BlueFerry Shortcuts CA (…)“
     einschalten. Die Seite merkt selbst, wenn das Vertrauen aktiv ist (✅).
   - **Kurzbefehl hinzufügen**: *Kurzbefehl „BlueFerry“ hinzufügen* öffnet
     den iCloud-Link; Kurzbefehle fragt nach Adresse und Token, die Seite hat
     für beides einen großen *Kopieren*-Knopf. Beim ersten Ausführen fragt
     iOS nach dem Zugriff aufs **lokale Netzwerk**: *Erlauben*.
   - **Jetzt testen**: Der PC zeigt „iPhone verbunden ✅“.
   - Optional: Automationen für den Akkustand beim Ein- und Ausstecken des
     Ladegeräts (iOS lässt Automationen nicht importieren; die Seite
     erklärt die paar Schritte).
4. Die Karte zeigt den Zustand: *iPhone noch nicht eingerichtet*,
   *Zertifikat fehlt vermutlich auf dem iPhone* oder *iPhone zuletzt
   verbunden vor 5 Min.*

`https://<PC>:47801/` ohne Einrichtungslink zeigt nur einen Hinweis auf
„iPhone einrichten“; das Token erscheint nur nach einem gültigen Einmal-Link.

### Der Kurzbefehl „BlueFerry“

Ein einziger Kurzbefehl für alles: Menü (*Zwischenablage → PC*, *PC →
Zwischenablage*, *Link → PC*, *Akku → PC*), Share-Sheet und die Eingaben
`battery`, `battery-charging`, `battery-unplugged` für Automationen. Weil
unsignierte `.shortcut`-Dateien seit iOS 15 nicht importierbar sind, wird er
als **iCloud-Link mit Import-Fragen** (Adresse, Token) geteilt; der Link
gehört in die Einstellung **Shortcut link** (`shortcut_url`).

### Unverschlüsselt im Heimnetz

Wer das Zertifikat nicht will, kann **Allow unencrypted in the home
network (HTTP)** (`allow_http`, Erweitert, **standardmäßig aus**)
einschalten. Dann kann jeder im selben WLAN mitlesen, was die Kurzbefehle
senden. Regeln:

- Eigener HTTP-Listener auf `http_port` (47800), nur für private und
  Link-Local-Adressen; das Token bleibt Pflicht.
- **PC-Zwischenablage lesen ist über HTTP immer gesperrt** (403).
- **Pro Netz**: Beim Einschalten wird das NetworkManager-Profil mit der
  Standardroute freigegeben (per UUID, nicht SSID: ein „Zuhause“ im Café
  ist ein anderes Profil). In jedem anderen Netz schließt der Listener
  sofort, die Karte zeigt *Unverschlüsselt pausiert – fremdes Netz* mit
  **Dieses Netz freigeben**.
- **Offene WLANs** (kein Passwort, WEP, OWE) nie, auch nicht freigegeben.
  **Ohne NetworkManager** nicht verfügbar.
- Freigegebene Netze: Einstellung *Approved networks* (Namen löschen zum
  Entfernen) oder `blueferry-shortcuts networks [list|allow-current|remove NAME]`.

Ist HTTP im freigegebenen Netz aktiv, zeigt der QR-Code die HTTP-Adresse,
Safari öffnet die Seite ohne Warnung und der Zertifikatsschritt ist
*optional, empfohlen*.

### Für Fortgeschrittene: manuell einrichten

Du brauchst **URL** (z. B. `https://192.168.1.20:47801`), **Token** und
**Fingerprint**: in BlueFerry auf der Telefonkarte bei „Kurzbefehle-Brücke“
> „Einrichtungsdaten anzeigen“ („Aufdecken“ zeigt das Token), oder
`blueferry-shortcuts show`.

#### Schritt 0: Zertifikat vertrauen (einmalig)

1. Auf dem iPhone in **Safari** `https://<PC-Adresse>:47801/ca.crt` öffnen.
   Safari warnt, die Verbindung sei nicht privat (erwartet, das iPhone kennt
   die CA noch nicht): *Details einblenden* > *diese Website besuchen* >
   *Website besuchen*.
2. Den Download des Konfigurationsprofils *Erlauben*.
3. **Einstellungen** > *Profil geladen* (oder *Allgemein* > *VPN und
   Geräteverwaltung*) > „BlueFerry Shortcuts CA (…)“ > *Installieren*. Unter
   *Mehr Details* muss der **SHA-256**-Fingerabdruck des Zertifikats dem in
   BlueFerry angezeigten Fingerprint entsprechen.
4. **Einstellungen** > *Allgemein* > *Info* > *Zertifikatsvertrauenseinstellungen*:
   „BlueFerry Shortcuts CA (…)“ voll vertrauen.

Ohne Schritt 4 scheitert jeder Kurzbefehl mit einem SSL-Fehler.

#### Die Anfrage-Aktion

Alle drei Kurzbefehle nutzen **Inhalte von URL abrufen**. Mit dem Pfeil
(*Mehr anzeigen*) erscheinen die Optionen:

| Feld | Wert |
| --- | --- |
| URL | `https://<PC-Adresse>:47801/<Endpunkt>` |
| Methode | `POST` (bzw. `GET` bei „Von PC“) |
| Header | Schlüssel `Authorization`, Wert `Bearer <Token>` (ein Leerzeichen nach `Bearer`) |
| Hauptteil der Anfrage | `JSON`, Felder wie unten |

Die Beschriftungen können je nach iOS-Version leicht abweichen.

#### Kurzbefehl 1: „An PC: Zwischenablage“

1. Neuer Kurzbefehl, Name **An PC: Zwischenablage**.
2. Aktion **Zwischenablage abrufen**.
3. Aktion **Inhalte von URL abrufen**: URL `https://<PC>:47801/clipboard`,
   Methode `POST`, Header wie oben, Hauptteil `JSON` mit einem Feld:
   Schlüssel `text`, Typ **Text**, Wert: die Variable **Zwischenablage**.
4. Optional: Aktion **Mitteilung anzeigen** „Gesendet“.

Bilder (mit `accept_images` an): als Hauptteil **Datei** mit dem Bild aus der
Zwischenablage statt JSON. Das Plugin nimmt PNG, JPEG, GIF und WebP; HEIC-Fotos
vorher mit **Bild konvertieren** (JPEG) umwandeln.

Links: eine Variante mit URL `…/link` und JSON-Feld `url` (Typ Text) schickt
einen Link; in den Kurzbefehl-Details *Im Share-Sheet anzeigen* einschalten
und *Kurzbefehleingabe* als Wert nehmen, dann geht die aktuelle Safari-Seite
per Teilen-Menü an den PC.

#### Kurzbefehl 2: „Von PC: Zwischenablage“

Braucht `allow_clipboard_read` an.

1. Neuer Kurzbefehl **Von PC: Zwischenablage**.
2. Aktion **Inhalte von URL abrufen**: URL `https://<PC>:47801/clipboard`,
   Methode `GET`, Header `Authorization` = `Bearer <Token>`, kein Hauptteil.
3. Aktion **In Zwischenablage kopieren** mit *Inhalte von URL*.

#### Kurzbefehl 3: „An PC: Akku“

1. Neuer Kurzbefehl **An PC: Akku**.
2. Aktion **Batteriestatus abrufen** (Suche: „Batterie“).
3. Aktion **Inhalte von URL abrufen**: URL `https://<PC>:47801/battery`,
   Methode `POST`, Header wie oben, Hauptteil `JSON` mit
   - Schlüssel `level`, Typ **Zahl**, Wert *Batteriestatus*
   - Schlüssel `charging`, Typ **Boolesch**: siehe Automationen.

`charging` ist optional: fehlt es, behält der PC den letzten bekannten Stand.

Automationen (Tab *Automation* > *Neue Automation*, *Sofort ausführen* wählen):

- **Ladegerät** > *Ist verbunden*: die Aktionen oben mit `charging` = **Wahr**.
- **Ladegerät** > *Ist getrennt*: dasselbe mit `charging` = **Falsch**.
- Halbstündlich: iOS kennt keinen Intervall-Auslöser. Lege
  **Tageszeit**-Automationen für die gewünschten Zeiten an (z. B. 08:00,
  08:30, …), die **An PC: Akku** ohne das Feld `charging` ausführen; auf
  neueren iOS-Versionen lässt es sich stattdessen mit der Aktion **Wird
  geladen** füllen. Eine **Batteriestand**-Automation (*Fällt unter* 50 % /
  20 %) ist die sparsamere Alternative.

## Testing with curl

```sh
curl --cacert ~/.config/blueferry/plugins/io.weirdware.blueferry.shortcuts/ca.pem \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"level": 87, "charging": true}' https://192.168.1.20:47801/battery
```

Errors are JSON `{"error": "…"}` with the HTTP status: 401 token, 403 feature
off, 411 missing `Content-Length`, 413 too large, 415 type not accepted,
429 rate limit, 503 clipboard not reachable.

## Develop

```sh
python3 -m venv --system-site-packages .venv   # dbus-python, PyGObject from the system
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check . && .venv/bin/python -m pytest -q
```

`blueferry-plugin-api` comes from the `plugin-api` directory of the
BlueFerry repository. The clipboard helper, the listen-address choice, the
owner-only files, the certificates and the hardened HTTPS server come from
the shared [blueferry-plugin-kit](https://github.com/joshii-h/blueferry-plugin-kit)
(tag `kit-v0.3.0`, extra `lanserver`); the routes stay in this plugin.
The QR code comes from [segno](https://pypi.org/project/segno/).
Tests run the real HTTPS server on localhost with the plugin's CA, and the
kit's fake clipboard and fake host, which checks every card reply against
the 1.2 limits. The
Shortcuts steps above have not been verified on an iPhone yet; the
NetworkManager rules are tested against a fake NetworkManager.

## License

GPL-2.0-or-later, like BlueFerry. See `LICENSE`.
