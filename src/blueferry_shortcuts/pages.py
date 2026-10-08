"""HTML pages: the iPhone setup page, the PC page with the QR code, and
the plain answer for ``GET /``.

Self-contained on purpose: no external resources, the one style block and
the one script are allowed by their SHA-256 in a strict
Content-Security-Policy (``default-src 'none'``). Dynamic values go into
the HTML escaped, and into the script only through ``data-`` attributes.
"""
from __future__ import annotations

import base64
import hashlib
import html
from dataclasses import dataclass

STYLE = """
:root{color-scheme:light dark;--fg:#1d1d1f;--bg:#f2f2f7;--card:#fff;--muted:#6e6e73;
--accent:#0a64d8;--button:#0a64d8;--on-accent:#fff;--ok:#1a7f37;--bad:#b42318;--line:#d8d8de;
--field:#f2f2f7;--note:#fff5e0;--note-line:#e8a317}
@media (prefers-color-scheme:dark){:root{--fg:#f5f5f7;--bg:#000;--card:#1c1c1e;
--muted:#a1a1a6;--accent:#4c9bff;--button:#1662d0;--ok:#3fb950;--bad:#ff6b5e;--line:#38383a;
--field:#2c2c2e;--note:#3a2d10;--note-line:#e8a317}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;font:17px/1.47 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;
color:var(--fg);background:var(--bg);overflow-wrap:break-word;
padding:16px max(16px,env(safe-area-inset-right)) 40px max(16px,env(safe-area-inset-left))}
main{max-width:560px;margin:0 auto}
h1{font-size:28px;line-height:1.2;margin:12px 0 8px;font-weight:700}
h2{font-size:20px;line-height:1.3;margin:0 0 10px;font-weight:700;display:flex;
align-items:center;flex-wrap:wrap;gap:6px 10px}
.num{flex:none;display:inline-flex;align-items:center;justify-content:center;width:28px;
height:28px;border-radius:50%;background:var(--button);color:var(--on-accent);
font-size:15px;font-weight:700}
.done .num{background:var(--ok);font-size:0}
.done .num::after{content:"\\2713";font-size:16px}
.tag{font-size:13px;font-weight:600;color:var(--muted);border:1px solid var(--line);
border-radius:999px;padding:1px 9px}
section,main>details{background:var(--card);border:1px solid var(--line);
border-radius:16px;padding:18px 16px;margin:16px 0}
p{margin:8px 0}
ol,ul{margin:12px 0;padding-left:24px}
li{margin:8px 0;padding-left:2px}
.muted{color:var(--muted);font-size:15px}
.button{display:flex;align-items:center;justify-content:center;width:100%;min-height:50px;
margin:14px 0;padding:12px 16px;border:0;border-radius:12px;background:var(--button);
color:var(--on-accent);font-family:inherit;font-size:17px;font-weight:600;line-height:1.25;
text-align:center;text-decoration:none;cursor:pointer;-webkit-appearance:none;
appearance:none;touch-action:manipulation}
.button:active,.copy button:active{opacity:.7}
.button.secondary{background:transparent;color:var(--accent);
box-shadow:inset 0 0 0 1.5px var(--accent)}
.copy{margin:14px 0}
.label{display:block;font-size:15px;font-weight:600;margin:0 0 6px}
.row{display:flex;gap:8px;align-items:stretch}
.value{flex:1;min-width:0;margin:0;padding:11px 12px;border:1px solid var(--line);
border-radius:10px;background:var(--field);
font:15px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;
-webkit-user-select:all;user-select:all}
.copy button{flex:none;min-width:96px;min-height:46px;padding:0 14px;border:0;
border-radius:10px;background:var(--button);color:var(--on-accent);font-family:inherit;
font-size:16px;font-weight:600;cursor:pointer;-webkit-appearance:none;appearance:none;
touch-action:manipulation}
.state{font-weight:600;font-size:15px;margin:12px 0;padding:10px 12px;border-radius:10px;
background:var(--field)}
.state:empty{display:none}
.ok{color:var(--ok)}.bad{color:var(--bad)}
.note{background:var(--note);border-left:4px solid var(--note-line);border-radius:10px;
padding:10px 12px;margin:12px 0;font-size:15px}
.note p{margin:6px 0}
section details{margin:10px 0}
summary{font-weight:600;cursor:pointer;padding:4px 0}
section summary{font-size:15px;font-weight:500;color:var(--accent)}
.qr{background:#fff;display:inline-block;padding:8px;border-radius:8px}
.qr svg{display:block;width:260px;height:260px;max-width:100%}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14px;
word-break:break-all}
"""

SCRIPT = """
(function(){
var d=document.body.dataset;
function done(b){var t=b.textContent;b.textContent=d.copied;
setTimeout(function(){b.textContent=t;},1500);}
function select(v){var r=document.createRange(),s=window.getSelection();
r.selectNodeContents(v);s.removeAllRanges();s.addRange(r);}
function fallback(b,v){select(v);try{if(document.execCommand('copy')){done(b);}}catch(e){}}
Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'),function(b){
b.addEventListener('click',function(){var v=document.getElementById(b.dataset.copy);
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(v.textContent)
.then(function(){done(b);},function(){fallback(b,v);});}else{fallback(b,v);}});});
var trusted=false,busy=false,state=document.getElementById('trust-state');
function probe(){if(trusted||busy||!d.probe)return;busy=true;
fetch(d.probe,{mode:'no-cors',cache:'no-store'}).then(function(){trusted=true;
state.textContent=d.trusted;state.className='state ok';
document.getElementById('step-cert').classList.add('done');
var a=document.getElementById('address');if(a&&d.secureAddress){a.textContent=d.secureAddress;}
},function(){}).then(function(){busy=false;if(!trusted){setTimeout(probe,3000);}});}
probe();document.addEventListener('visibilitychange',function(){if(!document.hidden)probe();});
var test=document.getElementById('test'),out=document.getElementById('test-state');
if(test){test.addEventListener('click',function(){out.textContent=d.testing;out.className='state';
fetch(d.testUrl,{method:'POST',headers:{'X-BlueFerry-Setup':'1'},credentials:'same-origin',
cache:'no-store'}).then(function(r){out.textContent=r.ok?d.testOk:d.testFail;
out.className='state '+(r.ok?'ok':'bad');},function(){out.textContent=d.testFail;
out.className='state bad';});});}
})();
"""


def _sha(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def csp(*, script: bool, connect: tuple[str, ...] = ()) -> str:
    parts = [
        "default-src 'none'", f"style-src {_sha(STYLE)}", "img-src data:",
        "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
    ]
    if script:
        parts.append(f"script-src {_sha(SCRIPT)}")
        parts.append("connect-src " + " ".join(("'self'", *connect)))
    return "; ".join(parts)


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


def language(accept_language: str) -> str:
    """``de`` when German comes before English in ``Accept-Language``."""
    best, best_q = "en", -1.0
    for index, part in enumerate(accept_language.split(",")[:20]):
        tag, _, params = part.strip().partition(";")
        q = 1.0
        if params.strip().startswith("q="):
            try:
                q = float(params.strip()[2:])
            except ValueError:
                q = 0.0
        primary = tag.strip().lower().split("-", 1)[0]
        if primary in ("de", "en") and q - index * 1e-6 > best_q:
            best, best_q = primary, q - index * 1e-6
    return best


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _document(lang: str, title: str, body: str, data: dict[str, str] | None = None,
              *, script: bool = False, refresh: int = 0) -> bytes:
    attributes = "".join(
        f' data-{key}="{_e(value)}"' for key, value in (data or {}).items()
    )
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    scripts = f"<script>{SCRIPT}</script>" if script else ""
    return (
        f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta name="referrer" content="no-referrer">{meta}'
        f"<title>{_e(title)}</title><style>{STYLE}</style></head>"
        f"<body{attributes}><main>{body}</main>{scripts}</body></html>"
    ).encode()


# ---- the plain pages ------------------------------------------------------------

_SIMPLE = {
    "en": {
        "home_title": "BlueFerry",
        "home": "<h1>BlueFerry on your PC</h1><section><p>This is the iOS Shortcuts bridge "
                "of BlueFerry.</p><p>To set up your iPhone, open BlueFerry on your PC, go to "
                "the phone card, <b>Shortcuts bridge</b>, and choose <b>Set up iPhone</b>. "
                "Then scan the QR code with the iPhone's camera.</p></section>",
        "expired_title": "Setup link expired",
        "expired": "<h1>This setup link is no longer valid</h1><section><p>Setup links "
                   "work once and for ten minutes. On your PC, choose <b>Set up iPhone</b> in "
                   "BlueFerry again and scan the new QR code.</p></section>",
    },
    "de": {
        "home_title": "BlueFerry",
        "home": "<h1>BlueFerry auf deinem PC</h1><section><p>Hier läuft die "
                "Kurzbefehle-Brücke von BlueFerry.</p><p>Zum Einrichten deines iPhones "
                "öffne BlueFerry auf deinem PC, dort auf der Telefonkarte bei "
                "<b>Kurzbefehle-Brücke</b> auf <b>iPhone einrichten</b> tippen. Dann den "
                "QR-Code mit der Kamera des iPhones scannen.</p></section>",
        "expired_title": "Einrichtungslink abgelaufen",
        "expired": "<h1>Dieser Einrichtungslink gilt nicht mehr</h1><section><p>Ein "
                   "Einrichtungslink funktioniert einmal und zehn Minuten lang. Wähle auf "
                   "deinem PC in BlueFerry noch einmal <b>iPhone einrichten</b> und scanne "
                   "den neuen QR-Code.</p></section>",
    },
}


def home_page(lang: str) -> bytes:
    t = _SIMPLE[lang]
    return _document(lang, t["home_title"], t["home"])


def expired_page(lang: str) -> bytes:
    t = _SIMPLE[lang]
    return _document(lang, t["expired_title"], t["expired"])


# ---- the iPhone setup page --------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SetupView:
    address: str            # what the shortcut should use now
    secure_address: str     # the https address (shown once the CA is trusted)
    token: str
    ca_name: str
    fingerprint: str
    probe_url: str          # "" when the trust check is not available
    shortcut_url: str       # "" when no iCloud link is configured
    plain_http: bool        # plain HTTP is active (certificate optional)
    clipboard_read: bool


_SETUP = {
    "en": {
        "title": "Set up BlueFerry",
        "h1": "Set up BlueFerry on this iPhone",
        "intro": "Three steps, about three minutes. Keep this page open; it checks your "
                 "progress itself.",
        "cert_h": "Install the certificate",
        "cert_optional": "optional, recommended",
        "cert_why": "So that iPhone and PC talk encrypted, the iPhone needs your PC's "
                    "certificate. Your PC created it itself, not a company, which is why iOS "
                    "calls the profile <i>Not Verified</i>. That is expected here.",
        "cert_button": "Download profile",
        "cert_steps": [
            "Tap <b>Allow</b>, then <b>Close</b>.",
            "Open <b>Settings</b>. At the top: <b>Profile Downloaded</b> &gt; "
            "<b>Install</b> (enter your passcode) &gt; <b>Install</b>.",
            "<b>Settings</b> &gt; <b>General</b> &gt; <b>About</b> &gt; at the very bottom "
            "<b>Certificate Trust Settings</b> &gt; switch on <b>{ca}</b> &gt; "
            "<b>Continue</b>.",
            "Come back to this page.",
        ],
        "cert_switch": "Why this extra switch? iOS asks for a second, deliberate "
                       "confirmation for every root certificate you install yourself, so "
                       "nobody can slip one in unnoticed. No app can skip it, and it is "
                       "needed only once.",
        "fingerprint_h": "Compare the fingerprint",
        "fingerprint": "In the profile: <b>More Details</b> &gt; <b>SHA-256</b>. It must "
                       "match:",
        "trust_wait": "Not trusted yet. This page checks automatically.",
        "trust_none": "Cannot check automatically here; the test in step 3 will show it.",
        "trusted": "Certificate trusted",
        "plain_note": "Unencrypted in the home network is on, so you may skip this step. "
                      "Then anyone in this Wi-Fi could read what you send (not the PC "
                      "clipboard: reading it always needs the certificate). With the "
                      "certificate it stays private.",
        "skip": "Skip for now",
        "short_h": "Add the shortcut",
        "short_button": "Add the “BlueFerry” shortcut",
        "short_intro": "While adding it, the Shortcuts app asks two questions. Copy the "
                       "answers here:",
        "short_missing": "The share link of the shortcut is not set up on the PC yet "
                         "(setting “Shortcut link”). Build it by the guide in the README; you "
                         "need these two values there too:",
        "address": "Address",
        "token": "Token",
        "copy": "Copy",
        "copied": "Copied ✓",
        "local_net": "The first time the shortcut runs, iOS asks whether Shortcuts may "
                     "find devices on your local network: tap <b>Allow</b>.",
        "read_off": "“PC → Clipboard” works once you allow reading the PC clipboard in "
                    "BlueFerry's plugin settings, and only over the encrypted connection.",
        "test_h": "Test",
        "test_button": "Test now",
        "test_hint": "Your PC shows “iPhone connected ✅”. Then try the shortcut "
                     "“BlueFerry” &gt; “Clipboard → PC”.",
        "testing": "Testing …",
        "test_ok": "Done: your PC got the test.",
        "test_fail": "That did not work. Is the PC on and in the same network?",
        "auto_h": "Optional: send the battery level automatically",
        "auto": "iOS cannot import automations, so set them up once by hand: "
                "<b>Shortcuts</b> &gt; <b>Automation</b> &gt; <b>+</b> &gt; <b>Charger</b> "
                "&gt; <b>Is Connected</b> &gt; <b>Run Immediately</b> &gt; "
                "<b>New Blank Automation</b>. Add <b>Text</b> with "
                "<code>battery-charging</code>, then <b>Run Shortcut</b> "
                "“BlueFerry” with the text as input. Repeat with <b>Is Disconnected</b> "
                "and <code>battery-unplugged</code>. A <b>Battery Level</b> automation (e.g. "
                "falls below 20&nbsp;%) works the same way with <code>battery</code>.",
    },
    "de": {
        "title": "BlueFerry einrichten",
        "h1": "BlueFerry auf diesem iPhone einrichten",
        "intro": "Drei Schritte, etwa drei Minuten. Lass diese Seite offen; sie prüft "
                 "selbst, wie weit du bist.",
        "cert_h": "Zertifikat installieren",
        "cert_optional": "optional, empfohlen",
        "cert_why": "Damit iPhone und PC verschlüsselt sprechen, braucht das iPhone das "
                    "Zertifikat deines PCs. Dein PC hat es selbst erzeugt, keine Firma, "
                    "deshalb nennt iOS das Profil <i>Nicht überprüft</i>. Das ist hier "
                    "normal.",
        "cert_button": "Profil laden",
        "cert_steps": [
            "Auf <b>Erlauben</b> tippen, dann <b>Schließen</b>.",
            "<b>Einstellungen</b> öffnen. Ganz oben: <b>Profil geladen</b> &gt; "
            "<b>Installieren</b> (Code eingeben) &gt; <b>Installieren</b>.",
            "<b>Einstellungen</b> &gt; <b>Allgemein</b> &gt; <b>Info</b> &gt; ganz unten "
            "<b>Zertifikatsvertrauenseinstellungen</b> &gt; Schalter bei <b>{ca}</b> "
            "einschalten &gt; <b>Fortfahren</b>.",
            "Zurück zu dieser Seite.",
        ],
        "cert_switch": "Warum dieser zusätzliche Schalter? iOS verlangt für jedes selbst "
                       "installierte Stammzertifikat eine zweite, bewusste Bestätigung, damit "
                       "dir niemand unbemerkt eines unterschiebt. Keine App kann das "
                       "überspringen, und es ist nur einmal nötig.",
        "fingerprint_h": "Fingerabdruck vergleichen",
        "fingerprint": "Im Profil: <b>Mehr Details</b> &gt; <b>SHA-256</b>. Er muss so "
                       "lauten:",
        "trust_wait": "Noch nicht vertraut. Die Seite prüft automatisch.",
        "trust_none": "Hier nicht automatisch prüfbar; der Test in Schritt 3 zeigt es.",
        "trusted": "Zertifikat vertraut",
        "plain_note": "Unverschlüsselt im Heimnetz ist eingeschaltet, du kannst diesen "
                      "Schritt also überspringen. Dann kann aber jeder in diesem WLAN "
                      "mitlesen, was du sendest (nicht die PC-Zwischenablage: lesen geht "
                      "immer nur mit Zertifikat). Mit Zertifikat bleibt es privat.",
        "skip": "Vorerst überspringen",
        "short_h": "Kurzbefehl hinzufügen",
        "short_button": "Kurzbefehl „BlueFerry“ hinzufügen",
        "short_intro": "Beim Hinzufügen stellt die Kurzbefehle-App zwei Fragen. Kopiere "
                       "die Antworten hier:",
        "short_missing": "Der Freigabe-Link des Kurzbefehls ist auf dem PC noch nicht "
                         "hinterlegt (Einstellung „Kurzbefehl-Link“). Baue ihn nach der "
                         "Anleitung im README; dort brauchst du diese beiden Angaben auch:",
        "address": "Adresse",
        "token": "Token",
        "copy": "Kopieren",
        "copied": "Kopiert ✓",
        "local_net": "Beim ersten Ausführen fragt iOS, ob Kurzbefehle Geräte im lokalen "
                     "Netzwerk finden darf: <b>Erlauben</b> tippen.",
        "read_off": "„PC → Zwischenablage“ geht, sobald du in BlueFerry in den "
                    "Plugin-Einstellungen das Lesen der PC-Zwischenablage erlaubst, und "
                    "nur über die verschlüsselte Verbindung.",
        "test_h": "Testen",
        "test_button": "Jetzt testen",
        "test_hint": "Dein PC zeigt „iPhone verbunden ✅“. Danach im Kurzbefehl "
                     "„BlueFerry“ &gt; „Zwischenablage → PC“ ausprobieren.",
        "testing": "Teste …",
        "test_ok": "Geklappt: dein PC hat den Test erhalten.",
        "test_fail": "Das hat nicht geklappt. Ist der PC an und im selben Netz?",
        "auto_h": "Optional: Akkustand automatisch senden",
        "auto": "Automationen lassen sich in iOS nicht importieren, darum einmal von Hand: "
                "<b>Kurzbefehle</b> &gt; <b>Automation</b> &gt; <b>+</b> &gt; "
                "<b>Ladegerät</b> &gt; <b>Ist verbunden</b> &gt; <b>Sofort ausführen</b> "
                "&gt; <b>Neue leere Automation</b>. Aktion <b>Text</b> mit "
                "<code>battery-charging</code>, dann <b>Kurzbefehl ausführen</b> „BlueFerry“ "
                "mit dem Text als Eingabe. Dasselbe mit <b>Ist getrennt</b> und "
                "<code>battery-unplugged</code>. Eine <b>Batteriestand</b>-Automation (z. B. fällt "
                "unter 20&nbsp;%) geht genauso mit <code>battery</code>.",
    },
}


def _copy_field(key: str, label: str, value: str, copy: str) -> str:
    return (
        f'<div class="copy"><span class="label" id="{key}-label">{label}</span>'
        f'<div class="row"><p class="value" id="{key}" aria-labelledby="{key}-label">'
        f"{_e(value)}</p>"
        f'<button type="button" data-copy="{key}">{copy}</button></div></div>'
    )


def setup_page(lang: str, view: SetupView) -> tuple[bytes, str]:
    """The page and its Content-Security-Policy."""
    t = _SETUP[lang]
    steps = "".join(f"<li>{step.format(ca=_e(view.ca_name))}</li>" for step in t["cert_steps"])
    plain = (
        f'<div class="note"><p>{t["plain_note"]}</p></div>'
        f'<a class="button secondary" href="#step-shortcut">{t["skip"]}</a>'
        if view.plain_http else ""
    )
    trust_text = t["trust_wait"] if view.probe_url else t["trust_none"]
    optional = f' <span class="tag">{t["cert_optional"]}</span>' if view.plain_http else ""
    download = f'<a class="button" href="/ca.mobileconfig">{t["cert_button"]}</a>'
    cert = (
        f'<section id="step-cert"><h2><span class="num">1</span>{t["cert_h"]}{optional}</h2>'
        f'<p>{t["cert_why"]}</p>{download}'
        f"<ol>{steps}</ol>"
        f'<p class="muted">{t["cert_switch"]}</p>'
        f'<p id="trust-state" class="state" aria-live="polite">{trust_text}</p>'
        f'<details><summary>{t["fingerprint_h"]}</summary>'
        f'<p class="muted">{t["fingerprint"]}</p>'
        f'<p><code>{_e(view.fingerprint)}</code></p></details>'
        f"{plain}</section>"
    )
    if view.shortcut_url:
        add = (f'<a class="button" href="{_e(view.shortcut_url)}">{t["short_button"]}</a>'
               f'<p>{t["short_intro"]}</p>')
    else:
        add = f'<p>{t["short_missing"]}</p>'
    fields = "".join(
        _copy_field(key, t[key], value, t["copy"])
        for key, value in (("address", view.address), ("token", view.token))
    )
    read_note = "" if view.clipboard_read else f'<p class="muted">{t["read_off"]}</p>'
    shortcut = (
        f'<section id="step-shortcut"><h2><span class="num">2</span>{t["short_h"]}</h2>'
        f'{add}{fields}<p class="muted">{t["local_net"]}</p>{read_note}</section>'
    )
    test = (
        f'<section id="step-test"><h2><span class="num">3</span>{t["test_h"]}</h2>'
        f'<button type="button" class="button" id="test">{t["test_button"]}</button>'
        f'<p id="test-state" class="state" aria-live="polite"></p>'
        f'<p class="muted">{t["test_hint"]}</p></section>'
    )
    automation = f'<details><summary>{t["auto_h"]}</summary><p>{t["auto"]}</p></details>'
    body = (f'<h1>{t["h1"]}</h1><p class="muted">{t["intro"]}</p>'
            f"{cert}{shortcut}{test}{automation}")
    secure = view.secure_address if view.secure_address != view.address else ""
    data = {
        "probe": view.probe_url, "trusted": t["trusted"], "copied": t["copied"],
        "testing": t["testing"], "test-ok": t["test_ok"], "test-fail": t["test_fail"],
        "test-url": "/setup/test", "secure-address": secure,
    }
    connect = (view.probe_url,) if view.probe_url else ()
    return (_document(lang, t["title"], body, data, script=True),
            csp(script=True, connect=connect))


# ---- the PC page with the QR code ----------------------------------------------------

@dataclass(frozen=True, slots=True)
class PcView:
    link: str               # the one-time link ("" when none can be offered)
    qr: str                 # inline SVG
    valid_until: str        # "14:32"
    error: str              # why there is no link
    plain_network: str      # approved network name when the link is plain HTTP
    opened: bool
    trusted: bool
    tested: bool


_PC = {
    "en": {
        "title": "Set up iPhone",
        "h1": "Set up your iPhone",
        "scan": "Scan this code with the iPhone's <b>Camera</b> app and tap the link. "
                "iPhone and PC must be in the same network.",
        "valid": "Valid until {time}, works once. This page renews itself.",
        "warning": "Safari warns once that the connection is not private, because the "
                   "iPhone does not know your PC's certificate yet: tap <b>Show Details</b> "
                   "&gt; <b>visit this website</b> &gt; <b>Visit Website</b>. The setup "
                   "page then installs the certificate.",
        "plain": "Unencrypted in the home network is active in “{name}”, so Safari opens "
                 "the page without a warning.",
        "used": "The code was used. To set up another iPhone:",
        "renew": "New code",
        "progress": "Progress",
        "opened": "Opened on the iPhone",
        "trusted": "Certificate trusted",
        "tested": "Test received",
        "error": "The iPhone cannot reach the PC right now: {error}",
        "secret": "Do not share a photo of this code: it gives access to the token.",
    },
    "de": {
        "title": "iPhone einrichten",
        "h1": "iPhone einrichten",
        "scan": "Scanne diesen Code mit der <b>Kamera</b>-App des iPhones und tippe auf "
                "den Link. iPhone und PC müssen im selben Netz sein.",
        "valid": "Gültig bis {time}, nur einmal verwendbar. Diese Seite erneuert sich selbst.",
        "warning": "Safari warnt einmal, die Verbindung sei nicht privat, weil das iPhone "
                   "das Zertifikat deines PCs noch nicht kennt: <b>Details einblenden</b> "
                   "&gt; <b>diese Website besuchen</b> &gt; <b>Website besuchen</b>. Die "
                   "Einrichtungsseite installiert dann das Zertifikat.",
        "plain": "Unverschlüsselt im Heimnetz ist in „{name}“ aktiv, darum öffnet Safari "
                 "die Seite ohne Warnung.",
        "used": "Der Code wurde verwendet. Für ein weiteres iPhone:",
        "renew": "Neuer Code",
        "progress": "Fortschritt",
        "opened": "Auf dem iPhone geöffnet",
        "trusted": "Zertifikat vertraut",
        "tested": "Test angekommen",
        "error": "Das iPhone erreicht den PC gerade nicht: {error}",
        "secret": "Kein Foto dieses Codes weitergeben: er gibt Zugang zum Token.",
    },
}


def pc_page(lang: str, view: PcView) -> tuple[bytes, str]:
    t = _PC[lang]
    if view.error:
        top = f'<section><p class="bad">{_e(t["error"].format(error=view.error))}</p></section>'
    elif view.link:
        hint = (t["plain"].format(name=_e(view.plain_network)) if view.plain_network
                else t["warning"])
        top = (
            f'<section><p>{t["scan"]}</p><div class="qr">{view.qr}</div>'
            f'<p class="muted">{t["valid"].format(time=_e(view.valid_until))}</p>'
            f'<p class="muted"><code>{_e(view.link)}</code></p>'
            f'<p>{hint}</p><p class="muted">{t["secret"]}</p></section>'
        )
    else:
        top = (f'<section><p>{t["used"]}</p>'
               f'<a class="button" href="?new=1">{t["renew"]}</a></section>')

    def mark(done: bool, key: str) -> str:
        return f'<li class="{"ok" if done else "muted"}">{"✅" if done else "○"} {t[key]}</li>'

    progress = (
        f'<section><h2>{t["progress"]}</h2><ul>'
        f'{mark(view.opened, "opened")}{mark(view.trusted, "trusted")}'
        f'{mark(view.tested, "tested")}</ul></section>'
    )
    body = f'<h1>{t["h1"]}</h1>{top}{progress}'
    return _document(lang, t["title"], body, refresh=5), csp(script=False)
