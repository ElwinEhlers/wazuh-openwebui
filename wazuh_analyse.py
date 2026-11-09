"""
title: Wazuh-Analyse
author: Elwin Ehlers
author_url: https://github.com/ElwinEhlers
credits: Entwickelt mit Claude (Anthropic)
description: Bewertet Wazuh-Schwachstellen-Einträge (wazuh-states-vulnerabilities) auf Debian/Ubuntu mit festen Regeln und wertet die Ausgaben der Prüfbefehle aus. Das Sprachmodell schreibt nur den Satz "Worum geht's" (optional).
version: 1.25
license: MIT
"""

# Einrichtung: Open WebUI -> Admin-Bereich -> Funktionen -> "+" -> diesen Code einfügen -> speichern -> aktivieren.
# Danach erscheint "Wazuh-Analyse" in der Modellauswahl. Einstellungen (Zahnrad bei der Funktion): LLM-Adresse usw.
#
# Ablauf im Chat:
#   1. Wazuh-JSON einfügen  -> Ampel, Begründung, Prüfbefehle
#   2. Ausgabe der Prüfbefehle einfügen -> Endergebnis (betroffen / angreifbar / was tun)

import asyncio
import copy
import html
import http.client
import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, wait
import urllib.error
import urllib.parse
import urllib.request

from pydantic import BaseModel, Field


# ---------------------------------------------------------------- Versionen

def bereinige_version(v):
    """'1:9.18.33-1~deb12u2' -> ('9.18.33', '-1~deb12u2')"""
    ohne_epoche = re.sub(r"^\d+:", "", v.strip())
    really = re.search(r"\+really([0-9][^-+~]*)", ohne_epoche)  # 2.12.7+dfsg+really2.9.14-2 -> 2.9.14
    if really:
        return really.group(1), ohne_epoche[really.end():]
    rein = re.match(r"[^-+~]*", ohne_epoche).group(0)
    return rein, ohne_epoche[len(rein):]


def vteile(v):
    return [int(t) if t.isdigit() else t for t in re.findall(r"\d+|[a-z]+", v.lower())]


def vergleiche(a, b):
    """-1, 0, 1 wie a <=> b"""
    x, y = vteile(a), vteile(b)
    for i in range(max(len(x), len(y))):
        p = x[i] if i < len(x) else 0
        q = y[i] if i < len(y) else 0
        if p == q:
            continue
        if type(p) is not type(q):  # Zahl gegen Buchstaben: Zahl gilt als größer
            return 1 if isinstance(p, int) else -1
        return -1 if p < q else 1
    return 0


VER = r"v?(\d+(?:\.\d+)+[a-z]?\d*)"
LISTE = r"((?:\s*,\s*(?:and\s+|or\s+)?|\s+(?:and|or)\s+)" + VER + r")*"


def bereiche_aus_beschreibung(text):
    """Liste von (untere, obere, art) mit art 'lt' (vor) oder 'le' (bis einschließlich)."""
    t = " " + text.lower() + " "
    bereiche = []

    def weg(m):
        return " " * (m.end() - m.start())

    # "3.0.0 to before 3.2.9"
    muster = (rf"{VER}\s*(?:(?:to|-|until|up to)\s*(?:before|prior to|but not including|excluding)|"
              rf"until|till|up until)\s*{VER}")
    for m in re.finditer(muster, t):
        bereiche.append((m.group(1), m.group(2), "lt"))
    t = re.sub(muster, weg, t)
    # "9.18.0 through 9.18.27" / "1.2 to 1.5"
    muster = rf"{VER}\s*(?:through|to|up to and including|up to|-)\s*{VER}"
    for m in re.finditer(muster, t):
        bereiche.append((m.group(1), m.group(2), "le"))
    t = re.sub(muster, weg, t)
    # "before 3.2.9, 3.3.11, and 3.4.11"
    for wort, art in ((r"(?:before|prior to|earlier than|older than|<)", "lt"),
                      (r"(?:through|up to and including|up to|<=)", "le")):
        muster = rf"{wort}\s*(?:versions?\s*)?{VER}{LISTE}"
        for m in re.finditer(muster, t):
            for v in re.findall(VER, m.group(0)):
                bereiche.append((None, v, art))
        t = re.sub(muster, weg, t)
    # nur wenn sonst nichts gefunden: "fixed in version 2.8.0" / "patched in 1.2.3"
    if not bereiche:
        for m in re.finditer(rf"(?:fixed|patched|resolved|addressed) in (?:versions?\s*)?{VER}", t):
            bereiche.append((None, m.group(1), "lt"))
    return bereiche


def text_bereich(u, o, art):
    if u:
        return f"ab {u}, vor {o}" if art == "lt" else f"{u} bis einschließlich {o}"
    return f"vor {o}" if art == "lt" else f"bis einschließlich {o}"


def pruefe_version(installiert, bereiche):
    """-> (ergebnis 'ja'|'nein'|'unklar'|'keine', passender Bereich oder None, Fix-Version oder None)"""
    if not bereiche:
        return "keine", None, None

    def drin(u, o, art):
        if u and vergleiche(installiert, u) < 0:
            return False
        c = vergleiche(installiert, o)
        return c < 0 if art == "lt" else c <= 0

    mit_unten = [b for b in bereiche if b[0]]
    nur_oben = [b for b in bereiche if not b[0]]
    for b in mit_unten:
        if drin(*b):
            return "ja", b, (b[1] if b[2] == "lt" else None)
    if nur_oben:
        zweig = vteile(installiert)[:2]
        gleich = [b for b in nur_oben if vteile(b[1])[:2] == zweig]
        kandidaten = gleich or nur_oben
        if len(kandidaten) == 1 or gleich:
            b = kandidaten[0]
            if drin(*b):
                return "ja", b, (b[1] if b[2] == "lt" else None)
            return "nein", b, None
        kleinste = min(kandidaten, key=lambda b: vteile(b[1]))
        groesste = max(kandidaten, key=lambda b: vteile(b[1]))
        if drin(*kleinste):
            return "ja", kleinste, (kleinste[1] if kleinste[2] == "lt" else None)
        if not drin(*groesste):
            return "nein", groesste, None
        return "unklar", None, None
    return "nein", mit_unten[0], None


# ---------------------------------------------------------------- Kernel

ARCHITEKTUREN = {
    "s390": "IBM-Großrechner (s390)", "arm": "ARM-Geräte (32 Bit)", "arm64": "ARM-Geräte (64 Bit)",
    "powerpc": "PowerPC-Rechner", "riscv": "RISC-V-Rechner", "mips": "MIPS-Geräte",
    "loongarch": "Loongson-Rechner", "sparc": "SPARC-Rechner", "parisc": "PA-RISC-Rechner",
    "m68k": "Motorola-68k-Rechner", "sh": "SuperH-Geräte", "alpha": "Alpha-Rechner",
    "xtensa": "Xtensa-Chips", "arc": "ARC-Chips", "csky": "C-SKY-Chips", "hexagon": "Hexagon-Chips",
    "microblaze": "MicroBlaze-Chips", "openrisc": "OpenRISC-Chips", "um": "User-Mode-Linux",
}
X86 = {"amd64", "i386", "x86_64"}


def kernel_teile(beschreibung):
    """'... resolved:  gpio: mxc: fix race' -> ['gpio', 'mxc'];  's390/pai: ...' -> ['s390', 'pai']"""
    m = re.search(r"resolved:\s*((?:[\w.,/-]+:\s+)+)", beschreibung)
    if not m:
        return []
    teile = []
    for stueck in re.findall(r"([\w.,/-]+):", m.group(1)):
        teile += [t for t in stueck.split("/") if t]
    return teile


def config_muster(treiber):
    return "_" + re.sub(r"[^A-Za-z0-9]", "_", treiber).upper() + "(_|=| )"


def modul_muster(treiber):
    t = re.sub(r"[^A-Za-z0-9]", "_", treiber).lower()
    return rf"^(\w+_)?{t}(_\w+)? "


def kernel_befehle(treiber):
    return (f"uname -r\ngrep -iE '{config_muster(treiber)}' /boot/config-$(uname -r)\n"
            f"lsmod | grep -iE '{modul_muster(treiber)}' || echo 'Modul nicht geladen'")


# ---------------------------------------------------------------- Pakete

DIENST_PORTS = {
    "rsync": [873], "apache2": [80, 443], "libapache2": [80, 443], "nginx": [80, 443],
    "openssh-server": [22], "openssh": [22], "bind9": [53], "named": [53], "postfix": [25],
    "exim4": [25], "samba": [139, 445], "cups": [631], "mariadb": [3306], "mysql": [3306],
    "postgresql": [5432], "dovecot": [110, 143, 993, 995], "vsftpd": [21], "proftpd": [21],
    "squid": [3128], "redis": [6379], "memcached": [11211], "openvpn": [1194], "xrdp": [3389],
    "freerdp": [3389], "gnome-remote-desktop": [3389], "lighttpd": [80, 443], "haproxy": [80, 443],
}


# Lücken, die laut Beschreibung nur einen bestimmten Netzdienst treffen, auch wenn das Paket eine Bibliothek ist
DIENST_AUS_TEXT = [
    (r"\brpc\b[^.]*\bservice|rpcsec_gss|rpcbind|sunrpc", [111, 2049], "RPC-Dienst (rpcbind, NFS)"),
]


def dienst_aus_text(beschreibung):
    for muster, ports, name in DIENST_AUS_TEXT:
        if re.search(muster, beschreibung.lower()):
            return ports, name
    return None, None


def namens_teile(name):
    teile = set()
    for t in re.split(r"[-_.+]", name.lower()):
        t = re.sub(r"\d+$", "", re.sub(r"^lib", "", t))
        if len(t) >= 3 and t not in {"dev", "bin", "common", "data", "utils", "tools", "doc"}:
            teile.add(t)
    return teile


def ports_fuer(name):
    n = name.lower()
    for k, v in DIENST_PORTS.items():
        if n == k or n.startswith(k + "-") or n.startswith(k):
            return v
    return None


def paket_befehle(name, cve):
    return (f"zcat /usr/share/doc/{name}/changelog.Debian.gz | grep -c {cve}\n"
            f"apt-cache rdepends --installed --no-breaks --no-conflicts --no-replaces --no-enhances --no-suggests {name}\n"
            "ss -ltn")


# ---------------------------------------------------------------- Bewertung des JSON

def lade_eintrag(text):
    t = text.strip()
    t = re.sub(r"^```\w*\s*|\s*```$", "", t)
    kandidaten = [t]
    if "{" in t and "}" in t:
        kandidaten.append(t[t.index("{"): t.rindex("}") + 1])
    for k in kandidaten:
        try:
            d = json.loads(k)
        except Exception:
            continue
        if isinstance(d, dict):
            d = d.get("_source", d)
            if isinstance(d, dict) and "vulnerability" in d and "package" in d:
                return d
    return None


def bewerte(e):
    pkg, vul = e.get("package", {}), e.get("vulnerability", {})
    name = pkg.get("name", "–")
    beschreibung = vul.get("description", "")
    r = {
        "cve": vul.get("id", "–"), "host": e.get("agent", {}).get("name", "–"), "paket": name,
        "version": pkg.get("version", "–"), "paket_text": pkg.get("description", "–"),
        "arch": pkg.get("architecture", ""), "schwere": vul.get("severity", "–"),
        "cvss": vul.get("score", {}).get("base", "–"), "bedingung": vul.get("scanner", {}).get("condition", "–"),
        "quelle": vul.get("reference", ""), "beschreibung": beschreibung, "gruende": [], "details": [],
    }
    os_ = e.get("host", {}).get("os", {})
    r["release"] = (DEBIAN_NAMEN.get(str(os_.get("version", "")).split(".")[0])
                    if str(os_.get("platform", "")).lower() == "debian" else None)
    m_cve = re.match(r"CVE-(\d{4})-", str(r["cve"]))
    m_jetzt = re.match(r"(\d{4})", str(vul.get("detected_at", "")))
    r["alt"] = bool(m_cve and m_jetzt and int(m_jetzt.group(1)) - int(m_cve.group(1)) >= 3)
    r["cve_jahr"] = m_cve.group(1) if m_cve else ""
    if r["cvss"] in (-1, "-1"):
        r["cvss"] = "–"
    if r["schwere"] in ("-", ""):
        r["schwere"] = "–"

    if name.startswith(("linux-image", "linux-headers")):
        r["typ"] = "kernel"
        teile = kernel_teile(beschreibung)
        r["bereich"] = "/".join(teile) or "–"
        r["treiber"] = teile[-1] if teile else None
        arch = teile[0] if teile else ""
        if arch in ARCHITEKTUREN and r["arch"] in X86:
            r["ampel"] = "gruen"
            r["gruende"].append(f"Die Lücke steckt im Kernel-Teil `{r['bereich']}`. Diesen Teil gibt es nur für "
                                f"{ARCHITEKTUREN[arch]}, dieser Rechner ist aber ein PC ({r['arch']}).")
        elif r["treiber"]:
            r["ampel"] = "gelb"
            r["gruende"].append(f"Die Lücke steckt im Kernel-Treiber `{r['treiber']}` (Bereich `{r['bereich']}`).")
            r["gruende"].append("Kernel-Meldungen nennen keine Versionen. Ob dieser Treiber in deinem Kernel "
                                "überhaupt eingebaut ist, zeigt erst der Prüfbefehl.")
            r["befehle"] = kernel_befehle(r["treiber"])
            r["lesen"] = (f"Steht beim zweiten Befehl keine Zeile oder nur „is not set“, ist `{r['treiber']}` "
                          "nicht eingebaut – dann kein Problem. `=m` heißt: als Modul vorhanden. Der dritte Befehl "
                          "zeigt, ob das Modul gerade geladen ist.")
        else:
            r["ampel"] = "gelb"
            r["gruende"].append("Aus der Beschreibung lässt sich kein Treibername ablesen. Hier hilft nur ein "
                                "Blick in den Debian-Tracker (Link unten).")
        r["details"] += [("Kernel-Bereich", r["bereich"]), ("Treiber", r.get("treiber") or "–")]
        return r

    r["typ"] = "paket"
    rein, zusatz = bereinige_version(r["version"])
    backport = "deb" in zusatz.lower()
    bereiche = bereiche_aus_beschreibung(beschreibung)
    ver, bereich, fix = pruefe_version(rein, bereiche)
    regel = ", ".join(text_bereich(*b) for b in bereiche) if bereiche else "keine Grenze genannt"
    teile = namens_teile(name)
    komponente = "ja" if any(t in beschreibung.lower() for t in teile) else "unklar"

    if ver == "nein":
        r["ampel"] = "gruen"
        r["gruende"].append(f"Betroffen sind Versionen {regel}. Installiert ist {rein} – das liegt außerhalb.")
    elif ver == "ja":
        r["gruende"].append(f"Betroffen sind Versionen {text_bereich(*bereich)}. Installiert ist {rein} – "
                            "das liegt im betroffenen Bereich.")
        if backport:
            r["ampel"] = "gelb"
            r["gruende"].append(f"Aber: Die Version trägt den Debian-Zusatz `{zusatz}`. Debian baut Sicherheits-Fixes "
                                "oft nachträglich ein, ohne die Versionsnummer zu ändern. Ob der Fix drin ist, "
                                "zeigt der erste Prüfbefehl.")
        elif komponente == "ja":
            r["ampel"] = "rot"
            r["gruende"].append(f"Die Beschreibung nennt dieses Paket ({name}) ausdrücklich, und es gibt keinen "
                                "Hinweis auf einen nachgerüsteten Fix.")
        else:
            r["ampel"] = "gelb"
            r["gruende"].append(f"Die Beschreibung nennt das Paket `{name}` nicht direkt. Ob genau dieses Paket den "
                                "betroffenen Teil enthält, ist unklar.")
    elif ver == "unklar":
        r["ampel"] = "gelb"
        r["gruende"].append(f"Betroffen sind Versionen {regel}. Installiert ist {rein} – das lässt sich keinem "
                            "Bereich eindeutig zuordnen.")
    else:
        r["ampel"] = "gelb"
        r["gruende"].append("Die Beschreibung nennt keine Versionsgrenze. Ob deine Version betroffen ist, "
                            "lässt sich nur über den Prüfbefehl klären.")
    if r["ampel"] != "gruen":
        r["befehle"] = paket_befehle(name, r["cve"])
        r["lesen"] = ("Zeigt der erste Befehl **0**, ist der Fix nicht eingebaut. Der zweite zeigt, welche "
                      "Programme das Paket nutzen, der dritte, welche Ports offen sind.")
        if "tiocsti" in r["beschreibung"].lower():  # entscheidet allein die Kernel-Sperre
            r["gruende"].append("Die Lücke braucht den Terminal-Trick **TIOCSTI** (Zeichen in ein fremdes Terminal "
                                "schieben) und ist nur lokal ausnutzbar. Neuere Kernel sperren den Trick – der Befehl "
                                "unten zeigt, ob das hier so ist.")
            r["befehle"] = "sysctl dev.tty.legacy_tiocsti"
            r["lesen"] = ("**= 0** heißt: Der Kernel sperrt TIOCSTI, die Lücke ist nicht ausnutzbar. **= 1** oder "
                          "„unknown key“ heißt: ausnutzbar für jemanden, der schon angemeldet ist.")
    r["details"] += [("Bereinigte Version", rein), ("Debian-Zusatz", zusatz or "–"),
                     ("Regel aus der Beschreibung", regel), ("Fix-Version", fix or "–"),
                     ("Paket im Text genannt", "ja" if komponente == "ja" else "nein")]
    return r


# ---------------------------------------------------------------- Auswertung der Befehlsausgaben

def werte_kernel_aus(r, text):
    if "CONFIG_" not in text and not re.search(r"\d+\.\d+\.\d+\S*-(amd64|686|arm64|cloud|rt)", text):
        return None
    zeilen = [z.strip() for z in text.splitlines() if "CONFIG_" in z]
    pm = re.compile(config_muster(r["treiber"] or "§"), re.I)
    treffer = [z for z in zeilen if pm.search(z)]
    t = re.escape(re.sub(r"[^A-Za-z0-9]", "_", r["treiber"] or "§").upper())
    haupt = [z for z in treffer if re.search(rf"_{t}(=| is not set)", z, re.I)]
    if haupt:  # z. B. CONFIG_DRM_XE=m statt Unteroptionen wie CONFIG_DRM_XE_DISPLAY=y
        treffer = haupt
    aktiv = [z for z in treffer if re.search(r"=(y|m)\b", z)]
    fest = [z for z in aktiv if z.endswith("=y")]
    mm = re.compile(modul_muster(r["treiber"] or "§") + r"*\d+\s+\d+", re.I)
    geladen = [z.split()[0] for z in text.splitlines() if mm.match(z.strip())]
    if aktiv and not fest and not geladen and "nicht geladen" in text:
        return {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein",
                "gruende": [f"Der Treiber `{r['treiber']}` ist nur als Modul vorhanden (`{aktiv[0]}`) und gerade "
                            "nicht geladen. Solange er nicht geladen wird, ist die Lücke nicht erreichbar.",
                            "Er würde nur auf passender Hardware bzw. in passender Umgebung automatisch geladen."],
                "tun": "Nichts sofort. Das nächste reguläre Kernel-Update schließt die Lücke ohnehin "
                       "(`sudo apt update && sudo apt full-upgrade`)."}
    if aktiv:
        wie = f"geladen (`{geladen[0]}`)" if geladen else ("fest eingebaut" if fest else "als Modul vorhanden")
        return {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Nein",
                "gruende": [f"Der Treiber `{r['treiber']}` ist in deinem Kernel {wie}: `{aktiv[0]}`.",
                            "Ausnutzen lässt sich so eine Kernel-Lücke meist nur von jemandem, der schon auf dem "
                            "Rechner ist oder passende Hardware anschließt."],
                "tun": "Kernel-Update einspielen, sobald Debian es liefert: `sudo apt update && sudo apt full-upgrade`, "
                       "danach neu starten."}
    grund = (f"Der Treiber `{r['treiber']}` ist in deinem Kernel nicht eingebaut "
             + (f"(`{treffer[0]}`)." if treffer else "(der Prüfbefehl fand keine Zeile)."))
    return {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein", "gruende": [grund],
            "tun": "Nichts. Die Meldung kann in Wazuh ignoriert werden."}


def werte_paket_aus(r, text):
    zahl = None
    for z in text.splitlines():
        if re.fullmatch(r"\s*\d+\s*", z):
            zahl = int(z)
            break
    if zahl is None:
        if "Reverse Depends:" not in text:
            return None
        programme = []
        for block in text.split("Reverse Depends:")[1:]:
            for z in block.splitlines()[1:]:
                z = z.strip().lstrip("|").strip()
                if not re.fullmatch(r"[a-z0-9][a-z0-9+.:-]+", z):
                    break
                n = z.split(":")[0]
                if n not in programme and not re.search(r"^lib|-libs?$|^zlib|lib\d", n):
                    programme.append(n)
        gruende = ["Die betroffene Bibliothek wird über andere Bibliotheken von diesen Programmen genutzt: "
                   + (", ".join(f"`{n}`" for n in programme[:10]) if programme else "keinen weiteren Programmen") + "."]
        gruende.append("Gefährlich wird die Lücke nur, wenn eines davon Daten aus nicht vertrauenswürdiger Quelle "
                       "verarbeitet (z. B. Dateien oder Antworten aus dem Internet).")
        return {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Unklar" if programme else "Nein",
                "gruende": gruende,
                "tun": f"Update einspielen, sobald Debian es liefert. Nachsehen mit `sudo apt update && apt list "
                       f"--upgradable 2>/dev/null | grep '^{r['paket']}/'`."}
    if zahl > 0:
        return {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein",
                "gruende": [f"Der Debian-Changelog von `{r['paket']}` erwähnt {r['cve']} ({zahl}×). Der Fix ist also "
                            "eingebaut, auch wenn die Versionsnummer älter aussieht."],
                "tun": "Nichts. Die Meldung kann in Wazuh ignoriert werden."}
    offen = []
    for z in text.splitlines():
        m = re.search(r"LISTEN\s+\d+\s+\d+\s+(\S+):(\d+)\s", z + " ")
        if m:
            adr, port = m.group(1), int(m.group(2))
            lokal = adr.startswith("127.") or adr in ("[::1]", "::1", "localhost")
            offen.append((adr, port, lokal))
    if r.get("alt"):
        erg = {"ampel": "gelb", "betroffen": "Unklar", "angreifbar": "Unklar",
                "gruende": [f"Der Debian-Changelog erwähnt {r['cve']} nicht. Das sagt bei einer so alten Lücke (von "
                            f"{r['cve_jahr']}) aber wenig: Der Changelog nennt nur Fixes, die Debian selbst nachgerüstet "
                            "hat. Ein Fix, der schon in einer neueren Upstream-Version steckt, taucht dort nicht auf.",
                            "Ob Debian die Lücke für deine Version als behoben, unwichtig oder offen führt, steht im "
                            f"Debian-Tracker: {r.get('quelle') or 'security-tracker.debian.org'}"],
                "tun": "Im Debian-Tracker bei deiner Debian-Version nachsehen. Steht dort „not-affected“, "
                       "„unimportant“ oder eine Version ≤ deiner installierten, kann die Meldung ignoriert werden."}
        if lokale_luecke(r.get("beschreibung", "")):
            erg["gruende"].append("Laut Beschreibung nur **lokal** ausnutzbar: Ein Angreifer müsste schon auf diesem "
                                  "Rechner angemeldet sein. Über das Netz ist die Lücke nicht erreichbar.")
            erg["angreifbar"] = "Nein"
        return erg
    gruende = [f"Der Debian-Changelog von `{r['paket']}` erwähnt {r['cve']} nicht. Der Fix ist also nicht eingebaut."]
    tun = (f"Update einspielen, sobald Debian es liefert. Nachsehen mit "
           f"`sudo apt update && apt list --upgradable 2>/dev/null | grep '^{r['paket']}/'`.")
    ports, dienst = ports_fuer(r["paket"]), None
    if not ports:
        ports, dienst = dienst_aus_text(r.get("beschreibung", ""))
    if ports:
        aussen = [o for o in offen if o[1] in ports and not o[2]]
        innen = [o for o in offen if o[1] in ports and o[2]]
        if aussen and not lokale_luecke(r.get("beschreibung", "")):
            gruende.append(f"Der {dienst or 'zugehörige Dienst'} lauscht von außen erreichbar auf Port {aussen[0][1]} "
                           f"(`{aussen[0][0]}`).")
            return {"ampel": "rot", "betroffen": "Ja", "angreifbar": "Ja", "gruende": gruende,
                    "tun": tun + " Bis dahin den Dienst nur aus dem eigenen Netz erreichbar machen "
                                 "(Firewall) oder abschalten, wenn er nicht gebraucht wird."}
        if innen:
            gruende.append(f"Der {dienst or 'zugehörige Dienst'} lauscht nur lokal (Port {innen[0][1]} auf `{innen[0][0]}`), "
                           "ist also von außen nicht erreichbar.")
        else:
            gruende.append(f"Der {dienst or 'zugehörige Dienst'} (Port {', '.join(map(str, ports))}) läuft nicht "
                           "oder lauscht nicht – von außen nicht angreifbar.")
            if dienst:
                gruende.append(f"Die Lücke trifft laut Beschreibung nur einen {dienst}. Programme, die die "
                               "Bibliothek nur nutzen, ohne selbst so einen Dienst anzubieten, sind nicht angreifbar.")
                return {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Nein", "lokal": "Nein (Dienst läuft nicht)",
                        "gruende": gruende, "tun": tun}
        return {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Nein", "gruende": gruende, "tun": tun}
    nutzer = []
    if "Reverse Depends:" in text:
        teil = text.split("Reverse Depends:", 1)[1]
        for z in teil.splitlines()[1:]:
            z = z.strip().lstrip("|").strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9+.:-]+", z):  # nur Paketnamen, Ende bei Prompt/ss-Ausgabe
                break
            n = z.split(":")[0]
            if n not in nutzer:
                nutzer.append(n)
    erg = {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Unklar", "gruende": gruende, "tun": tun}
    beschr = r.get("beschreibung", "")
    if lokale_luecke(beschr):
        gruende.append("Laut Beschreibung nur **lokal** ausnutzbar: Ein Angreifer müsste schon auf diesem Rechner "
                       "angemeldet sein. Über das Netz ist die Lücke nicht erreichbar.")
        erg["angreifbar"] = "Nein"
    if "secure boot" in beschr.lower():
        gruende.append("Die Lücke hebelt nur **Secure Boot** aus. Ist Secure Boot auf diesem Rechner aus, "
                       "bringt sie einem Angreifer nichts zusätzlich.")
        erg["befehle"] = "mokutil --sb-state 2>/dev/null || echo 'Secure Boot nicht verfügbar (z. B. BIOS-Start oder VM ohne UEFI-SB)'"
        erg["befehle_text"] = "Optional prüfen, ob Secure Boot an ist (`SecureBoot disabled` = Lücke praktisch bedeutungslos):"
    if client_luecke(beschr):
        gruende.append("Es ist eine **Client-Lücke**: Ausnutzbar nur, wenn ein Programm auf diesem Rechner selbst "
                       "einen Server des Angreifers anfragt. Über offene Ports dieses Rechners ist sie nicht erreichbar.")
        erg["angreifbar"] = "Nein"
    if datei_luecke(beschr, r.get("paket", "")) and erg["angreifbar"] != "Nein":
        gruende.append("Ausnutzbar nur, wenn jemand auf diesem Rechner eine **präparierte Datei** (oder einen präparierten Pfad) selbst öffnet "
                       "oder verarbeitet. Über offene Ports dieses Rechners ist die Lücke nicht erreichbar.")
        erg["angreifbar"] = "Nein"
        erg["tun"] += " Bis dahin keine Dateien aus unbekannter Quelle mit dem Programm öffnen."
    if server_luecke(beschr) and nutzer and all("client" in n for n in nutzer) and erg["angreifbar"] != "Ja":
        gruende.append("Die Lücke steckt im **Server-Teil** der Bibliothek. Genutzt wird sie hier nur von "
                       "Client-Programmen (" + ", ".join(f"`{n}`" for n in nutzer[:6]) + "), die diesen Teil nicht "
                       "verwenden.")
        return {"ampel": "gruen", "betroffen": "Ja", "angreifbar": "Nein", "lokal": "Nein (nur Client-Nutzung)",
                "gruende": gruende,
                "tun": "Nichts dringend. Das Update kommt mit den normalen Debian-Updates. Wird später ein Dienst "
                       "installiert, der die Bibliothek als Server nutzt, die Meldung neu prüfen."}
    if gui_luecke(beschr) and "Reverse Depends:" in text and not any(re.search(GUI_PAKET, n) for n in nutzer):
        gruende.append("Die Lücke steckt nur in der **grafischen Fassung** (GUI, z. B. gvim). Die ist hier nicht "
                       "installiert: Genutzt wird das Paket nur von " + ", ".join(f"`{n}`" for n in nutzer[:6] or
                                                                              ["keinem Programm"]) + ".")
        return {"ampel": "gruen", "betroffen": "Ja", "angreifbar": "Nein", "lokal": "Nein (keine GUI-Fassung)",
                "gruende": gruende,
                "tun": "Nichts dringend. Das Update kommt mit den normalen Debian-Updates. Wird später eine "
                       "GUI-Fassung installiert (Paketname mit gtk, gui, motif …), die Meldung neu prüfen."}
    if gui_luecke(beschr):
        gruende.append("Ausnutzbar nur in der **grafischen Fassung** (GUI) – die ist hier installiert.")
    bibliotheken = [n for n in nutzer if re.search(r"^lib|-libs?$|^zlib|lib\d", n)]
    if nutzer and len(bibliotheken) == len(nutzer):
        satz = f"`{r['paket']}` wird nur von Bibliotheken genutzt (" + ", ".join(f"`{n}`" for n in nutzer[:6]) + ")."
        if erg["angreifbar"] == "Unklar":
            satz += " Welche Programme dahinterstehen, zeigt der Befehl unten."
        gruende.append(satz)
        if erg["angreifbar"] == "Unklar" and not erg.get("befehle"):
            erg["befehle"] = "\n".join(f"apt-cache rdepends --installed --no-breaks --no-conflicts --no-replaces "
                                       f"--no-enhances --no-suggests {n}" for n in bibliotheken[:3])
            erg["befehle_text"] = "Zum Weiterprüfen (Ausgabe gern hier einfügen, ich lese sie dir vor):"
    elif nutzer:
        gruende.append("Genutzt wird das Paket von: " + ", ".join(f"`{n}`" for n in nutzer[:6]) + ".")
        if bibliotheken and erg["angreifbar"] == "Unklar" and not erg.get("befehle"):
            gruende[-1] += " Welche Programme hinter den Bibliotheken stehen, zeigt der Befehl unten."
            erg["befehle"] = "\n".join(f"apt-cache rdepends --installed --no-breaks --no-conflicts --no-replaces "
                                       f"--no-enhances --no-suggests {n}" for n in bibliotheken[:3])
            erg["befehle_text"] = "Zum Weiterprüfen (Ausgabe gern hier einfügen):"
    else:
        gruende.append("Kein installiertes Programm hängt von diesem Paket ab.")
        erg["angreifbar"] = "Nein"
    return erg


def werte_secureboot_aus(an):
    if not an:
        return {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein",
                "gruende": ["Secure Boot ist auf diesem Rechner **aus**. Die Lücke umgeht nur Secure Boot – "
                            "ohne Secure Boot gibt es nichts zu umgehen."],
                "tun": "Nichts. Die Meldung kann in Wazuh ignoriert werden. Das Update kommt mit den normalen "
                       "Debian-Updates."}
    return {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Nein", "lokal": "Nur mit Root-Rechten",
            "gruende": ["Secure Boot ist auf diesem Rechner **an**, die Lücke ist also grundsätzlich relevant.",
                        "Ausnutzen kann sie aber nur, wer schon Root-Rechte auf dem Rechner hat. Der Gewinn für den "
                        "Angreifer: Er könnte trotz Secure Boot unsignierten Code beim Start laden und sich so "
                        "dauerhaft einnisten."],
            "tun": "Update einspielen, sobald Debian es liefert (`sudo apt update && apt list --upgradable "
                   "2>/dev/null | grep grub`). Keine Sofortmaßnahme nötig, solange niemand Fremdes Root-Zugang hat."}


def werte_tiocsti_aus(text, ergebnis):
    """Lücken über TIOCSTI (Zeichen ins Terminal schieben) wirken nicht, wenn der Kernel das sperrt (ab 6.2)."""
    m = re.search(r"legacy_tiocsti\s*=\s*([01])", text)
    if m and m.group(1) == "0":
        return {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein",
                "gruende": ["Die Lücke braucht den Terminal-Trick **TIOCSTI** (Zeichen in ein fremdes Terminal "
                            "schieben). Der Kernel sperrt ihn auf diesem Rechner (`dev.tty.legacy_tiocsti = 0`), "
                            "die Lücke lässt sich also nicht ausnutzen."],
                "tun": "Nichts. Die Meldung kann in Wazuh ignoriert werden. Wichtig: `dev.tty.legacy_tiocsti` "
                       "nicht auf 1 stellen."}
    if not ergebnis and (m or re.search(r"legacy_tiocsti", text)):  # nur die sysctl-Zeile eingefügt
        ergebnis = {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Nein", "lokal": "Ja",
                    "gruende": ["Die Lücke ist nur lokal ausnutzbar: Ein Angreifer müsste schon auf diesem Rechner "
                                "angemeldet sein."],
                    "tun": "TIOCSTI sperren: `sysctl -w dev.tty.legacy_tiocsti=0`, dauerhaft mit einer Datei in "
                           "`/etc/sysctl.d/` (z. B. `echo dev.tty.legacy_tiocsti=0 > /etc/sysctl.d/90-tiocsti.conf`)."}
    if not ergebnis:
        return None
    if m:
        ergebnis["gruende"].append("Der Kernel erlaubt TIOCSTI (`dev.tty.legacy_tiocsti = 1`). Abhilfe ohne "
                                   "Update: `sysctl -w dev.tty.legacy_tiocsti=0` (dauerhaft in "
                                   "`/etc/sysctl.d/`).")
    elif re.search(r"legacy_tiocsti.*(unknown key|cannot stat|nicht gefunden)|"
                   r"(unknown key|cannot stat|nicht gefunden).*legacy_tiocsti", text, re.I):
        ergebnis["gruende"].append("Der Kernel kennt die TIOCSTI-Sperre nicht (älter als 6.2). Die Lücke ist "
                                   "grundsätzlich ausnutzbar, aber nur von jemandem, der schon angemeldet ist.")
    return ergebnis


# ---------------------------------------------------------------- Ausgabe

KOPF_A = {"gruen": "🟢 Kein Handlungsbedarf", "gelb": "🟡 Unklar – bitte prüfen", "rot": "🔴 Handlungsbedarf"}
KOPF_B = {"gruen": "🟢 Kein Problem", "gelb": "🟡 Betroffen, aber derzeit nicht angreifbar",
          "gelb_unklar": "🟡 Betroffen – Risiko hängt von den nutzenden Programmen ab",
          "rot": "🔴 Problem bestätigt"}


def lokale_luecke(beschreibung):
    """Lücke, die nur jemand ausnutzen kann, der schon auf dem Rechner ist."""
    b = beschreibung.lower()
    return re.search(r"\blocal(ly)? (authenticated |privileged |unprivileged )?(attacker|user)|\blocally\b|"
                     r"physical access|attacker with (local|physical) access|requires? (root|administrator|admin) "
                     r"privileges", b) is not None


def client_luecke(beschreibung):
    """Lücke, die nur greift, wenn dieser Rechner selbst einen bösartigen Server anfragt."""
    b = beschreibung.lower()
    return ("client" in b and re.search(r"attacker[- ]controlled (host|server)|malicious (\w+ )?server|"
                                        r"rogue (\w+ )?server|crafted (\w+ )?(replies|responses?)", b) is not None)


def datei_luecke(beschreibung, paket=""):
    """Lücke, die nur greift, wenn jemand auf diesem Rechner eine präparierte Datei selbst öffnet oder verarbeitet.
    Bei Programmen reicht die präparierte Datei, wenn die Beschreibung nichts von Netz oder Server sagt; Bibliotheken
    können auch Dateien verarbeiten, die ein Server von außen annimmt."""
    b = beschreibung.lower()
    if re.search(r"crafted (\w+ ){0,3}(file|archive|document|image|member|font|project|vimball|pdf|path|directory|"
                 r"filename)s?\b|\b(tags|malicious|untrusted|attacker-controlled) (\w+ ){0,2}files?\b", b) is None:
        return False
    if re.search(r"(privileges|context|permissions) of the (user|victim)|user (running|who opens|opens)|"
                 r"victim (opens|to open)|(trick|convince|persuade)\w* (a |the )?(user|victim)|"
                 r"user interaction|(when|if) (a|the) user (invokes|opens|edits|runs|browses|loads)", b):
        return True
    programm = paket and not re.search(r"^lib|-libs?$|^zlib|lib\d|^python3?-|^perl|^ruby-|^node-", paket)
    return bool(programm) and re.search(r"remote|network|request|server|packet|https?\b|url|client|"
                                         r"connection|upload|web", b) is None


GUI_PAKET = r"gtk|gui|athena|motif|qt|x11|gnome|kde"


def server_luecke(beschreibung):
    """Lücke steckt im Server-Teil einer Bibliothek (z. B. Token-Endpunkt eines OAuth-Servers)."""
    return re.search(r"token endpoint|authorization server|server[- ]side|(acting|running|used) as (a |an )?server|"
                     r"server (implementation|mode|role)", beschreibung.lower()) is not None


def gui_luecke(beschreibung):
    """Lücke steckt nur in der grafischen Fassung eines Programms (z. B. GUI-Vim / gvim)."""
    return re.search(r"\bgui\b|\bgvim\b|graphical (user )?interface", beschreibung.lower()) is not None


def zeile_meldung(r):
    s = f"**{r['cve']}** · `{r['paket']}` {r['version']} auf **{r['host']}**"
    if r["schwere"] != "–":
        s += f" · Schweregrad {r['schwere']} (CVSS {r['cvss']})"
    return s


def antwort_a(r, worum):
    t = [f"## {r.get('kopf') or KOPF_A[r['ampel']]}", "", zeile_meldung(r), ""]
    if r.get("ergebnis"):
        e = r["ergebnis"]
        t += [f"**Ergebnis:** Betroffen: **{e['betroffen']}** · Von außen angreifbar: **{e['angreifbar']}** · "
              f"Lokal ausnutzbar: **{lokal_wert(r, e)}**", ""]
    if worum:
        t += [f"**Worum geht's:** {worum}", ""]
    t += ["**Warum diese Einstufung:**"] + [f"- {g}" for g in r["gruende"]] + [""]
    if r.get("befehle"):
        t += [f"**Was tun:** Diese Befehle auf **{r['host']}** ausführen und die komplette Ausgabe hier einfügen:",
              "", "```bash", r["befehle"], "```", "", f"**So liest du das Ergebnis:** {r['lesen']}"]
    elif r.get("tun"):
        t += [f"**Was tun:** {r['tun']}"]
    elif r["ampel"] == "gruen":
        t += ["**Was tun:** Nichts. Die Meldung kann in Wazuh ignoriert werden."]
    else:
        t += ["**Was tun:** Im Debian-Tracker nachsehen (Link unten), ob die Lücke für deine Debian-Version "
              "behoben ist."]
    det = [("Paket", r["paket"]), ("Paketbeschreibung", r["paket_text"]), ("Installiert", r["version"])] + r["details"]
    det += [("Scanner-Bedingung", r["bedingung"])]
    if r["quelle"]:
        det.append(("Debian-Tracker", r["quelle"]))
    t += ["", "---", "", "##### Details", "", "| | |", "|---|---|"]
    t += [f"| {k} | {str(v).replace('|', '/')} |" for k, v in det]
    return "\n".join(t)


def root_luecke(beschreibung):
    """Lücke, für die der Angreifer schon Root-Rechte braucht (z. B. Zugriff auf die Boot-Konfiguration)."""
    b = beschreibung.lower()
    return re.search(r"requires? (root|administrator|admin(istrative)?) (privileges|access|rights)|"
                     r"control over (\w+'s )?(boot )?(configuration|config)|local(ly)? privileged (attacker|user)|"
                     r"attacker with (root|administrative|admin) (privileges|access|rights)", b) is not None


def lokal_wert(r, e):
    """Kann jemand, der schon auf dem Rechner ist (Benutzerkonto, geöffnete Datei), die Lücke ausnutzen?"""
    if e.get("lokal"):
        return e["lokal"]
    if e["betroffen"] == "Nein":
        return "Nein"
    nvd = r.get("nvd") or {}
    if nvd.get("weg") == "PHYSICAL":
        return "Nur mit Zugriff am Gerät"
    if nvd.get("rechte") == "HIGH":
        return "Nur mit Root-Rechten"
    if nvd.get("weg"):
        return "Ja, falls betroffen" if e["betroffen"] == "Unklar" else "Ja"
    b = r.get("beschreibung", "")
    if root_luecke(b):
        return "Nur mit Root-Rechten"
    if lokale_luecke(b) or datei_luecke(b, r.get("paket", "")) or e["angreifbar"] == "Ja":
        return "Ja, falls betroffen" if e["betroffen"] == "Unklar" else "Ja"
    return "Unklar"


def antwort_b(r, e):
    if e["betroffen"] == "Unklar":
        kopf = "🟡 Noch unklar – Debian-Tracker ansehen"
    elif e["ampel"] == "gelb" and e["angreifbar"] == "Unklar":
        kopf = KOPF_B["gelb_unklar"]
    else:
        kopf = KOPF_B[e["ampel"]]
    t = [f"## {kopf}", "", zeile_meldung(r), "",
         f"**Ergebnis:** Betroffen: **{e['betroffen']}** · Von außen angreifbar: **{e['angreifbar']}** · "
         f"Lokal ausnutzbar: **{lokal_wert(r, e)}**", "",
         "**Warum:**"] + [f"- {g}" for g in e["gruende"]] + ["", f"**Was tun:** {e['tun']}"]
    if e.get("befehle"):
        t += ["", e.get("befehle_text", "Zum Weiterprüfen:"), "", "```bash", e["befehle"], "```"]
    return "\n".join(t)


# ---------------------------------------------------------------- Online-Daten (NVD, Debian-Tracker)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
TRACKER_URL = "https://security-tracker.debian.org/tracker/"
DEBIAN_NAMEN = {"10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}

ONLINE_FRIST = 8  # Sekunden für alle Online-Abfragen zusammen, danach ohne sie weiter
ONLINE_PAUSE = 300  # nach einem Fehlschlag so lange nicht erneut fragen (Sekunden)
HTTP_CODES = {
    200: "erreichbar, alles in Ordnung",
    0: "keine Verbindung oder keine Antwort innerhalb von %d Sekunden – der Open-WebUI-Container kommt nicht "
       "ins Internet (DNS, Firewall oder Proxy prüfen)" % ONLINE_FRIST,
    403: "Zugriff verweigert – oft zu viele Anfragen ohne API-Key, oder ein Proxy blockt",
    404: "Adresse nicht gefunden",
    429: "zu viele Anfragen – eine Minute warten",
}


class _Https4(http.client.HTTPSConnection):
    """Verbindet zuerst über IPv4, je Adresse höchstens 3 s. In vielen Docker-Netzen ist IPv6 kaputt: Python
    probiert die Adressen nacheinander und hängt dann pro IPv6-Adresse bis zum Timeout (curl merkt das nicht)."""
    def connect(self):
        if getattr(self, "_tunnel_host", None):  # Proxy: Standardweg
            return super().connect()
        fehler = OSError("keine Adresse gefunden")
        adressen = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)
        for fam, typ, proto, _, adr in sorted(adressen, key=lambda a: a[0] != socket.AF_INET):
            sock = socket.socket(fam, typ, proto)
            sock.settimeout(3)
            try:
                sock.connect(adr)
            except OSError as f:
                sock.close()
                fehler = f
                continue
            sock.settimeout(self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            return
        raise fehler


class _Https4Handler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_Https4, req, context=getattr(self, "_context", None) or ssl.create_default_context())


ABRUF = urllib.request.build_opener(_Https4Handler())


def code_text(code):
    text = HTTP_CODES.get(code) or ("Dienst gestört oder überlastet – später noch mal" if code >= 500
                                    else "unerwartete Antwort")
    return f"Code {code:03d} – {text}"


def dpkg_vergleich(a, b):
    """Debian-Versionen vergleichen wie dpkg: -1, 0, 1. Beachtet Epoche, Revision und ~ (vor allem anderen)."""
    def zerlege(v):
        v = v.strip()
        m = re.match(r"(\d+):(.*)", v)
        ep, rest = (int(m.group(1)), m.group(2)) if m else (0, v)
        up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "0")
        return ep, up, rev

    def ordnung(c):
        if c == "~":
            return -1
        if c.isalpha():
            return ord(c)
        return ord(c) + 256

    def teil(x, y):
        while x or y:
            nx, ny = re.match(r"\D*", x).group(0), re.match(r"\D*", y).group(0)
            x, y = x[len(nx):], y[len(ny):]
            for i in range(max(len(nx), len(ny))):
                p = ordnung(nx[i]) if i < len(nx) else 0
                q = ordnung(ny[i]) if i < len(ny) else 0
                if p != q:
                    return -1 if p < q else 1
            dx, dy = re.match(r"\d*", x).group(0), re.match(r"\d*", y).group(0)
            x, y = x[len(dx):], y[len(dy):]
            if int(dx or 0) != int(dy or 0):
                return -1 if int(dx or 0) < int(dy or 0) else 1
        return 0

    ea, ua, ra = zerlege(a)
    eb, ub, rb = zerlege(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return teil(ua, ub) or teil(ra, rb)


def lies_nvd(daten):
    """Angriffsweg, nötige Rechte und Mitwirkung aus der NVD-Antwort. {} = NVD hat noch keine Bewertung."""
    try:
        metriken = daten["vulnerabilities"][0]["cve"].get("metrics", {})
    except (KeyError, IndexError, TypeError, AttributeError):
        return {}
    for schluessel in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        for m in sorted(metriken.get(schluessel, []), key=lambda m: m.get("type") != "Primary"):
            d = m.get("cvssData") or {}
            weg = d.get("attackVector") or d.get("accessVector")
            if weg:
                return {"weg": weg.upper(), "rechte": str(d.get("privilegesRequired", "")).upper(),
                        "interaktion": str(d.get("userInteraction", "")).upper()}
    return {}


NVD_WEG = {"NETWORK": "über das Netzwerk", "ADJACENT_NETWORK": "nur aus dem lokalen Netz",
           "ADJACENT": "nur aus dem lokalen Netz", "LOCAL": "nur lokal (angemeldet oder über eine präparierte Datei)",
           "PHYSICAL": "nur mit Zugriff am Gerät"}
NVD_RECHTE = {"NONE": "keine Rechte nötig", "LOW": "normales Benutzerkonto nötig", "HIGH": "Root-Rechte nötig"}


def nvd_text(nvd):
    teile = [NVD_WEG.get(nvd["weg"], nvd["weg"]), NVD_RECHTE.get(nvd.get("rechte", ""), "")]
    if nvd.get("interaktion") not in ("", "NONE"):
        teile.append("jemand muss mitwirken (z. B. Datei öffnen)")
    return ", ".join(t for t in teile if t)


def lies_tracker(seite, release, paket):
    """Stand einer CVE für eine Debian-Version, aus der HTML-Seite des Debian-Trackers."""
    def zellen(zeile):
        return [html.unescape(re.sub(r"<[^>]+>", "", z)).strip()
                for z in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", zeile, re.S)]

    stand, fixe = [], []
    for tab in re.findall(r"<table>(.*?)</table>", seite, re.S):
        zeilen = [zellen(z) for z in re.findall(r"<tr>(.*?)</tr>", tab, re.S)]
        if not zeilen:
            continue
        if zeilen[0][:2] == ["Source Package", "Release"]:
            quelle = ""
            for z in zeilen[1:]:
                if len(z) >= 4:
                    quelle = re.sub(r"\s*\(PTS\)$", "", z[0]) or quelle
                    stand.append((quelle, z[1], z[2], z[3]))
        elif "Fixed Version" in zeilen[0]:
            fixe += [(z[0], z[2], z[3], z[4]) for z in zeilen[1:] if len(z) >= 5]
    pre = html.unescape(re.sub(r"<[^>]+>", " ", " ".join(re.findall(r"<pre>(.*?)</pre>", seite, re.S))))
    notizen = re.findall(r"\[(\w+)\] - (\S+) <([\w-]+)>\s*(\([^)]*\))?", pre)

    namen = list(dict.fromkeys(q for q, *_ in stand))
    if not namen:
        return {}
    teile = namens_teile(paket)
    q = ([n for n in namen if namens_teile(n) & teile] or namen)[0]
    zeilen = [(st, ver) for qq, rel, ver, st in stand
              if qq == q and release in [x.strip() for x in rel.replace("(security)", "").split(",")]]
    if not zeilen:
        return {}
    status = "fixed" if any(st == "fixed" for st, _ in zeilen) else zeilen[0][0].split()[0]
    fix = next((fv for pk, rel, fv, _ in fixe if pk == q and rel == release and re.match(r"\d", fv)), None)
    if not fix and status == "fixed":
        fix = next(ver for st, ver in zeilen if st == "fixed")
    notiz = next(((art, text.strip("()")) for rel, pk, art, text in notizen if rel == release and pk == q), ("", ""))
    if notiz[0] == "not-affected" or any(pk == q and rel in (release, "(unstable)") and "not affected" in fv.lower()
                                         for pk, rel, fv, _ in fixe):
        status = "not-affected"
    unwichtig = any(pk == q and rel in (release, "(unstable)") and urg == "unimportant" for pk, rel, _, urg in fixe)
    return {"release": release, "quellpaket": q, "status": status, "fix": fix, "unwichtig": unwichtig,
            "notiz": notiz[0], "notiz_text": notiz[1]}


NOTIZ = {"no-dsa": "kein eigenes Sicherheitsupdate geplant, der Fix kommt höchstens mit einem normalen Debian-Update",
         "ignored": "wird für diese Debian-Version nicht behoben",
         "postponed": "verschoben, kommt mit einem späteren Update",
         "end-of-life": "für diese Debian-Version gibt es keine Sicherheitsupdates mehr"}
NOTIZ_TEXT = {"Minor issue": "geringfügiges Problem", "Revisit when fixed upstream": "Fix der Entwickler abwarten"}


def debian_text(deb):
    if deb["status"] == "not-affected":
        return "nicht betroffen"
    if deb.get("fix"):
        return f"behoben in {deb['fix']}"
    if deb.get("unwichtig"):
        return "offen, von Debian als unwichtig eingestuft"
    t = "offen, noch kein Fix"
    if deb.get("notiz"):
        t += f" ({deb['notiz']}" + (f": {deb['notiz_text']}" if deb.get("notiz_text") else "") + ")"
    return t


def wende_online_an(r):
    """NVD und Debian-Tracker in die erste Bewertung einrechnen. Ohne Daten bleibt alles, wie es ist."""
    nvd, deb = r.get("nvd") or {}, r.get("debian") or {}
    if nvd:
        r["details"].append(("Angriffsweg (NVD)", nvd_text(nvd)))
    if deb:
        r["details"].append((f"Debian-Tracker ({deb['release']})", debian_text(deb)))
    if r.get("online_info"):
        r["details"].append(("Online-Abfrage", r["online_info"]))
    if r.get("typ") != "paket" or not deb:
        return r
    r["alt"] = False  # der Tracker ist schon gelesen, „im Tracker nachsehen“ entfällt
    quelle = deb.get("quellpaket")
    quell_grund = []
    if quelle:
        r["details"].append(("Debian-Quellpaket", quelle))
        herkunft = f"`{r['paket']}` stammt aus dem Debian-Quellpaket `{quelle}`. " if quelle != r["paket"] else ""
        quell_grund = [herkunft + f"Meldet Wazuh {r['cve']} für weitere Pakete aus `{quelle}`, gilt dieselbe "
                       "Bewertung – die müssen nicht einzeln geprüft werden."]
    weg = nvd.get("weg", "")
    nvd_grund = [f"Angriffsweg laut NVD: {nvd_text(nvd)}."] if weg else []
    angreifbar = "Ja" if weg == "NETWORK" else "Nein" if weg in ("LOCAL", "PHYSICAL") else "Unklar"

    def fertig(ampel, kopf, grund, tun, betroffen, angr):
        r.update(ampel=ampel, kopf=kopf, tun=tun, befehle=None, gruende=[grund] + nvd_grund + quell_grund,
                 ergebnis={"betroffen": betroffen, "angreifbar": angr})
        return r

    fix, inst = deb.get("fix"), r["version"]
    if deb["status"] == "not-affected":
        return fertig("gruen", None, f"Laut Debian-Tracker ist {deb['release']} von dieser Lücke **nicht betroffen**.",
                      None, "Nein", "Nein")
    if fix and dpkg_vergleich(inst, fix) >= 0:
        return fertig("gruen", None, f"Debian hat die Lücke in Version `{fix}` behoben. Installiert ist `{inst}` – "
                      "der Fix ist drin.", None, "Nein", "Nein")
    if fix:
        ampel = "rot" if weg == "NETWORK" else "gelb"
        return fertig(ampel, ("🔴" if ampel == "rot" else "🟡") + " Update verfügbar – bitte einspielen",
                      f"Debian hat den Fix in Version `{fix}` geliefert, installiert ist noch `{inst}`.",
                      f"Update einspielen: `sudo apt update && sudo apt install --only-upgrade {r['paket']}` "
                      "(oder alle Updates mit `sudo apt full-upgrade`).", "Ja", angreifbar)
    if deb.get("unwichtig"):
        return fertig("gruen", None, "Debian stuft die Lücke als **unwichtig** ein (im normalen Betrieb kein "
                      "Sicherheitsrisiko) und plant keinen Fix.", None, "Kaum (Debian: unwichtig)", angreifbar)
    offen = f"Debian kennt die Lücke, für {deb['release']} gibt es aber **noch keinen Fix**"
    if deb.get("notiz"):
        offen += f": {NOTIZ.get(deb['notiz'], deb['notiz'])}"
        if deb.get("notiz_text"):
            offen += f" („{NOTIZ_TEXT.get(deb['notiz_text'], deb['notiz_text'])}“)"
    offen += "."
    if r["ampel"] == "gruen":  # die Versionsgrenze sagt schon „nicht betroffen“: Begründung behalten
        r["gruende"].append(offen[:-1] + ". Das heißt oft nur, dass Debian die Lücke für diese Version noch nicht "
                            "geprüft hat – die Versionsgrenze aus der Beschreibung ist hier eindeutiger.")
        return r
    sonder = re.search(r"tiocsti|secure boot", r["beschreibung"].lower())  # eigene Prüfbefehle können entlasten
    if weg in ("LOCAL", "PHYSICAL") and not sonder:
        return fertig("gelb", "🟡 Betroffen, aber nur lokal ausnutzbar", offen,
                      "Kein Sofortbedarf. Update einspielen, sobald Debian es liefert. Nachsehen mit "
                      f"`sudo apt update && apt list --upgradable 2>/dev/null | grep '^{r['paket']}/'`.", "Ja", "Nein")
    r["gruende"] = [offen] + nvd_grund + quell_grund
    if r.get("befehle") and "tiocsti" in r["beschreibung"].lower():
        r["kopf"] = "🟡 Nur lokal – ein Befehl klärt, ob ausnutzbar"
        r["gruende"].append("Die Lücke braucht den Terminal-Trick **TIOCSTI**. Ob der Kernel ihn sperrt, zeigt der "
                            "Befehl unten.")
    elif r.get("befehle"):
        r["kopf"] = "🟡 Betroffen – bitte prüfen, ob erreichbar"
        r["gruende"].append("Ob die Lücke auf diesem Rechner erreichbar ist, zeigen die Befehle unten.")
    return r


def nvd_nachbessern(r, ergebnis):
    """Folgeantwort: Sagt NVD „nur lokal“, ist die Lücke von außen nicht angreifbar – egal welche Ports offen sind."""
    weg = (r.get("nvd") or {}).get("weg")
    if ergebnis["betroffen"] != "Nein" and weg in ("LOCAL", "PHYSICAL") and ergebnis["angreifbar"] != "Nein":
        ergebnis["angreifbar"] = "Nein"
        ergebnis["gruende"].append(f"Angriffsweg laut NVD: {nvd_text(r['nvd'])} – nicht über das Netz.")
    return ergebnis


# ---------------------------------------------------------------- Open WebUI

def text_von(nachricht):
    c = nachricht.get("content", "")
    if isinstance(c, list):
        c = "\n".join(x.get("text", "") for x in c if isinstance(x, dict))
    return c or ""


def datei_texte(dateien):
    """Inhalte angehängter Dateien. Open WebUI legt lange eingefügte Texte je nach Einstellung als Datei an."""
    texte = []
    for d in dateien or []:
        if not isinstance(d, dict):
            continue
        f = d.get("file") if isinstance(d.get("file"), dict) else d
        data = f.get("data") if isinstance(f.get("data"), dict) else {}
        t = next((x for x in (data.get("content"), f.get("content"), d.get("content"))
                  if isinstance(x, str) and x.strip()), None)
        if t and t not in texte:
            texte.append(t)
    return texte


def voller_text(nachricht):
    return "\n".join([text_von(nachricht)] + datei_texte(nachricht.get("files")))


KEIN_TEXT = ("Bei mir ist kein Text angekommen. Vermutlich hat Open WebUI die eingefügte Ausgabe als **Datei** "
             "angehängt (Einstellungen → Benutzeroberfläche → „Großen Text als Datei einfügen“). Diese Einstellung "
             "ausschalten und die Ausgabe noch einmal einfügen.")


class Pipe:
    class Valves(BaseModel):
        LLM_URL: str = Field(default="http://localhost:8080/v1",
                             description="OpenAI-kompatible API (llama.cpp, Ollama, vLLM, OpenAI …), endet auf /v1. Mehrere Adressen möglich (eine pro Zeile), die erste erreichbare wird genutzt")
        LLM_KEY: str = Field(default="", description="API-Key, falls der Server einen verlangt")
        LLM_MODELL: str = Field(default="", description="Modellname, z. B. qwen3.5-9b oder llama3.1:8b")
        WORUM_SATZ: bool = Field(default=True, description="Satz 'Worum geht's' vom Sprachmodell schreiben lassen")
        ONLINE: bool = Field(default=True, description="NVD (Angriffsweg) und Debian-Tracker (Fix-Stand) abfragen. "
                             "Braucht Internet im Open-WebUI-Container; ohne gelten nur die festen Regeln. "
                             "Prüfen: im Chat 'Verbindungstest' schreiben")
        NVD_KEY: str = Field(default="", description="Optionaler NVD-API-Key (mehr Anfragen pro Minute), "
                             "kostenlos bei nvd.nist.gov/developers/request-an-api-key")

    def __init__(self):
        self.valves = self.Valves()
        self._zuletzt = ""  # zuletzt erreichbare LLM-Adresse, wird zuerst probiert
        self._online = {}  # CVE -> (NVD-Daten, Tracker-Seite), nur erfolgreiche Abfragen
        self._pause_bis = 0  # bis dahin keine Online-Abfrage (letzte hatte keine Verbindung)

    def llm_adressen(self):
        adressen = [a for a in re.split(r"[\s,;]+", self.valves.LLM_URL or "") if a.startswith("http")]
        if self._zuletzt in adressen:
            adressen.remove(self._zuletzt)
            adressen.insert(0, self._zuletzt)
        return adressen

    @staticmethod
    def erreichbar(url):
        u = urllib.parse.urlparse(url)
        try:
            socket.create_connection((u.hostname, u.port or (443 if u.scheme == "https" else 80)), timeout=2).close()
            return True
        except OSError:
            return False

    def worum(self, beschreibung):
        if not self.valves.WORUM_SATZ or not beschreibung:
            return ""
        body = {
            "model": self.valves.LLM_MODELL,
            "messages": [
                {"role": "system", "content": "Erkläre in genau einem Satz auf Deutsch, für Laien verständlich, was die "
                 "beschriebene Sicherheitslücke ist und wie sie ausgelöst wird. Höchstens 30 Wörter. Keine Aussage "
                 "darüber, ob ein Rechner betroffen ist, keine Versionsnummern, keine Einleitung."},
                {"role": "user", "content": beschreibung[:3000]},
            ],
            "temperature": 0.3, "max_tokens": 120,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        for adresse in self.llm_adressen():
            if not self.erreichbar(adresse):
                continue
            try:
                kopf = {"Content-Type": "application/json"}
                if self.valves.LLM_KEY:
                    kopf["Authorization"] = f"Bearer {self.valves.LLM_KEY}"
                req = urllib.request.Request(adresse.rstrip("/") + "/chat/completions", json.dumps(body).encode(), kopf)
                antwort = json.load(urllib.request.urlopen(req, timeout=60))
                satz = antwort["choices"][0]["message"]["content"].strip()
                self._zuletzt = adresse
                return re.sub(r"\s+", " ", satz)
            except Exception:  # diese Adresse antwortet nicht sinnvoll: nächste probieren
                continue
        return ""  # kein Sprachmodell erreichbar: Antwort kommt dann ohne "Worum geht's"

    @staticmethod
    def hole(url, kopf=None):
        """-> (HTTP-Code, Text). Code 0 = keine Verbindung."""
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "wazuh-analyse (Open WebUI)", **(kopf or {})})
            with ABRUF.open(req, timeout=10) as antwort:
                return antwort.status, antwort.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as f:
            return f.code, ""
        except Exception:
            return 0, ""

    def hole_alle(self, auftraege):
        """{name: (url, kopf)} parallel holen, zusammen höchstens ONLINE_FRIST Sekunden -> {name: (code, text)}.
        Hängt eine Abfrage (z. B. DNS ohne Antwort), läuft sie im Hintergrund aus, die Antwort kommt trotzdem."""
        if not auftraege:
            return {}
        pool = ThreadPoolExecutor(max_workers=len(auftraege))
        jobs = {name: pool.submit(self.hole, url, kopf) for name, (url, kopf) in auftraege.items()}
        wait(list(jobs.values()), timeout=ONLINE_FRIST)
        pool.shutdown(wait=False)
        return {name: (j.result() if j.done() else (0, "")) for name, j in jobs.items()}

    def nvd_kopf(self):
        return {"apiKey": self.valves.NVD_KEY} if self.valves.NVD_KEY else {}

    def online(self, r):
        """NVD und Debian-Tracker abfragen und ins Ergebnis schreiben (r["nvd"], r["debian"], r["online_info"])."""
        if not self.valves.ONLINE or not re.fullmatch(r"CVE-\d{4}-\d+", str(r["cve"])):
            return r
        nvd_daten, seite = self._online.get(r["cve"], (None, None))
        auftraege = {}
        if nvd_daten is None:
            auftraege["nvd"] = (NVD_URL + r["cve"], self.nvd_kopf())
        if seite is None and r.get("release"):
            auftraege["deb"] = (TRACKER_URL + r["cve"], {})
        if auftraege and time.time() < self._pause_bis:
            r["online_info"] = "Online-Abfrage pausiert, weil die letzte keine Verbindung bekam – Bewertung nur " \
                               "nach den festen Regeln. Prüfen: im Chat „Verbindungstest“ schreiben."
            return r
        geholt = self.hole_alle(auftraege)
        if geholt and all(code == 0 for code, _ in geholt.values()):
            self._pause_bis = time.time() + ONLINE_PAUSE
        fehler = []
        if "nvd" in geholt:
            code, text = geholt["nvd"]
            try:
                nvd_daten = json.loads(text) if code == 200 else None
            except ValueError:
                code = -1
            if nvd_daten is None:
                fehler.append("NVD: " + (code_text(code) if code >= 0 else "Antwort unlesbar"))
        if "deb" in geholt:
            code, text = geholt["deb"]
            seite = text if code == 200 else None
            if seite is None:
                fehler.append("Debian-Tracker: " + code_text(code))
        if nvd_daten is not None and (seite is not None or not r.get("release")):
            if len(self._online) > 500:
                self._online.clear()
            self._online[r["cve"]] = (nvd_daten, seite)
        r["nvd"] = lies_nvd(nvd_daten) if nvd_daten else {}
        r["debian"] = lies_tracker(seite, r["release"], r["paket"]) if seite else {}
        if nvd_daten and not r["nvd"]:
            fehler.append("NVD: noch keine Bewertung für diese CVE")
        if fehler:
            r["online_info"] = " · ".join(fehler) + " – Bewertung nur nach den festen Regeln. Prüfen: im Chat " \
                                                    "„Verbindungstest“ schreiben."
        return r

    def mit_online(self, r):
        """Online-Daten anwenden; jeder Fehler darin fällt auf die festen Regeln zurück."""
        try:
            return wende_online_an(self.online(copy.deepcopy(r)))
        except Exception as f:
            r["details"].append(("Online-Abfrage", f"übersprungen wegen eines Fehlers ({type(f).__name__}) – "
                                                   "Bewertung nur nach den festen Regeln."))
            return r

    def verbindungstest(self):
        t = ["## Verbindungstest", "", "| Ziel | Ergebnis |", "|---|---|"]
        if not self.valves.ONLINE:
            t.append("| NVD, Debian-Tracker | ausgeschaltet (Einstellung `ONLINE`) |")
        else:
            self._pause_bis = 0
            geholt = self.hole_alle({"NVD (Angriffsweg)": (NVD_URL + "CVE-2021-44228", self.nvd_kopf()),
                                     "Debian-Tracker (Fix-Stand)": (TRACKER_URL + "CVE-2021-44228", {})})
            for name, (code, _) in geholt.items():
                t.append(f"| {name} | {'✅' if code == 200 else '❌'} {code_text(code)} |")
        for adresse in self.llm_adressen():
            ok = self.erreichbar(adresse)
            t.append(f"| Sprachmodell `{adresse}` | {'✅ erreichbar' if ok else '❌ keine Verbindung'} |")
        t += ["", "**So liest du die Codes:** **200** = alles in Ordnung. **000** = keine Verbindung: Der "
              "Open-WebUI-Container kommt nicht ins Internet (DNS, Firewall oder Proxy). **403** = Zugriff verweigert, "
              "meist zu viele Anfragen ohne API-Key. **429** = zu viele Anfragen, eine Minute warten. **5xx** = der "
              "Dienst ist gerade gestört.", "",
              "Ohne Internet funktioniert die Funktion trotzdem – dann nur mit den festen Regeln und den Prüfbefehlen."]
        return "\n".join(t)

    async def pipe(self, body: dict, __task__=None, __files__=None) -> str:
        # Eigener Thread: Während Online-Abfrage und Sprachmodell laufen, bleibt Open WebUI bedienbar
        # (eine normale def-Funktion würde den ganzen Server blockieren -> "Verbindung unterbrochen").
        return await asyncio.to_thread(self.antworte, body, __task__, __files__)

    def antworte(self, body, __task__=None, __files__=None):
        nachrichten = body.get("messages", [])
        if __task__:
            for n in reversed(nachrichten):
                e = lade_eintrag(voller_text(n)) if n.get("role") == "user" else None
                if e:
                    return json.dumps({"title": f"Wazuh {e['vulnerability'].get('id', '')} {e['agent'].get('name', '')}",
                                       "tags": ["Wazuh"], "follow_ups": []})
            return json.dumps({"title": "Wazuh-Analyse", "tags": ["Wazuh"], "follow_ups": []})

        nutzer = [n for n in nachrichten if n.get("role") == "user"]
        if not nutzer:
            return "Bitte einen Wazuh-Schwachstellen-Eintrag (JSON) einfügen."
        letzte = text_von(nutzer[-1])
        if re.fullmatch(r"\s*(verbindungs?test|verbindung (testen|prüfen))\s*[.!?]*\s*", letzte, re.I):
            return self.verbindungstest()
        # Anhänge der letzten Nachricht; ältere Open-WebUI-Fassungen geben sie nur über __files__/body["files"] mit
        anhang = datei_texte(nutzer[-1].get("files")) or datei_texte(__files__ or body.get("files"))
        frueher = next((lade_eintrag(voller_text(n)) for n in reversed(nutzer[:-1]) if lade_eintrag(voller_text(n))),
                       None)
        e = lade_eintrag(letzte)
        if not e and not frueher:  # JSON als Datei angehängt
            e = next((lade_eintrag(t) for t in anhang if lade_eintrag(t)), None)
        if e:
            r = bewerte(e)
            with ThreadPoolExecutor(max_workers=1) as pool:  # Satz vom Sprachmodell parallel zur Online-Abfrage
                satz = pool.submit(self.worum, r["beschreibung"])
                r = self.mit_online(r)
                return antwort_a(r, satz.result())

        if not frueher:
            if not letzte.strip() and not anhang:
                return KEIN_TEXT
            return ("Ich erwarte einen Eintrag aus `wazuh-states-vulnerabilities-*` als JSON "
                    "(mit `package` und `vulnerability`). Bitte den ganzen Eintrag einfügen.")
        letzte = "\n".join([letzte] + [t for t in anhang if not lade_eintrag(t)])
        if not letzte.strip():
            return KEIN_TEXT
        r = self.mit_online(bewerte(frueher))
        sb = re.search(r"secureboot (enabled|disabled)", letzte.lower())
        if sb and "secure boot" in r["beschreibung"].lower():
            return antwort_b(r, werte_secureboot_aus(sb.group(1) == "enabled"))
        if r["typ"] == "kernel" and r.get("treiber"):
            ergebnis = werte_kernel_aus(r, letzte)
        elif r["typ"] == "paket":
            ergebnis = werte_paket_aus(r, letzte)
        else:
            ergebnis = None
        if "tiocsti" in r["beschreibung"].lower():
            ergebnis = werte_tiocsti_aus(letzte, ergebnis)
        if ergebnis:
            ergebnis = nvd_nachbessern(r, ergebnis)
        if not ergebnis:
            return ("Die Ausgabe passt nicht zu den Prüfbefehlen. Bitte die Befehle aus der vorigen Antwort "
                    "ausführen und die **komplette** Ausgabe einfügen.")
        return antwort_b(r, ergebnis)
