"""
title: Wazuh-Analyse
author: Elwin Ehlers
author_url: https://github.com/ElwinEhlers
credits: Entwickelt mit Claude (Anthropic)
description: Bewertet Wazuh-Schwachstellen-Einträge (wazuh-states-vulnerabilities) auf Debian/Ubuntu mit festen Regeln und wertet die Ausgaben der Prüfbefehle aus. Das Sprachmodell schreibt nur den Satz "Worum geht's" (optional).
version: 1.8
license: MIT
"""

# Einrichtung: Open WebUI -> Admin-Bereich -> Funktionen -> "+" -> diesen Code einfügen -> speichern -> aktivieren.
# Danach erscheint "Wazuh-Analyse" in der Modellauswahl. Einstellungen (Zahnrad bei der Funktion): LLM-Adresse usw.
#
# Ablauf im Chat:
#   1. Wazuh-JSON einfügen  -> Ampel, Begründung, Prüfbefehle
#   2. Ausgabe der Prüfbefehle einfügen -> Endergebnis (betroffen / angreifbar / was tun)

import json
import re
import socket
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
    oben = f"vor {o}" if art == "lt" else f"bis einschließlich {o}"
    return f"{u} bis {oben}" if u else oben


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
                       f"--upgradable 2>/dev/null | grep {r['paket']}`."}
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
        return {"ampel": "gelb", "betroffen": "Unklar", "angreifbar": "Unklar",
                "gruende": [f"Der Debian-Changelog erwähnt {r['cve']} nicht. Das sagt bei einer so alten Lücke (von "
                            f"{r['cve_jahr']}) aber wenig: Der Changelog nennt nur Fixes, die Debian selbst nachgerüstet "
                            "hat. Ein Fix, der schon in einer neueren Upstream-Version steckt, taucht dort nicht auf.",
                            "Ob Debian die Lücke für deine Version als behoben, unwichtig oder offen führt, steht im "
                            f"Debian-Tracker: {r.get('quelle') or 'security-tracker.debian.org'}"],
                "tun": "Im Debian-Tracker bei deiner Debian-Version nachsehen. Steht dort „not-affected“, "
                       "„unimportant“ oder eine Version ≤ deiner installierten, kann die Meldung ignoriert werden."}
    gruende = [f"Der Debian-Changelog von `{r['paket']}` erwähnt {r['cve']} nicht. Der Fix ist also nicht eingebaut."]
    tun = (f"Update einspielen, sobald Debian es liefert. Nachsehen mit "
           f"`sudo apt update && apt list --upgradable 2>/dev/null | grep {r['paket']}`.")
    ports = ports_fuer(r["paket"])
    if ports:
        aussen = [o for o in offen if o[1] in ports and not o[2]]
        innen = [o for o in offen if o[1] in ports and o[2]]
        if aussen and not lokale_luecke(r.get("beschreibung", "")):
            gruende.append(f"Der zugehörige Dienst lauscht von außen erreichbar auf Port {aussen[0][1]} "
                           f"(`{aussen[0][0]}`).")
            return {"ampel": "rot", "betroffen": "Ja", "angreifbar": "Ja", "gruende": gruende,
                    "tun": tun + " Bis dahin den Dienst nur aus dem eigenen Netz erreichbar machen "
                                 "(Firewall) oder abschalten, wenn er nicht gebraucht wird."}
        if innen:
            gruende.append(f"Der zugehörige Dienst lauscht nur lokal (Port {innen[0][1]} auf `{innen[0][0]}`), "
                           "ist also von außen nicht erreichbar.")
        else:
            gruende.append(f"Der zugehörige Dienst (Port {', '.join(map(str, ports))}) läuft nicht oder lauscht "
                           "nicht – von außen nicht angreifbar.")
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
    return {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Nein",
            "gruende": ["Secure Boot ist auf diesem Rechner **an**, die Lücke ist also grundsätzlich relevant.",
                        "Ausnutzen kann sie aber nur, wer schon Root-Rechte auf dem Rechner hat. Der Gewinn für den "
                        "Angreifer: Er könnte trotz Secure Boot unsignierten Code beim Start laden und sich so "
                        "dauerhaft einnisten."],
            "tun": "Update einspielen, sobald Debian es liefert (`sudo apt update && apt list --upgradable "
                   "2>/dev/null | grep grub`). Keine Sofortmaßnahme nötig, solange niemand Fremdes Root-Zugang hat."}


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


def zeile_meldung(r):
    s = f"**{r['cve']}** · `{r['paket']}` {r['version']} auf **{r['host']}**"
    if r["schwere"] != "–":
        s += f" · Schweregrad {r['schwere']} (CVSS {r['cvss']})"
    return s


def antwort_a(r, worum):
    t = [f"## {KOPF_A[r['ampel']]}", "", zeile_meldung(r), ""]
    if worum:
        t += [f"**Worum geht's:** {worum}", ""]
    t += ["**Warum diese Einstufung:**"] + [f"- {g}" for g in r["gruende"]] + [""]
    if r.get("befehle"):
        t += [f"**Was tun:** Diese Befehle auf **{r['host']}** ausführen und die komplette Ausgabe hier einfügen:",
              "", "```bash", r["befehle"], "```", "", f"**So liest du das Ergebnis:** {r['lesen']}"]
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


def antwort_b(r, e):
    if e["betroffen"] == "Unklar":
        kopf = "🟡 Noch unklar – Debian-Tracker ansehen"
    elif e["ampel"] == "gelb" and e["angreifbar"] == "Unklar":
        kopf = KOPF_B["gelb_unklar"]
    else:
        kopf = KOPF_B[e["ampel"]]
    t = [f"## {kopf}", "", zeile_meldung(r), "",
         f"**Ergebnis:** Betroffen: **{e['betroffen']}** · Von außen angreifbar: **{e['angreifbar']}**", "",
         "**Warum:**"] + [f"- {g}" for g in e["gruende"]] + ["", f"**Was tun:** {e['tun']}"]
    if e.get("befehle"):
        t += ["", e.get("befehle_text", "Zum Weiterprüfen:"), "", "```bash", e["befehle"], "```"]
    return "\n".join(t)


# ---------------------------------------------------------------- Open WebUI

def text_von(nachricht):
    c = nachricht.get("content", "")
    if isinstance(c, list):
        c = "\n".join(x.get("text", "") for x in c if isinstance(x, dict))
    return c or ""


class Pipe:
    class Valves(BaseModel):
        LLM_URL: str = Field(default="http://localhost:8080/v1",
                             description="OpenAI-kompatible API (llama.cpp, Ollama, vLLM, OpenAI …), endet auf /v1. Mehrere Adressen möglich (eine pro Zeile), die erste erreichbare wird genutzt")
        LLM_KEY: str = Field(default="", description="API-Key, falls der Server einen verlangt")
        LLM_MODELL: str = Field(default="", description="Modellname, z. B. qwen3.5-9b oder llama3.1:8b")
        WORUM_SATZ: bool = Field(default=True, description="Satz 'Worum geht's' vom Sprachmodell schreiben lassen")

    def __init__(self):
        self.valves = self.Valves()
        self._zuletzt = ""  # zuletzt erreichbare LLM-Adresse, wird zuerst probiert

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

    def pipe(self, body: dict, __task__=None) -> str:
        nachrichten = body.get("messages", [])
        if __task__:
            for n in reversed(nachrichten):
                e = lade_eintrag(text_von(n)) if n.get("role") == "user" else None
                if e:
                    return json.dumps({"title": f"Wazuh {e['vulnerability'].get('id', '')} {e['agent'].get('name', '')}",
                                       "tags": ["Wazuh"], "follow_ups": []})
            return json.dumps({"title": "Wazuh-Analyse", "tags": ["Wazuh"], "follow_ups": []})

        nutzer = [n for n in nachrichten if n.get("role") == "user"]
        if not nutzer:
            return "Bitte einen Wazuh-Schwachstellen-Eintrag (JSON) einfügen."
        letzte = text_von(nutzer[-1])
        e = lade_eintrag(letzte)
        if e:
            r = bewerte(e)
            return antwort_a(r, self.worum(r["beschreibung"]))

        frueher = next((lade_eintrag(text_von(n)) for n in reversed(nutzer[:-1]) if lade_eintrag(text_von(n))), None)
        if not frueher:
            return ("Ich erwarte einen Eintrag aus `wazuh-states-vulnerabilities-*` als JSON "
                    "(mit `package` und `vulnerability`). Bitte den ganzen Eintrag einfügen.")
        r = bewerte(frueher)
        sb = re.search(r"secureboot (enabled|disabled)", letzte.lower())
        if sb and "secure boot" in r["beschreibung"].lower():
            return antwort_b(r, werte_secureboot_aus(sb.group(1) == "enabled"))
        if r["typ"] == "kernel" and r.get("treiber"):
            ergebnis = werte_kernel_aus(r, letzte)
        elif r["typ"] == "paket":
            ergebnis = werte_paket_aus(r, letzte)
        else:
            ergebnis = None
        if not ergebnis:
            return ("Die Ausgabe passt nicht zu den Prüfbefehlen. Bitte die Befehle aus der vorigen Antwort "
                    "ausführen und die **komplette** Ausgabe einfügen.")
        return antwort_b(r, ergebnis)
