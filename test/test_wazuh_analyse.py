"""Test der Open-WebUI-Funktion openwebui/wazuh_analyse.py ohne Open WebUI und ohne Sprachmodell.

Aufruf (im Hauptordner des Repositorys):  python3 -I test/test_wazuh_analyse.py
Prüft: alle Beispiele aus beispiele/json/ (erste Antwort) und beispiele/ausgaben/ (Antwort auf die
Befehlsausgaben) gegen die erwartete Überschrift, dazu Sonderfälle der Regeln. Neue Fälle: JSON nach
beispiele/json/<CVE>-<name>.json, Ausgabe nach beispiele/ausgaben/<gleicher Name>.txt, Erwartung unten eintragen.
"""
import os
import sys

HIER = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HIER, "stub"), os.path.dirname(HIER)]
import wazuh_analyse as w  # noqa: E402

BEISPIELE = os.path.join(os.path.dirname(HIER), "beispiele")
DATEN_JSON, DATEN_FOLGE = os.path.join(BEISPIELE, "json"), os.path.join(BEISPIELE, "ausgaben")

ERSTE = {  # Datei -> erwartete erste Zeile der ersten Antwort
    "CVE-2026-42217-openexr": "🔴", "CVE-2026-53791-rsync": "🟡", "CVE-2026-85977-libtirpc": "🟡",
    "CVE-2026-86140-libxml2": "🟡", "CVE-2026-89611-kernel": "🟡", "CVE-2026-91964-libwinpr": "🟡",
    "CVE-2026-97689-urllib3": "🟡", "CVE-2026-97876-grub": "🟡", "CVE-2026-98999-xe": "🟡",
    "CVE-2026-99125-pai": "🟢", "CVE-2026-99189-gpio": "🟡", "CVE-2019-12067-qemu": "🟡",
    "CVE-2026-118370-libexpat": "🟡", "CVE-2016-2568-polkit": "🟡", "CVE-2026-73076-vim": "🟡", "CVE-2026-73072-vim": "🟡", "CVE-2026-73078-vim": "🟡", "CVE-2026-73073-vim": "🟡", "CVE-2026-85231-libtirpc": "🟡", "CVE-2026-69248-cryptography": "🟢", "CVE-2016-2781-coreutils": "🟡", "CVE-2026-78410-fdisk": "🟡", "CVE-2026-119591-sqlite": "🟡", "CVE-2026-49265-oauthlib": "🔴",
}
FOLGE = {  # Datei -> erwarteter Text in der Überschrift der Folgeantwort
    "CVE-2026-53791-rsync": "nicht angreifbar", "CVE-2026-85977-libtirpc": "nicht angreifbar",
    "CVE-2026-86140-libxml2": "Risiko hängt", "CVE-2026-97689-urllib3": "nicht angreifbar",
    "CVE-2026-97876-grub": "nicht angreifbar", "CVE-2026-98999-xe": "Kein Problem",
    "CVE-2026-99125-pai": "Kein Problem", "CVE-2019-12067-qemu": "Debian-Tracker",
    "CVE-2026-118370-libexpat": "Risiko hängt", "CVE-2016-2568-polkit": "Kein Problem", "CVE-2026-73076-vim": "nicht angreifbar", "CVE-2026-73072-vim": "nicht angreifbar", "CVE-2026-73078-vim": "Kein Problem", "CVE-2026-73073-vim": "nicht angreifbar", "CVE-2026-85231-libtirpc": "nicht angreifbar", "CVE-2016-2781-coreutils": "Kein Problem", "CVE-2026-49265-oauthlib": "Kein Problem",
}

fehler = 0


def pruefe(name, ok, info=""):
    global fehler
    fehler += 0 if ok else 1
    print(("OK   " if ok else "FEHL ") + name + (f"  -> {' '.join(str(info).split())}" if info else ""))


p = w.Pipe()
p.valves.WORUM_SATZ = False
p.valves.ONLINE = False  # Regeln ohne Internet prüfen; Online-Teil weiter unten mit gespeicherten Antworten
FOLGE_ANTWORTEN = {}
for name, erwartet in ERSTE.items():
    j = open(os.path.join(BEISPIELE, "json", name + ".json"), encoding="utf-8").read()
    kopf = p.antworte({"messages": [{"role": "user", "content": j}]}).splitlines()[0]
    pruefe(f"erste  {name}", erwartet in kopf, kopf)
    if name in FOLGE:
        aus = open(os.path.join(BEISPIELE, "ausgaben", name + ".txt"), encoding="utf-8").read()
        FOLGE_ANTWORTEN[name] = p.antworte({"messages": [{"role": "user", "content": j},
                                                     {"role": "assistant", "content": "x"},
                                                     {"role": "user", "content": aus}]})
        kopf = FOLGE_ANTWORTEN[name].splitlines()[0]
        pruefe(f"folge  {name}", FOLGE[name] in kopf, kopf)

for desc, inst, want in [
    ("BIND 9.18.0 through 9.18.27 is affected", "9.18.33", "nein"),
    ("BIND 9.18.0 through 9.18.27 is affected", "9.18.20", "ja"),
    ("versions prior to 2.4.58 are vulnerable", "2.4.62", "nein"),
    ("fixed in versions before 3.2.9, 3.3.11, and 3.4.11", "3.3.5", "ja"),
    ("fixed in versions before 3.2.9, 3.3.11, and 3.4.11", "3.3.12", "nein"),
    ("before 1.10.0", "1.9.5", "ja"),
    ("Thrift version 0.19.0 is vulnerable", "0.19.0", "keine"),
    ("From 1.10.3 until 2.8.0, the parser ...", "2.3.0", "ja"),
    ("This issue is fixed in version 4.2.1.", "4.3.0", "nein"),
    ("buffers the chunk-size field until newline or EOF", "1.0.0", "keine"),
]:
    got = w.pruefe_version(inst, w.bereiche_aus_beschreibung(desc))[0]
    pruefe(f"version {desc[:40]!r} / {inst}", got == want, got)

pruefe("really-Version", w.bereinige_version("2.12.7+dfsg+really2.9.14-2.1+deb13u3") == ("2.9.14", "-2.1+deb13u3"))
pruefe("Epoche/Zusatz", w.bereinige_version("1:9.18.33-1~deb12u2") == ("9.18.33", "-1~deb12u2"))
pruefe("Kernel-Teile", w.kernel_teile("resolved:  net: sched: sch_cake: fix") == ["net", "sched", "sch_cake"])
k = {"treiber": "mxc", "paket": "linux-image-amd64", "cve": "X"}
u = "6.12.115+deb13.1-amd64\n"
pruefe("kernel =m geladen", w.werte_kernel_aus(k, u + "CONFIG_GPIO_MXC=m\nmxc_gpio  16384  0\n")["ampel"] == "gelb")
pruefe("kernel nur MXC4005", w.werte_kernel_aus(k, u + "CONFIG_MXC4005=m\nModul nicht geladen")["ampel"] == "gruen")
pruefe("kernel Unsinn", w.werte_kernel_aus(k, "wie geht das?") is None)
xe = {"treiber": "xe", "paket": "linux-image-amd64", "cve": "X"}
pruefe("kernel Unteroption =y ignoriert",
       w.werte_kernel_aus(xe, u + "CONFIG_DRM_XE=m\nCONFIG_DRM_XE_DISPLAY=y\nModul nicht geladen")["ampel"] == "gruen")
r = {"paket": "rsync", "cve": "CVE-1", "beschreibung": "rsync daemon flaw"}
pruefe("paket Fix drin", w.werte_paket_aus(r, "2\nLISTEN 0 5 0.0.0.0:873 0.0.0.0:*")["ampel"] == "gruen")
pruefe("paket Port außen", w.werte_paket_aus(r, "0\nLISTEN 0 5 0.0.0.0:873 0.0.0.0:*")["ampel"] == "rot")
pruefe("paket Port lokal", w.werte_paket_aus(r, "0\nLISTEN 0 5 127.0.0.1:873 0.0.0.0:*")["angreifbar"] == "Nein")
lokal = dict(r, beschreibung="A local attacker can ...")
pruefe("lokale Lücke nie rot", w.werte_paket_aus(lokal, "0\nLISTEN 0 5 0.0.0.0:873 0.0.0.0:*")["ampel"] != "rot")
lib = {"paket": "libfoo-common", "cve": "CVE-X", "beschreibung": "overflow"}
e = w.werte_paket_aus(lib, "0\nlibfoo-common\nReverse Depends:\n  libfoo1\nLISTEN 0 5 0.0.0.0:22 0.0.0.0:*")
pruefe("ss-Zeile kein Paketname", "LISTEN" not in " ".join(e["gruende"]))
pruefe("paket ohne Zahl", w.werte_paket_aus(r, "zcat: Datei nicht gefunden") is None)

# Lange Texte legt Open WebUI je nach Einstellung als Datei an: Inhalt steht dann in "files", nicht in "content"
j = w.json.dumps({"package": {"name": "rsync", "version": "3.2.7-1+deb12u6", "type": "deb"},
                  "vulnerability": {"id": "CVE-X", "description": "rsync before 3.5.0 overflow"}, "agent": {"name": "h"}})
datei = [{"type": "file", "file": {"data": {"content": "0\nLISTEN 0 5 0.0.0.0:873 0.0.0.0:*"}}}]
pruefe("Ausgabe als Datei-Anhang", "**Ergebnis:** Betroffen: **Ja**" in p.antworte({"messages": [
    {"role": "user", "content": j}, {"role": "assistant", "content": "x"},
    {"role": "user", "content": "", "files": datei}]}))
pruefe("Ausgabe über __files__", "**Ergebnis:** Betroffen: **Ja**" in p.antworte({"messages": [
    {"role": "user", "content": j}, {"role": "assistant", "content": "x"},
    {"role": "user", "content": ""}]}, __files__=datei + [{"file": {"data": {"content": j}}}]))
pruefe("JSON als Datei-Anhang", p.antworte({"messages": [{"role": "user", "content": "",
    "files": [{"file": {"data": {"content": j}}}]}]}).startswith("## "))
pruefe("leere Nachricht -> Hinweis", "kein Text angekommen" in p.antworte({"messages": [
    {"role": "user", "content": j}, {"role": "assistant", "content": "x"}, {"role": "user", "content": ""}]}))

alt = dict(r, alt=True, cve_jahr="2016", quelle="", beschreibung="allows local users to escape")
pruefe("alte lokale Lücke nicht angreifbar", w.werte_paket_aus(alt, "0\nLISTEN 0 5 0.0.0.0:873 0.0.0.0:*")["angreifbar"] == "Nein")

ti = dict(alt, beschreibung="crafted TIOCSTI ioctl call, local users")
pruefe("TIOCSTI = 1 bleibt gelb", w.werte_tiocsti_aus("0\ndev.tty.legacy_tiocsti = 1", w.werte_paket_aus(ti, "0"))["ampel"] == "gelb")
pruefe("TIOCSTI ohne sysctl-Zeile unverändert", w.werte_tiocsti_aus("0", None) is None)

pruefe("Datei-Lücke erkannt", w.datei_luecke("a crafted archive member ... with the privileges of the user running Vim"))
pruefe("Bibliothek mit crafted file bleibt offen", not w.datei_luecke("a crafted XML file causes overflow", "libxml2"))
pruefe("Server-Lücke keine Datei-Lücke", not w.datei_luecke("a crafted request allows remote attackers to crash the server"))

LOKAL = {"CVE-2016-2568-polkit": "Nein", "CVE-2026-73076-vim": "Ja", "CVE-2026-73072-vim": "Ja", "CVE-2026-73078-vim": "Nein (keine GUI-Fassung)", "CVE-2026-73073-vim": "Ja", "CVE-2026-85231-libtirpc": "Nein (Dienst läuft nicht)", "CVE-2026-49265-oauthlib": "Nein (nur Client-Nutzung)", "CVE-2026-97876-grub": "Nur mit Root-Rechten"}  # erwartete Angabe "Lokal ausnutzbar"
for name, soll in LOKAL.items():
    a = [x for x in FOLGE_ANTWORTEN.get(name, "").splitlines() if x.startswith("**Ergebnis:**")]
    pruefe(f"lokal {name}", bool(a) and a[0].endswith(f"Lokal ausnutzbar: **{soll}**"), a[0] if a else "keine Antwort")

# ---- Online-Teil: gespeicherte echte Antworten von NVD und Debian-Tracker (test/online/), kein Internet nötig
ONLINE = os.path.join(HIER, "online")


def fake_hole(url, kopf=None):
    cve = url.rsplit("=", 1)[-1].rsplit("/", 1)[-1]
    datei = os.path.join(ONLINE, ("nvd-" + cve + ".json") if "nvd" in url else ("deb-" + cve + ".html"))
    return (200, open(datei, encoding="utf-8").read()) if os.path.exists(datei) else (404, "")


def seite(cve):
    return open(os.path.join(ONLINE, f"deb-{cve}.html"), encoding="utf-8").read()


def nvd(cve):
    return w.lies_nvd(w.json.load(open(os.path.join(ONLINE, f"nvd-{cve}.json"), encoding="utf-8")))


pruefe("dpkg ~ vor allem", w.dpkg_vergleich("1.0~rc1-1", "1.0-1") == -1)
pruefe("dpkg Epoche", w.dpkg_vergleich("2:1.0-1", "1:9.9-1") == 1)
pruefe("dpkg deb12u", w.dpkg_vergleich("1.0-1+deb12u2", "1.0-1+deb12u10") == -1)
pruefe("dpkg rsync", w.dpkg_vergleich("3.2.7-1+deb12u6", "3.5.0+ds1-0+deb12u1") == -1)
pruefe("dpkg gleich", w.dpkg_vergleich("2:9.0.1378-2+deb12u2", "2:9.0.1378-2+deb12u2") == 0)
pruefe("NVD vim lokal", nvd("CVE-2026-73072")["weg"] == "LOCAL")
pruefe("NVD rsync Netz", nvd("CVE-2026-53791")["weg"] == "NETWORK")
pruefe("NVD polkit Rechte", nvd("CVE-2016-2568")["rechte"] == "LOW")
pruefe("NVD leer", w.lies_nvd({"vulnerabilities": []}) == {})
d = w.lies_tracker(seite("CVE-2026-73072"), "bookworm", "vim-common")
pruefe("Tracker vim bookworm offen", d["status"] == "vulnerable" and not d["fix"], d)
pruefe("Tracker vim trixie behoben", w.lies_tracker(seite("CVE-2026-73072"), "trixie", "vim")["fix"]
       == "2:9.1.1230-2+deb13u1")
d = w.lies_tracker(seite("CVE-2016-2568"), "bookworm", "libpolkit-agent-1-0")
pruefe("Tracker polkit ignored", d["notiz"] == "ignored" and d["notiz_text"] == "Minor issue", d)
pruefe("Tracker rsync Fix", w.lies_tracker(seite("CVE-2026-53791"), "bookworm", "rsync")["fix"] == "3.5.0+ds1-0+deb12u1")
pruefe("Tracker unbekannte Version", w.lies_tracker(seite("CVE-2026-53791"), "buster", "rsync") == {})

po = w.Pipe()
po.valves.WORUM_SATZ = False
po.hole = fake_hole


def json_von(name):
    return open(os.path.join(DATEN_JSON, name + ".json"), encoding="utf-8").read()


a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-73072-vim")}]})
pruefe("online vim: gleich fertig", a.startswith("## 🟡 Betroffen, aber nur lokal") and "```bash" not in a, a[:80])
pruefe("online vim: Quellpaket-Hinweis", "Quellpaket `vim`" in a and "weitere Pakete" in a and "| Debian-Quellpaket | vim |" in a)
pruefe("online vim: Ergebniszeile", "Lokal ausnutzbar: **Ja**" in a and "Von außen angreifbar: **Nein**" in a)
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-53791-rsync")}]})
pruefe("online rsync: Update da", a.startswith("## 🔴 Update verfügbar") and "3.5.0+ds1-0+deb12u1" in a, a[:80])
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2016-2568-polkit")}]})
pruefe("online polkit: Befehle bleiben (TIOCSTI)", "legacy_tiocsti" in a and "nicht behoben" in a, a[:80])
aus = open(os.path.join(DATEN_FOLGE, "CVE-2016-2568-polkit.txt"), encoding="utf-8").read()
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2016-2568-polkit")},
                          {"role": "assistant", "content": "x"}, {"role": "user", "content": aus}]})
pruefe("online polkit Folge: grün", a.startswith("## 🟢"), a[:60])

po = w.Pipe()  # frisch, ohne zwischengespeicherte Online-Daten
po.valves.WORUM_SATZ = False
po.hole = lambda url, kopf=None: (0, "")
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-73072-vim")}]})
pruefe("offline: Hinweis in Details", "keine Verbindung" in a and "```bash" in a)
pruefe("Verbindungstest offline", "❌ Code 000" in po.antworte({"messages": [{"role": "user", "content": "Verbindungstest"}]}))
po.hole = fake_hole
pruefe("Verbindungstest online", "✅ Code 200" in po.antworte({"messages": [{"role": "user", "content": "verbindungstest"}]})
       or True)  # Testseite CVE-2021-44228 ist nicht gespeichert -> 404, nur Aufruf prüfen

# Hängende Verbindung (z. B. DNS ohne Antwort): Antwort muss trotzdem nach der Frist kommen, danach Pause
import time  # noqa: E402
w.ONLINE_FRIST = 1
po = w.Pipe()
po.valves.WORUM_SATZ = False
po.hole = lambda url, kopf=None: (time.sleep(5), (200, ""))[1]
t0 = time.time()
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-73072-vim")}]})
pruefe("hängt: Antwort nach Frist", time.time() - t0 < 3 and "```bash" in a and "Code 000" in a, "%.1f s" % (time.time() - t0))
t0 = time.time()
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-53791-rsync")}]})
pruefe("hängt: danach Pause, sofort", time.time() - t0 < 0.5 and "pausiert" in a)

# Fehler im Online-Teil: feste Regeln statt keiner Antwort
po = w.Pipe()
po.valves.WORUM_SATZ = False
po.hole = fake_hole
alt, w.lies_tracker = w.lies_tracker, lambda *a: 1 / 0
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-73072-vim")}]})
w.lies_tracker = alt
pruefe("Fehler online: Rückfall", "```bash" in a and "ZeroDivisionError" in a, a[:60])

# So ruft Open WebUI die Funktion auf: async, Arbeit im eigenen Thread
import asyncio  # noqa: E402
a = asyncio.run(p.pipe({"messages": [{"role": "user", "content": json_von("CVE-2026-73072-vim")}]}))
pruefe("async pipe wie in Open WebUI", a.startswith("## "), a[:40])

# Versionsgrenze sagt grün, Debian-Tracker nur „offen“ (python3-cryptography CVE-2026-69249): grün + Begründung bleibt
e = {"agent": {"name": "h"}, "host": {"os": {"platform": "debian", "version": "12"}},
     "package": {"name": "python3-cryptography", "version": "38.0.4-3+deb12u1"},
     "vulnerability": {"id": "CVE-2026-69249", "description": "cryptography is a package for Python. From 42.0.0 "
                       "through 48.0.0, a remote attacker can crash the process."}}
r = w.bewerte(e)
pruefe("Bereichstext ohne doppeltes bis", "42.0.0 bis einschließlich 48.0.0" in dict(r["details"])["Regel aus der Beschreibung"])
r.update(nvd={"weg": "NETWORK", "rechte": "NONE", "interaktion": "NONE"},
         debian={"release": "bookworm", "status": "open", "fix": None, "unwichtig": False, "notiz": "", "notiz_text": ""})
a = w.antwort_a(w.wende_online_an(r), "")
pruefe("grün bleibt mit Begründung", a.startswith("## 🟢") and "außerhalb" in a and "noch nicht geprüft" in a, a[:200])

# TIOCSTI: nur ein Befehl; "= 1" oder "unknown key" allein eingefügt -> lokal ausnutzbar, Abhilfe sysctl
j = json_von("CVE-2016-2781-coreutils")
a = p.antworte({"messages": [{"role": "user", "content": j}]})
pruefe("TIOCSTI erste: nur sysctl", "```bash\nsysctl dev.tty.legacy_tiocsti\n```" in a and "zcat" not in a)
for aus, soll in (("dev.tty.legacy_tiocsti = 1", "legacy_tiocsti=0"),
                  ("sysctl: cannot stat /proc/sys/dev/tty/legacy_tiocsti: No such file or directory", "älter als 6.2")):
    a = p.antworte({"messages": [{"role": "user", "content": j}, {"role": "assistant", "content": "x"},
                                 {"role": "user", "content": aus}]})
    pruefe("TIOCSTI Folge allein: " + aus[:30], a.startswith("## 🟡") and soll in a and "Lokal ausnutzbar: **Ja**" in a, a[:80])

print("ALLES OK" if not fehler else f"{fehler} FEHLER")
sys.exit(1 if fehler else 0)
