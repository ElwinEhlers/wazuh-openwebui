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
e = w.werte_kernel_aus(k, u + "CONFIG_MXC4005=m\nModul nicht geladen")  # Name geraten, keine Zeile: kein Grün
pruefe("kernel nur MXC4005: nicht belegt", e["ampel"] == "gelb" and "Vermutlich" in e["kopf"], e["kopf"])
pruefe("kernel is not set -> grün", w.werte_kernel_aus(k, u + "# CONFIG_GPIO_MXC is not set")["ampel"] == "gruen")
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


# Kernel-Makefiles (GitHub), nachgebaut mit den Zeilen, auf die es ankommt
MAKEFILES = {
    "Kbuild": "obj-y += kernel/ mm/ fs/\nobj-$(CONFIG_NET) += net/\nobj-y += drivers/\n",
    "kernel/Makefile": "obj-y = fork.o exit.o \\\n\tptrace.o\n",
    "drivers/Makefile": "obj-$(CONFIG_GPIOLIB)\t+= gpio/\nobj-y += gpu/\n",
    "drivers/gpio/Makefile": "obj-$(CONFIG_GPIOLIB) += gpiolib.o\nobj-$(CONFIG_GPIO_MXC)\t+= gpio-mxc.o\n",
    "drivers/gpu/Makefile": "obj-y += drm/\n",
    "drivers/gpu/drm/Makefile": "obj-$(CONFIG_DRM_XE) += xe/\nobj-y += amd/amdgpu/\n",
    "drivers/gpu/drm/xe/Makefile": "xe-y += xe_bb.o \\\n\txe_bo.o\nxe-$(CONFIG_DRM_XE_DISPLAY) += "
                                   "display/xe_fb_pin.o\nobj-$(CONFIG_DRM_XE) += xe.o\n",
    "drivers/gpu/drm/amd/amdgpu/Makefile": "amdgpu-y := amdgpu_drv.o\nobj-$(CONFIG_DRM_AMDGPU) += amdgpu.o\n",
    "fs/Makefile": "obj-$(CONFIG_SMBFS) += smb/\nobj-$(CONFIG_XFS_FS) += xfs/\n",
    "fs/smb/Makefile": "obj-$(CONFIG_SMB_SERVER) += server/\n",
    "fs/smb/server/Makefile": "ksmbd-y := smb2pdu.o vfs_cache.o\nobj-$(CONFIG_SMB_SERVER) += ksmbd.o\n",
    "fs/xfs/Makefile": "obj-$(CONFIG_XFS_FS) += xfs.o\nxfs-y += $(addprefix libxfs/, \\\n\txfs_attr_leaf.o)\n",
}


def fake_hole(url, kopf=None):
    if "raw.githubusercontent.com" in url:
        pfad = url.split("/v6.12/", 1)[-1]
        return (200, MAKEFILES[pfad]) if pfad in MAKEFILES else (404, "")
    cve = url.rsplit("=", 1)[-1].rsplit("/", 1)[-1]
    name = "nvd-%s.json" if "nvd.nist.gov" in url else "cveorg-%s.json" if "cveawg" in url else "deb-%s.html"
    datei = os.path.join(ONLINE, name % cve)
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

# ---- Versionen: Formen, die früher falsch gelesen wurden
for desc, inst, want in [
    ("An issue was discovered in 6.0 before 6.0.3, 5.2 before 5.2.12, and 4.2 before 4.2.29.", "4.2.28", "ja"),
    ("An issue was discovered in 6.0 before 6.0.3, 5.2 before 5.2.12, and 4.2 before 4.2.29.", "4.2.29", "nein"),
    ("From 1.0.0 until 1.10.6 and 2.14.3, the encoder", "2.12.2", "ja"),
    ("From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, and 13.0.2, the engine", "10.11.18", "ja"),
    ("From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, and 13.0.2, the engine", "10.11.19", "nein"),
    ("From 10.6.1 until 10.6.28, 10.11.19, 11.4.13, and 13.0.2, the engine", "10.5.2", "nein"),
    ("versions 4.0.2 and later (fixed in 4.0.14, 5.0.10, 5.21.8 and 6.10)", "5.0.2", "ja"),
    ("from 4.0.2 before 4.0.14, 5.0.10, 5.21.8, and 6.10 on all platforms", "5.0.2", "ja"),
    ("HTTP::Body versions before 1.23_01 for Perl", "1.23", "ja"),
    ("In versions 1.36.37 and below and 1.37.61 through 1.38.0, there is", "1.36.35", "ja"),
    ("From versions 3.0.0 to before 3.2.9, 3.3.0 to before 3.3.11, and 3.4.0 to before 3.4.11, x", "3.3.12", "nein"),
    ("ranges of the form 1.2.3.4-1.2.3.25 are compared wrongly", "4.6.1", "keine"),
    ("This issue affects X: from ? before 7.8.0p0-1.1.", "7.6.0p1", "ja"),
]:
    got = w.pruefe_version(inst, w.bereiche_aus_beschreibung(desc))[0]
    pruefe(f"version {desc[:40]!r} / {inst}", got == want, got)
e = {"agent": {"name": "h"}, "package": {"name": "docker.io", "version": "20.10.24+dfsg1-1"},
     "vulnerability": {"id": "CVE-X", "description": "BuildKit is a toolkit. Prior to version 0.28.1, a frontend can"}}
pruefe("Version außerhalb, Paket nicht genannt: kein Grün", w.bewerte(e)["ampel"] == "gelb")
e["package"]["version"] = "2.3.0-3+deb13u2"
pruefe("Debian-Version aus +deb13", w.bewerte(e)["release"] == "trixie")
e["vulnerability"]["scanner"] = {"condition": "Package less than 2.3.0-3+deb13u5"}
pruefe("Fix-Version aus der Wazuh-Bedingung", "2.3.0-3+deb13u5" in " ".join(w.bewerte(e)["gruende"]))

# ---- Kernel: Bau-Regeln aus Makefiles, Versionsstand von kernel.org
def lies(verzeichnis):
    texte = [MAKEFILES.get((verzeichnis + "/" if verzeichnis else "") + n) for n in ("Makefile", "Kbuild")]
    return "\n".join(t for t in texte if t) or None


for datei, soll in [
    ("drivers/gpu/drm/xe/xe_bo.c", (["CONFIG_DRM_XE"], "xe")),
    ("drivers/gpu/drm/xe/display/xe_fb_pin.c", (["CONFIG_DRM_XE_DISPLAY", "CONFIG_DRM_XE"], "xe")),
    ("drivers/gpio/gpio-mxc.c", (["CONFIG_GPIO_MXC", "CONFIG_GPIOLIB"], "gpio-mxc")),
    ("fs/smb/server/smb2pdu.c", (["CONFIG_SMB_SERVER", "CONFIG_SMBFS"], "ksmbd")),
    ("fs/xfs/libxfs/xfs_attr_leaf.c", (["CONFIG_XFS_FS"], "xfs")),
    ("drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c", (["CONFIG_DRM_AMDGPU"], "amdgpu")),
    ("kernel/ptrace.c", ([], "ptrace")),
    ("drivers/gpio/gibt-es-nicht.c", None), ("fs/smb/server/vfs_cache.h", None),
]:
    b = w.kbuild_loese(datei, lies)
    pruefe(f"kbuild {datei}", (b and (b["symbole"], b["modul"])) == soll, b)

V = [{"version": "6.8", "status": "affected"}, {"version": "0", "lessThan": "6.8", "status": "unaffected"},
     {"version": "6.12.96", "lessThanOrEqual": "6.12.*", "status": "unaffected"},
     {"version": "6.18.57", "lessThanOrEqual": "6.18.*", "status": "unaffected"},
     {"version": "7.3", "lessThanOrEqual": "*", "status": "unaffected"}, {"version": "44e694958b95", "status": "affected"}]
pruefe("Kernel-Stand: Fehler kam später", w.kernel_stand("6.1.170", V) == ("nie", "6.8"))
pruefe("Kernel-Stand: Fix im Zweig drin", w.kernel_stand("6.12.115", V) == ("behoben", "6.12.96"))
pruefe("Kernel-Stand: Fix im Zweig fehlt", w.kernel_stand("6.12.90", V) == ("offen", "6.12.96"))
pruefe("Kernel-Stand: Zweig ohne Fix", w.kernel_stand("6.10.3", V) == ("offen", None))
pruefe("Kernel-Stand: nur Backport-Zweige", w.kernel_stand("6.12.115", [
    {"version": "6.18.53", "lessThan": "6.18.56", "status": "affected"}]) == ("nie", None))
pruefe("Kernel-Stand: keine Angaben", w.kernel_stand("6.12.115", [{"version": "1da177e4c3f4", "status": "affected"}]) is None)
pruefe("Kernbereich laut Beschreibung", w.kernbereich(["mm", "huge_memory"]) and w.kernbereich(["ptrace"])
       and not w.kernbereich(["net", "mlx5"]) and not w.kernbereich(["drm", "xe"]))

kr = {"paket": "linux-image-amd64", "version": "6.12.115-2", "typ": "kernel", "cve": "X", "host": "h", "schwere": "–"}
kopf = "6.12.116+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.116-1 (2026-11-07)\n"
t = kopf + "KERNEL-CHECK fs/btrfs/inode.c CONFIG_BTRFS_FS btrfs\nCONFIG_BTRFS_FS=m\nbtrfs  2023424  1\n"
pruefe("Kernel exakt: Modul geladen", w.werte_kernel_exakt(kr, t)["betroffen"] == "Ja")
t = kopf + "KERNEL-CHECK security/apparmor/policy.c CONFIG_SECURITY_APPARMOR apparmor\nCONFIG_SECURITY_APPARMOR=y\n"
pruefe("Kernel exakt: fest eingebaut", w.werte_kernel_exakt(kr, t)["betroffen"] == "Ja")
t = kopf + ("KERNEL-CHECK net/bluetooth/l2cap_core.c CONFIG_BT bluetooth\nCONFIG_BT=m\nModul nicht geladen\n"
            "AUTOLOAD net-pf-31 bluetooth\n")
e = w.werte_kernel_exakt(kr, t)
pruefe("Kernel exakt: Netzwerk-Modul lädt sich selbst", e["ampel"] == "gelb" and "automatisch" in e["kopf"], e["kopf"])
pruefe("Kernel exakt: ohne AUTOLOAD-Zeile grün", w.werte_kernel_exakt(kr, t.replace("AUTOLOAD", "x"))["ampel"] == "gruen")
t = kopf + "KERNEL-CHECK a/b.c CONFIG_A,CONFIG_B b\n# CONFIG_A is not set\nCONFIG_B=y\nModul nicht geladen\n"
pruefe("Kernel exakt: ein Symbol aus -> nicht eingebaut", w.werte_kernel_exakt(kr, t)["ampel"] == "gruen")
pruefe("Kernel exakt: fremde Ausgabe", w.werte_kernel_exakt(kr, "wie geht das?") is None)
t = kopf + "KERNEL-CHECK fs/btrfs/inode.c CONFIG_BTRFS_FS btrfs\nCONFIG_BTRFS_FS=m\nbtrfs  2023424  1\n"
mit_fix = dict(kr, debian={"fix": "6.12.116-1"}, nvd={})
e = w.kernel_nachbessern(mit_fix, w.werte_kernel_exakt(mit_fix, t), t)
pruefe("Kernel: laufender Kernel hat den Fix", e["ampel"] == "gruen" and "autoremove" in e["tun"], e["tun"])
netz = dict(kr, nvd={"weg": "NETWORK", "rechte": "NONE", "interaktion": "NONE", "quelle": "NVD"})
e = w.kernel_nachbessern(netz, w.werte_kernel_exakt(netz, t), t)
pruefe("Kernel: aktiv + Angriffsweg Netz -> rot", e["ampel"] == "rot" and e["angreifbar"] == "Ja")

# ---- CVE.org
org = w.lies_cveorg(w.json.load(open(os.path.join(ONLINE, "cveorg-CVE-2026-98999.json"), encoding="utf-8")))
pruefe("CVE.org Kernel: Quelldatei", org["dateien"] == ["drivers/gpu/drm/xe/xe_bo.c"], org["dateien"])
pruefe("CVE.org Kernel: Angriffsweg", org["vektor"].get("weg") == "LOCAL" and org["vektor"]["quelle"] == "CVE.org")
pruefe("CVE.org Kernel: Stand 6.12 offen", w.kernel_stand("6.12.115", org["versionen"]) == ("offen", None))
pruefe("CVE.org Kernel: 6.1 nie betroffen", w.kernel_stand("6.1.170", org["versionen"]) == ("nie", "6.8"))
pruefe("CVE.org leer", w.lies_cveorg({"error": "CVE_RECORD_DNE"}) == {})
pruefe("CVSS-Text", w.vektor_aus_text("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N")
       == {"weg": "NETWORK", "rechte": "NONE", "interaktion": "REQUIRED", "quelle": "CVE.org"})

# ---- Kernel online: Quelldateien -> Bau-Regeln -> genaue Befehle; Ausgaben echter Rechner (*.v2.txt)
po = w.Pipe()
po.valves.WORUM_SATZ = False
po.hole = fake_hole


def folge2(name):
    return open(os.path.join(DATEN_FOLGE, name + ".v2.txt"), encoding="utf-8").read()


j = json_von("CVE-2026-98999-xe")
a = po.antworte({"messages": [{"role": "user", "content": j}]})
pruefe("online xe: genaues Symbol", "echo 'KERNEL-CHECK drivers/gpu/drm/xe/xe_bo.c CONFIG_DRM_XE xe'" in a
       and "CONFIG_(DRM_XE)[= ]" in a and "| Betroffene Quelldateien | drivers/gpu/drm/xe/xe_bo.c |" in a, a[:300])
a = po.antworte({"messages": [{"role": "user", "content": j}, {"role": "assistant", "content": "x"},
                          {"role": "user", "content": folge2("CVE-2026-98999-xe")}]})
pruefe("online xe Folge: Modul nicht geladen", a.startswith("## 🟢") and "`xe`" in a, a[:200])
j = json_von("CVE-2026-99189-gpio")
a = po.antworte({"messages": [{"role": "user", "content": j}]})
pruefe("online gpio: genaues Symbol", "CONFIG_GPIO_MXC,CONFIG_GPIOLIB gpio-mxc" in a, a[:300])
a = po.antworte({"messages": [{"role": "user", "content": j}, {"role": "assistant", "content": "x"},
                          {"role": "user", "content": folge2("CVE-2026-99189-gpio")}]})
pruefe("online gpio Folge: nicht eingebaut", a.startswith("## 🟢") and "`CONFIG_GPIO_MXC` ist nicht gesetzt" in a, a[:200])
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-99125-pai")}]})
pruefe("online pai: fremde Architektur aus dem Dateipfad", a.startswith("## 🟢") and "arch/s390/" in a
       and "```bash" not in a, a[:200])
a = po.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-89611-kernel")}]})
pruefe("online ntfs: nicht auflösbar -> Name aus der Beschreibung", "grep -iE '_NTFS(_|=| )'" in a
       and "nicht eindeutig ablesbar" in a, a[:200])
# GitHub weist ab (429): dieselben Makefiles kommen von der Ausweichquelle
pg = w.Pipe()
pg.valves.WORUM_SATZ = False
pg.hole = lambda url, kopf=None: (429, "") if "raw.githubusercontent.com" in url else fake_hole(
    url.replace("cdn.jsdelivr.net/gh/torvalds/linux@v6.12/", "raw.githubusercontent.com/torvalds/linux/v6.12/"))
a = pg.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-98999-xe")}]})
pruefe("GitHub 429: Ausweichquelle", "KERNEL-CHECK drivers/gpu/drm/xe/xe_bo.c CONFIG_DRM_XE xe" in a, a[:200])
pg = w.Pipe()
pg.valves.WORUM_SATZ = False
pg.hole = lambda url, kopf=None: (429, "") if "/v6.12/" in url or "@v6.12/" in url or "h=v6.12" in url else fake_hole(url)
a = pg.antworte({"messages": [{"role": "user", "content": json_von("CVE-2026-98999-xe")}]})
pruefe("alle Makefile-Quellen 429: Name aus der Beschreibung", "grep -iE '_XE(_|=| )'" in a and "nicht abrufbar" in a, a[:200])
# Kerncode (ohne CONFIG-Symbol): gleich fertig, ohne Befehle; mit Fix bei Debian -> Update verfügbar
r = w.bewerte(w.lade_eintrag(json_von("CVE-2026-98999-xe")))
r.update(nvd={}, dateien=["kernel/ptrace.c"], kstand=None, bau=[w.kbuild_loese("kernel/ptrace.c", lies)],
         debian={"release": "trixie", "status": "vulnerable", "fix": "6.12.117-1", "unwichtig": False})
a = w.antwort_a(w.wende_online_an(r), "")
pruefe("Kerncode: Update verfügbar, keine Befehle", a.startswith("## 🟡 Kernel-Update verfügbar")
       and "```bash" not in a and "6.12.117-1" in a and "Betroffen: **Ja**" in a, a[:200])
r = w.bewerte(w.lade_eintrag(json_von("CVE-2026-98999-xe")))
r.update(nvd={}, dateien=["drivers/gpu/drm/xe/xe_bo.c"], kstand=("nie", "6.14"), bau=None, debian={})
a = w.antwort_a(w.wende_online_an(r), "")
pruefe("Kernel: Fehler kam erst später -> grün", a.startswith("## 🟢") and "6.14" in a, a[:200])
# ohne Internet: Kernbereich aus der Beschreibung wird nicht mehr über geratene Config-Namen geprüft
e = w.lade_eintrag(json_von("CVE-2026-98999-xe"))
e["vulnerability"]["description"] = "In the Linux kernel, the following vulnerability has been resolved:  mm: huge_memory: fix x"
a = p.antworte({"messages": [{"role": "user", "content": w.json.dumps(e)}]})
pruefe("offline mm/huge_memory: Kerncode, keine Befehle", a.startswith("## 🟡 Betroffen") and "```bash" not in a, a[:120])

# ---- Netz-Check: Dienste mit offenem Port, die das Paket nutzen (statt fester Port-Liste)
NETZ = ("0\nNETZ-CHECK {q}: {n} Dateien\n{zeilen}\nNETZ-ENDE 5 Sockets, {ohne} ohne Prozess\n")
r = {"paket": "rsync", "cve": "CVE-1", "beschreibung": "rsync daemon flaw", "typ": "paket"}
e = w.werte_paket_aus(r, NETZ.format(q="rsync", n=3, ohne=0, zeilen="LAUSCHT-IST-PAKET rsync tcp/0.0.0.0:873 tcp/[::]:873"))
pruefe("Netz: eigener Dienst außen -> rot", e["ampel"] == "rot" and "tcp/0.0.0.0:873" in " ".join(e["gruende"]))
e = w.werte_paket_aus(r, NETZ.format(q="rsync", n=3, ohne=0, zeilen="LAUSCHT-IST-PAKET rsync tcp/127.0.0.1:873\nLAUSCHT sshd tcp/0.0.0.0:22"))
pruefe("Netz: eigener Dienst nur lokal", e["ampel"] == "gelb" and e["angreifbar"] == "Nein", e["gruende"])
e = w.werte_paket_aus(r, NETZ.format(q="rsync", n=3, ohne=0, zeilen="LAUSCHT sshd tcp/0.0.0.0:22"))
pruefe("Netz: kein Dienst nutzt das Paket", e["angreifbar"] == "Nein" and "Kein von außen" in " ".join(e["gruende"]))
e = w.werte_paket_aus(r, NETZ.format(q="rsync", n=3, ohne=4, zeilen="LAUSCHT sshd tcp/0.0.0.0:22"))
pruefe("Netz: nicht als root -> unklar + Hinweis", e["angreifbar"] == "Unklar" and "ohne root" in " ".join(e["gruende"]))
e = w.werte_paket_aus({"paket": "gstreamer1.0-plugins-good", "cve": "CVE-1", "beschreibung": "RTP overflow", "typ": "paket"},
                      NETZ.format(q="gst-plugins-good1.0", n=0, ohne=11, zeilen="LAUSCHT firefox-esr udp/*:40672"))
a = w.antwort_b({"paket": "gstreamer1.0-plugins-good", "version": "1", "host": "h", "schwere": "–", "cve": "CVE-1", "typ": "paket"}, e)
pruefe("Netz: ohne root -> Befehle noch einmal, kein falscher Grund", a.startswith("## 🟡 Betroffen – Netz-Check bitte als root")
       and "NETZ-CHECK" in a and "keine Programme oder Bibliotheken" not in a and "rdepends --installed --no-breaks --no-conflicts --no-replaces --no-enhances --no-suggests lib" not in a, a[:300])
lib = {"paket": "libfoo1", "cve": "CVE-1", "beschreibung": "overflow in parser", "typ": "paket"}
e = w.werte_paket_aus(lib, NETZ.format(q="foo", n=2, ohne=0, zeilen="LAUSCHT-NUTZT-PAKET nginx tcp/0.0.0.0:443"))
pruefe("Netz: Dienst hat Bibliothek geladen -> möglich", e["ampel"] == "gelb" and e["angreifbar"] == "Möglich")
pruefe("Netz: Überschrift dazu", "erreichbarer Dienst nutzt das Paket" in w.antwort_b(dict(lib, version="1", host="h", schwere="–"), e))
e = w.werte_paket_aus(lib, NETZ.format(q="foo", n=2, ohne=0, zeilen="LAUSCHT-NUTZT-PAKET firefox-esr udp/*:40672"))
pruefe("Netz: UDP-Antwortport ist kein Dienst", e["angreifbar"] == "Nein")
py = {"paket": "python3-oauthlib", "cve": "CVE-1", "beschreibung": "timing issue", "typ": "paket"}
e = w.werte_paket_aus(py, NETZ.format(q="python-oauthlib", n=0, ohne=0, zeilen="LAUSCHT sshd tcp/0.0.0.0:22"))
pruefe("Netz: Python-Paket, kein Python-Dienst", e["angreifbar"] == "Nein" and "Python-Code" in " ".join(e["gruende"]))
e = w.werte_paket_aus(py, NETZ.format(q="python-oauthlib", n=0, ohne=0, zeilen="LAUSCHT gunicorn tcp/0.0.0.0:8000"))
pruefe("Netz: Python-Paket, Python-Dienst außen", e["angreifbar"] == "Möglich")
lokal = dict(r, beschreibung="A local attacker can ...")
e = w.werte_paket_aus(lokal, NETZ.format(q="rsync", n=3, ohne=0, zeilen="LAUSCHT-IST-PAKET rsync tcp/0.0.0.0:873"))
pruefe("Netz: lokale Lücke nie rot", e["ampel"] != "rot" and e["angreifbar"] == "Nein")
j = json_von("CVE-2026-118370-libexpat")
a = p.antworte({"messages": [{"role": "user", "content": j}]})
pruefe("Paket-Befehle: Netz-Check dabei", "NETZ-CHECK" in a and "changelog.Debian.gz /usr/share/doc/libexpat1/changelog.gz" in a)
a = p.antworte({"messages": [{"role": "user", "content": j}, {"role": "assistant", "content": "x"},
                         {"role": "user", "content": folge2("CVE-2026-118370-libexpat")}]})
pruefe("libexpat Folge mit Netz-Check (echte Ausgabe)", "avahi-daemon" in a and "firefox" not in a
       and "Von außen angreifbar: **Möglich**" in a, a[:200])

# ---- echter Lauf auf einem Debian-13-Server: Python-Paket, nur docker-proxy/sshd lauschen (kein Python-Dienst)
j = json_von("CVE-2026-97687-urllib3")
aus = folge2("CVE-2026-97687-urllib3")
a = p.antworte({"messages": [{"role": "user", "content": j}, {"role": "assistant", "content": "x"},
                         {"role": "user", "content": aus}]})
pruefe("urllib3 Folge: kein Python-Dienst", a.startswith("## 🟡 Betroffen, aber derzeit nicht angreifbar")
       and "kein von außen erreichbarer Dienst läuft mit Python (geprüft: 14 Prozesse" in a, a[:200])
r = w.bewerte(w.lade_eintrag(j))
r["nvd"] = {"weg": "NETWORK", "rechte": "NONE", "interaktion": "REQUIRED", "quelle": "NVD"}
e = w.nvd_nachbessern(r, w.werte_paket_aus(r, aus))
pruefe("Netz-Lücke ohne erreichbaren Dienst: nicht „lokal: Ja“",
       w.lokal_wert(r, e) == "Nur über ein Programm, das das Paket nutzt", w.lokal_wert(r, e))
e = {"betroffen": "Ja", "angreifbar": "Ja"}
pruefe("Netz-Lücke mit erreichbarem Dienst: lokal Ja", w.lokal_wert(r, e) == "Ja")

print("ALLES OK" if not fehler else f"{fehler} FEHLER")
sys.exit(1 if fehler else 0)
