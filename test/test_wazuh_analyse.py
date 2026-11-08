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

ERSTE = {  # Datei -> erwartete erste Zeile der ersten Antwort
    "CVE-2026-42217-openexr": "🔴", "CVE-2026-53791-rsync": "🟡", "CVE-2026-85977-libtirpc": "🟡",
    "CVE-2026-86140-libxml2": "🟡", "CVE-2026-89611-kernel": "🟡", "CVE-2026-91964-libwinpr": "🟡",
    "CVE-2026-97689-urllib3": "🟡", "CVE-2026-97876-grub": "🟡", "CVE-2026-98999-xe": "🟡",
    "CVE-2026-99125-pai": "🟢", "CVE-2026-99189-gpio": "🟡", "CVE-2019-12067-qemu": "🟡",
    "CVE-2026-118370-libexpat": "🟡",
}
FOLGE = {  # Datei -> erwarteter Text in der Überschrift der Folgeantwort
    "CVE-2026-53791-rsync": "nicht angreifbar", "CVE-2026-85977-libtirpc": "nicht angreifbar",
    "CVE-2026-86140-libxml2": "Risiko hängt", "CVE-2026-97689-urllib3": "nicht angreifbar",
    "CVE-2026-97876-grub": "nicht angreifbar", "CVE-2026-98999-xe": "Kein Problem",
    "CVE-2026-99125-pai": "Kein Problem", "CVE-2019-12067-qemu": "Debian-Tracker",
    "CVE-2026-118370-libexpat": "Risiko hängt",
}

fehler = 0


def pruefe(name, ok, info=""):
    global fehler
    fehler += 0 if ok else 1
    print(("OK   " if ok else "FEHL ") + name + (f"  -> {info}" if info else ""))


p = w.Pipe()
p.valves.WORUM_SATZ = False
for name, erwartet in ERSTE.items():
    j = open(os.path.join(BEISPIELE, "json", name + ".json"), encoding="utf-8").read()
    kopf = p.pipe({"messages": [{"role": "user", "content": j}]}).splitlines()[0]
    pruefe(f"erste  {name}", erwartet in kopf, kopf)
    if name in FOLGE:
        aus = open(os.path.join(BEISPIELE, "ausgaben", name + ".txt"), encoding="utf-8").read()
        kopf = p.pipe({"messages": [{"role": "user", "content": j}, {"role": "assistant", "content": "x"},
                                    {"role": "user", "content": aus}]}).splitlines()[0]
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

print("ALLES OK" if not fehler else f"{fehler} FEHLER")
sys.exit(1 if fehler else 0)
