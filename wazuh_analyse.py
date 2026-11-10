"""
title: Wazuh-Analyse
author: Elwin Ehlers
author_url: https://github.com/ElwinEhlers
credits: Entwickelt mit Claude (Anthropic)
description: Bewertet Wazuh-Schwachstellen-Einträge (wazuh-states-vulnerabilities) auf Debian mit festen Regeln und öffentlichen Daten (Debian-Tracker, NVD, CVE.org, Bau-Regeln des Kernels) und wertet die Ausgaben der Prüfbefehle aus. Das Sprachmodell schreibt nur den Satz "Worum geht's" (optional).
version: 2.5
license: MIT
"""

# Einrichtung: Open WebUI -> Admin-Bereich -> Funktionen -> "+" -> diesen Code einfügen -> speichern -> aktivieren.
# Danach erscheint "Wazuh-Analyse" in der Modellauswahl. Einstellungen (Zahnrad bei der Funktion): LLM-Adresse usw.
#
# Ablauf im Chat:
#   1. Wazuh-JSON einfügen  -> Ampel, Begründung, Prüfbefehle
#   2. Ausgabe der Prüfbefehle einfügen -> Endergebnis (betroffen / angreifbar / was tun)
#
# Grundsatz: Entschieden wird nach Daten, nicht nach Stichwörtern für einzelne Meldungen.
#   Pakete: Debian-Tracker (Fix-Stand), CVSS von NVD/CVE.org (Angriffsweg), auf dem Rechner der Netz-Check
#           (welcher Dienst mit offenem Port nutzt das Paket).
#   Kernel: betroffene Quelldateien und Versionen von kernel.org (über CVE.org), Makefiles des Kernels
#           (Datei -> CONFIG-Symbol -> Modul), auf dem Rechner genau dieses Symbol und dieses Modul.
#   Ohne Internet gelten die Regeln aus der Beschreibung; Grün gibt es dann nur mit Beleg.

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


VER = r"v?(\d+(?:\.\d+)+(?:_\d+)?[a-z]?\d*)"
# weitere Versionen einer Aufzählung; nicht, wenn danach ein neuer Bereich beginnt ("…, 3.3.0 to before 3.3.11")
LISTE = (r"((?:\s*,\s*(?:and\s+|or\s+)?|\s+(?:and|or)\s+)" + VER +
         r"(?!\.?\w)(?!\s*(?:to|until|till|through|before|prior|up)\b)(?!\s+-\s))*")


def bereiche_aus_beschreibung(text):
    """Liste von (untere, obere, art) mit art 'lt' (vor) oder 'le' (bis einschließlich).
    Mehrere Einträge mit derselben unteren Grenze sind Fix-Versionen verschiedener Zweige."""
    t = " " + text.lower() + " "
    bereiche = []

    def weg(m):
        return " " * (m.end() - m.start())

    def dazu(u, o, art):
        if u and vergleiche(u, o) > 0:  # „von 7.8 bis 1.1“: falsch gelesen, verwerfen
            return
        if (u, o, art) not in bereiche:
            bereiche.append((u, o, art))

    # "3.0.0 to before 3.2.9" / "from 1.0.0 until 1.10.6 and 2.14.3" (Fix je Zweig)
    muster = (rf"{VER}\s*(?:(?:to|until|up to)\s*(?:before|prior to|but not including|excluding)|"
              rf"until|till|up until)\s*{VER}{LISTE}")
    for m in re.finditer(muster, t):
        for o in re.findall(VER, m.group(0))[1:]:
            dazu(m.group(1), o, "lt")
    t = re.sub(muster, weg, t)
    # "6.0 before 6.0.3, 5.2 before 5.2.12, and 4.2 before 4.2.29"
    muster = rf"{VER}\s+(?:before|prior to)\s+{VER}{LISTE}"
    for m in re.finditer(muster, t):
        for o in re.findall(VER, m.group(0))[1:]:
            dazu(m.group(1), o, "lt")
    t = re.sub(muster, weg, t)
    # "9.18.0 through 9.18.27" / "1.2 to 1.5" / "7.0.0 - 7.0.8"
    muster = rf"{VER}(?:\s*(?:through|to|up to and including|up to)\s*|\s+-\s+){VER}"
    for m in re.finditer(muster, t):
        dazu(m.group(1), m.group(2), "le")
    t = re.sub(muster, weg, t)
    # "before 3.2.9, 3.3.11, and 3.4.11"
    for wort, art in ((r"(?:before|prior to|earlier than|older than|<)", "lt"),
                      (r"(?:through|up to and including|up to|<=)", "le")):
        muster = rf"{wort}\s*(?:versions?\s*)?{VER}{LISTE}"
        for m in re.finditer(muster, t):
            for v in re.findall(VER, m.group(0)):
                dazu(None, v, art)
        t = re.sub(muster, weg, t)
    # "1.36.37 and below" / "2.4 or earlier"
    muster = rf"{VER}\s+(?:and|or)\s+(?:below|earlier|prior|older|lower)\b"
    for m in re.finditer(muster, t):
        dazu(None, m.group(1), "le")
    t = re.sub(muster, weg, t)
    # nur wenn sonst nichts gefunden: "fixed in version 2.8.0" / "patched in 4.0.14, 5.0.10 and 6.10"
    if not bereiche:
        for m in re.finditer(rf"(?:fixed|patched|resolved|addressed) in (?:versions?\s*)?{VER}{LISTE}", t):
            for v in re.findall(VER, m.group(0)):
                dazu(None, v, "lt")
    return bereiche


def text_bereich(u, o, art):
    if u:
        return f"ab {u}, vor {o}" if art == "lt" else f"{u} bis einschließlich {o}"
    return f"vor {o}" if art == "lt" else f"bis einschließlich {o}"


def pruefe_version(installiert, bereiche):
    """-> (ergebnis 'ja'|'nein'|'unklar'|'keine', passender Bereich oder None, Fix-Version oder None)"""
    if not bereiche:
        return "keine", None, None

    def darunter(b):
        c = vergleiche(installiert, b[1])
        return c < 0 if b[2] == "lt" else c <= 0

    def ja(b):
        return "ja", b, (b[1] if b[2] == "lt" else None)

    zweig = vteile(installiert)[:2]
    gruppen = {}  # untere Grenze -> Bereiche; mehrere = Fix-Versionen verschiedener Zweige
    for b in bereiche:
        gruppen.setdefault(b[0], []).append(b)
    unklar, nein = False, None
    for unten, gruppe in gruppen.items():
        if unten and vergleiche(installiert, unten) < 0:
            nein = nein or gruppe[0]
            continue
        gleich = [b for b in gruppe if vteile(b[1])[:2] == zweig]
        kandidaten = gleich or [b for b in gruppe if vteile(b[1])[:1] == zweig[:1]] or gruppe
        if gleich or len(kandidaten) == 1:
            treffer = [b for b in kandidaten if darunter(b)]
            if treffer:
                return ja(max(treffer, key=lambda b: vteile(b[1])))
            nein = nein or kandidaten[0]
            continue
        kleinste = min(kandidaten, key=lambda b: vteile(b[1]))
        groesste = max(kandidaten, key=lambda b: vteile(b[1]))
        if darunter(kleinste):
            return ja(kleinste)
        if darunter(groesste):  # zwischen zwei Fix-Versionen, eigener Zweig nicht genannt
            unklar = True
        else:
            nein = nein or groesste
    if unklar:
        return "unklar", None, None
    return "nein", nein or bereiche[0], None


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
    return (f"uname -rv\ngrep -iE '{config_muster(treiber)}' /boot/config-$(uname -r)\n"
            f"lsmod | grep -iE '{modul_muster(treiber)}' || echo 'Modul nicht geladen'")


# Namen aus der Beschreibung, die keinen einzelnen Treiber meinen, sondern Kerncode, der in jedem Kernel steckt.
# Nur für die Bewertung ohne Internet; mit Internet entscheiden die Quelldateien und die Bau-Regeln des Kernels.
KERN_ZUERST = {"mm", "sched", "kernel", "bpf", "tracing", "perf", "io_uring", "locking", "rcu", "cgroup", "x86",
               "block", "ipc", "security", "lib", "init"}
KERN_BEREICHE = KERN_ZUERST | {
    "net", "fs", "vfs", "futex", "time", "timers", "irq", "genirq", "signal", "exec", "proc", "sysfs", "kernfs",
    "namespace", "pid", "fork", "module", "workqueue", "tcp", "udp", "ipv4", "ipv6", "inet", "ptrace", "slab",
    "memcg", "hugetlb", "printk", "epoll", "pipe", "iomap", "writeback", "dcache", "audit", "seccomp", "lsm", "keys",
    "random", "tty", "acpi", "acpica", "pci", "core", "skbuff", "sock", "socket", "xdp", "xsk", "netlink", "neighbour",
    "ring-buffer", "ftrace", "kprobes", "uprobes", "smp", "cpu", "entry", "ksm", "mmap", "vmalloc", "swap", "shmem",
    "userfaultfd", "binfmt_elf", "coredump", "fsnotify", "inotify", "fanotify", "eventfd", "eventpoll", "super",
    "kvm", "iommu", "cpufreq", "cpuidle", "pm", "clk", "dma-buf", "driver core", "devres", "firmware_loader",
}
ALLGEMEIN = {"core", "client", "server", "common", "display", "host", "main", "generic", "lib", "util", "utils"}


def kernbereich(teile):
    """Kerncode laut Namen in der Beschreibung? ['mm', 'huge_memory'] -> True, ['net', 'mlx5'] -> False"""
    t = [x.lower() for x in teile]
    return bool(t) and (t[0] in KERN_ZUERST or t[-1] in KERN_BEREICHE)


# Quelldateien, die nicht zum laufenden Kernel gehören (Beispiele, Hilfsprogramme, Dokumentation)
KEIN_KERNEL = ("Documentation/", "tools/", "samples/", "scripts/")
# Programme aus tools/, die Debian in eigene Pakete packt: (Pfad, Programm, Debian-Paket)
KERNEL_PROGRAMME = [("tools/perf/", "perf", "linux-perf"), ("tools/bpf/bpftool/", "bpftool", "bpftool"),
                    ("tools/usb/usbip/", "usbip", "usbip"), ("tools/power/cpupower/", "cpupower", "linux-cpupower"),
                    ("tools/power/x86/turbostat/", "turbostat", "linux-cpupower"),
                    ("tools/power/x86/x86_energy_perf_policy/", "x86_energy_perf_policy", "linux-cpupower"),
                    ("tools/hv/", "Hyper-V-Dienste", "hyperv-daemons")]


def kernel_programm(dateien):
    """Erstes Programm aus tools/, das Debian als eigenes Paket liefert -> (Programm, Paket) oder None."""
    return next(((prog, paket) for d in dateien for pfad, prog, paket in KERNEL_PROGRAMME if d.startswith(pfad)), None)
KBUILD_URL = "https://raw.githubusercontent.com/torvalds/linux/v{zweig}/{pfad}"
# Ausweichquellen mit denselben Dateien, falls GitHub abweist (Code 429 bei zu vielen Anfragen)
KBUILD_ERSATZ = ["https://cdn.jsdelivr.net/gh/torvalds/linux@v{zweig}/{pfad}",
                 "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/{pfad}?h=v{zweig}"]
KB_OBJ = r"obj-(?:y|m|\$\((CONFIG_\w+)\)|\$\(subst m,y,\$\((CONFIG_\w+)\)\))"
KB_KEIN_MODUL = {"obj", "lib", "ccflags", "subdir-ccflags", "asflags", "ldflags", "extra", "hostprogs", "always",
                 "targets", "clean", "CFLAGS", "AFLAGS", "header", "userprogs", "subdir"}


def kbuild_zeilen(text):
    """Zuweisungen eines Kernel-Makefiles: [(Variable, [Werte])], z. B. ('obj-$(CONFIG_DRM_XE)', ['xe.o'])"""
    aus = []
    for z in re.sub(r"\\\n", " ", text).splitlines():
        m = re.match(r"\s*([\w$(),. -]+?)\s*(?:\+=|:=|=)\s*(.*)", z.split("#")[0])
        if m:
            aus.append((m.group(1).strip(), [re.sub(r"\.o\)$", ".o", w) for w in m.group(2).split()]))
    return aus


def kbuild_objekt(zeilen, ziel, gesehen):
    """Objektdatei im Makefile suchen -> ([CONFIG-Symbole], Modulname) oder None.
    'xe-y += xe_bo.o' und 'obj-$(CONFIG_DRM_XE) += xe.o' ergeben (['CONFIG_DRM_XE'], 'xe')."""
    if ziel in gesehen:
        return None
    gesehen.add(ziel)
    for var, werte in zeilen:
        if ziel not in werte:
            continue
        m = re.fullmatch(KB_OBJ, var)
        if m:
            sym = m.group(1) or m.group(2)
            return ([sym] if sym else []), ziel[:-2].split("/")[-1]
        m = re.fullmatch(r"([\w-]+?)-(?:y|m|objs|\$\((CONFIG_\w+)\))", var)
        if m and m.group(1) not in KB_KEIN_MODUL:
            oben = kbuild_objekt(zeilen, m.group(1) + ".o", gesehen)
            if oben:
                return ([m.group(2)] if m.group(2) else []) + oben[0], oben[1]
    return None


def kbuild_verzeichnis(verzeichnis, lies):
    """CONFIG-Symbole, unter denen ein Verzeichnis überhaupt gebaut wird -> Liste oder None (nicht ablesbar)."""
    symbole, teile, kind = [], verzeichnis.split("/"), ""
    for i in range(len(teile) - 1, -1, -1):
        kind = teile[i] + "/" + kind  # ohne Makefile dazwischen: "amd/amdgpu/"
        text = lies("/".join(teile[:i]))
        if text is None:
            continue
        gefunden = False
        for var, werte in kbuild_zeilen(text):
            m = re.fullmatch(KB_OBJ, var)
            if m and kind in werte:
                sym = m.group(1) or m.group(2)
                symbole += [sym] if sym else []
                gefunden = True
                break
        if not gefunden and i > 0 and kind not in text:  # oberste Ebene: nicht genannt = wird immer gebaut
            return None
        kind = ""
    return symbole


def kbuild_loese(datei, lies):
    """Quelldatei -> {'datei', 'symbole', 'modul'} oder None, wenn die Makefiles es nicht eindeutig hergeben.
    lies(verzeichnis) liefert den Text von Makefile/Kbuild oder None. symbole leer = wird immer fest eingebaut."""
    if not datei.endswith((".c", ".S", ".rs")):
        return None
    teile = datei.split("/")
    for i in range(len(teile) - 1, 0, -1):
        verzeichnis = "/".join(teile[:i])
        text = lies(verzeichnis)
        if not text:
            continue
        zeilen = kbuild_zeilen(text)
        ziel = re.sub(r"\.(c|S|rs)$", ".o", "/".join(teile[i:]))
        gefunden = kbuild_objekt(zeilen, ziel, set())
        if not gefunden and "/" in ziel:  # $(addprefix libxfs/, xfs_attr_leaf.o …)
            gefunden = kbuild_objekt(zeilen, ziel.split("/")[-1], set())
        if not gefunden:
            continue
        tore = kbuild_verzeichnis(verzeichnis, lies)
        if tore is None:
            return None
        return {"datei": datei, "symbole": list(dict.fromkeys(gefunden[0] + tore)), "modul": gefunden[1]}
    return None


def kbuild_pfade(dateien):
    """Makefiles, die für diese Quelldateien gebraucht werden."""
    pfade = {"Kbuild"}
    for datei in dateien:
        teile = datei.split("/")
        for i in range(1, len(teile)):
            pfade.add("/".join(teile[:i]) + "/Makefile")
            if i <= 2:
                pfade.add("/".join(teile[:i]) + "/Kbuild")
    return sorted(pfade)


def kernel_quellen(dateien):
    """Quelldateien, die über 'betroffen' entscheiden: .c vor Headern, ohne Doku und Hilfsprogramme."""
    echte = [d for d in dateien if not d.startswith(KEIN_KERNEL)]
    return [d for d in echte if d.endswith((".c", ".S", ".rs"))] or echte


def kernel_stand(installiert, versionen):
    """Stand laut kernel.org (Angaben im CVE-Datensatz). installiert z. B. '6.12.115'.
    -> ('nie', ab_version) | ('behoben', fix) | ('offen', Fix im eigenen Zweig oder None) | None (keine Angaben)"""
    def zahl(v):
        return re.fullmatch(r"\d+(\.\d+)*", str(v or "")) is not None

    def zweig_von(v):
        return ".".join(str(v).split(".")[:2])

    zweig = zweig_von(installiert)
    ab, fixe, bereiche, haupt = [], {}, [], None
    for v in versionen or []:
        ver, status = str(v.get("version", "")), v.get("status")
        lt, le = v.get("lessThan"), v.get("lessThanOrEqual")
        if not zahl(ver) or ver == "0":
            continue
        if status == "affected" and not lt and not le:
            ab.append(ver)
        elif status == "affected" and zahl(lt):
            bereiche.append((ver, str(lt)))
        elif status == "unaffected" and le == "*":
            haupt = ver
        elif status == "unaffected" and str(le).endswith(".*"):
            fixe[str(le)[:-2]] = ver
    if not (ab or fixe or bereiche or haupt):
        return None
    if bereiche and not ab and zweig not in [zweig_von(x) for b in bereiche for x in b]:
        return "nie", None  # Fehler steckt nur in den genannten Zweigen (über Backports hineingekommen)
    for unten, oben in bereiche:  # Fehler kam über einen Backport in diesen Zweig
        if zweig in (zweig_von(unten), zweig_von(oben)):
            if vergleiche(installiert, unten) < 0:
                return "nie", unten
            return ("offen", oben) if vergleiche(installiert, oben) < 0 else ("behoben", oben)
    if ab and vergleiche(installiert, min(ab, key=vteile)) < 0:
        return "nie", min(ab, key=vteile)
    if zweig in fixe:
        return ("behoben", fixe[zweig]) if vergleiche(installiert, fixe[zweig]) >= 0 else ("offen", fixe[zweig])
    if haupt and vergleiche(installiert, haupt) >= 0:
        return "behoben", haupt
    return "offen", None


def kernel_befehle_exakt(bau):
    """Prüfbefehle für aufgelöste Quelldateien. Die echo-Zeilen machen die Ausgabe selbsterklärend."""
    zeilen, symbole, module = ["uname -rv"], [], []
    for b in bau:
        if not b["symbole"]:
            continue
        zeilen.append(f"echo 'KERNEL-CHECK {b['datei']} {','.join(b['symbole'])} {b['modul'] or '-'}'")
        symbole += [x[len("CONFIG_"):] for x in b["symbole"] if x[len("CONFIG_"):] not in symbole]
        if b["modul"] and b["modul"].replace("-", "_") not in module:
            module.append(b["modul"].replace("-", "_"))
    zeilen.append(f"grep -E '^(# )?CONFIG_({'|'.join(symbole)})[= ]' /boot/config-$(uname -r)")
    if module:
        zeilen.append(f"lsmod | grep -E '^({'|'.join(module)}) ' || echo 'Modul nicht geladen'")
        # Netzwerk-Module (Alias net-pf-…) lädt der Kernel von selbst, sobald ein Programm sie anspricht
        zeilen.append(f"grep -E '^alias net-pf-[^ ]+ ({'|'.join(module)})$' /lib/modules/$(uname -r)/modules.alias "
                      "| head -n3 | sed 's/^alias/AUTOLOAD/'")
    return "\n".join(zeilen)


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


def netz_befehl(name):
    """Welche Prozesse mit offenem Netzwerk-Port gehören zum Paket (IST) oder haben es geladen (NUTZT)?
    Verglichen werden die Programme und Bibliotheken aller Pakete desselben Quellpakets mit /proc/PID/maps."""
    return ("Q=$(dpkg-query -W -f='${source:Package}\\n' " + name + " 2>/dev/null | head -n1); "
            "D=$(dpkg-query -W -f='${binary:Package} ${source:Package}\\n' | awk -v q=\"$Q\" '$2==q{print $1}' | "
            "xargs -r dpkg -L 2>/dev/null | grep -E '\\.so[.0-9]*$|/s?bin/|/libexec/' | sed 's|.*/||' | sort -u); "
            "echo \"NETZ-CHECK $Q: $(echo \"$D\" | grep -c .) Dateien\"; "
            "ss -Hltnup | grep -o 'pid=[0-9]*' | sort -u | cut -d= -f2 | while read p; do n=LAUSCHT; "
            "[ -n \"$D\" ] && awk '{print $6}' /proc/$p/maps 2>/dev/null | sed 's|.*/||' | grep -qxF \"$D\" "
            "&& n=LAUSCHT-NUTZT-PAKET; "
            "[ -n \"$D\" ] && readlink /proc/$p/exe | sed 's|.*/||; s| (deleted)||' | grep -qxF \"$D\" "
            "&& n=LAUSCHT-IST-PAKET; "
            "echo \"$n $(cat /proc/$p/comm) $(ss -Hltnup | grep \"pid=$p,\" | awk '{print $1\"/\"$5}' | sort -u | "
            "tr '\\n' ' ')\"; done; "
            "echo \"NETZ-ENDE $(ss -Hltnu | wc -l) Sockets, $(ss -Hltnup | grep -vc pid=) ohne Prozess\"")


def paket_befehle(name, cve):
    doc = f"/usr/share/doc/{name}/changelog"
    return (f"zcat {doc}.Debian.gz {doc}.gz 2>/dev/null | grep -c {cve}\n"
            f"apt-cache rdepends --installed --no-breaks --no-conflicts --no-replaces --no-enhances --no-suggests {name}\n"
            + netz_befehl(name))


def lokale_adresse(adresse):
    """'tcp/127.0.0.1:631' -> True (nur von diesem Rechner aus erreichbar)"""
    a = adresse.split("/", 1)[-1].rsplit(":", 1)[0]
    return a.startswith("127.") or a.split("%")[0] in ("[::1]", "::1", "localhost")


def kurzlebig(adresse):
    """UDP-Port aus dem Bereich für ausgehende Verbindungen: Antwort-Port eines Programms, kein Dienst."""
    port = adresse.rsplit(":", 1)[-1]
    return adresse.startswith("udp/") and port.isdigit() and int(port) >= 32768


def lies_netz(text):
    """Ausgabe von netz_befehl() -> {'quelle', 'dateien', 'lauscher': [(art, prozess, [adressen])], 'ohne_prozess'}
    oder None. art: 'IST' (Programm aus dem Paket), 'NUTZT' (hat das Paket geladen), '' (unbeteiligt)."""
    m = re.search(r"^NETZ-CHECK ?([^:\n]*): (\d+) Dateien", text, re.M)
    if not m:
        return None
    lauscher = []
    for art, prozess, adressen in re.findall(r"^LAUSCHT(?:-(IST|NUTZT)-PAKET)? (\S+)[ \t]*([^\n]*)", text, re.M):
        lauscher.append((art, prozess, adressen.split()))
    ende = re.search(r"^NETZ-ENDE (\d+) Sockets, (\d+) ohne Prozess", text, re.M)
    return {"quelle": m.group(1).strip(), "dateien": int(m.group(2)), "lauscher": lauscher,
            "ohne_prozess": int(ende.group(2)) if ende else 0}


# Pakete ohne eigene Programme oder Bibliotheken (reiner Python-, Perl-, Ruby-, Node- oder PHP-Code):
# erreichbar nur über einen Dienst, der in dieser Sprache läuft
SPRACHEN = [(r"^python3?-", r"python|gunicorn|uwsgi|celery", "Python"), (r"^lib.*-perl$", r"perl|starman", "Perl"),
            (r"^ruby-", r"ruby|puma|unicorn|passenger", "Ruby"), (r"^node-", r"node|npm", "Node.js"),
            (r"^php", r"php|apache2", "PHP"), (r"-java$|^lib.*-java$", r"java", "Java")]


def sprache_von(paket):
    return next(((prozess, name) for muster, prozess, name in SPRACHEN if re.search(muster, paket)), (None, None))


def netz_lage(netz, paket):
    """-> ('dienst'|'nutzt'|'frei'|'unklar', von außen erreichbare Prozesse [(prozess, adresse)], Satz)"""
    def offen(adressen, alle):
        return [a for a in adressen if not lokale_adresse(a) and (alle or not kurzlebig(a))]

    def aussen(art):
        return [(p, offen(adr, art == "IST")[0]) for x, p, adr in netz["lauscher"]
                if x == art and offen(adr, art == "IST")]

    def liste(prozesse):
        return ", ".join(f"`{p}` ({a})" for p, a in prozesse[:5])

    zahl = len(netz["lauscher"])
    if netz["ohne_prozess"]:
        hinweis = (f" Achtung: Bei {netz['ohne_prozess']} offenen Ports war der Prozess nicht sichtbar – den Befehl "
                   "als root ausführen, sonst ist das Ergebnis unvollständig.")
    else:
        hinweis = ""
    dienst, nutzt = aussen("IST"), aussen("NUTZT")
    if dienst:
        return "dienst", dienst, f"Ein Programm aus diesem Paket lauscht von außen erreichbar: {liste(dienst)}." + hinweis
    if nutzt:
        return "nutzt", nutzt, ("Von außen erreichbare Dienste haben das Paket geladen: " + liste(nutzt) + ". Ob sie "
                                "die betroffene Funktion mit fremden Daten aufrufen, lässt sich nicht automatisch sagen."
                                + hinweis)
    if netz["dateien"] and not netz["ohne_prozess"]:
        innen = [p for x, p, adr in netz["lauscher"] if x]
        return "frei", [], (f"Kein von außen erreichbarer Dienst nutzt das Paket (geprüft: {zahl} Prozesse mit offenem "
                            "Netzwerk-Port" + (f"; nur lokal lauscht {', '.join(f'`{p}`' for p in innen[:3])}" if innen
                                               else "") + "). Über offene Ports ist die Lücke damit nicht erreichbar.")
    prozess, sprache = sprache_von(paket)
    if not netz["dateien"] and prozess and not netz["ohne_prozess"]:
        laeufer = [(p, offen(adr, False)[0]) for _, p, adr in netz["lauscher"]
                   if re.search(prozess, p) and offen(adr, False)]
        if laeufer:
            return "nutzt", laeufer, (f"Das Paket ist {sprache}-Code. Von außen erreichbar laufen diese "
                                      f"{sprache}-Dienste: {liste(laeufer)}. Ob sie das Paket verwenden, lässt sich "
                                      "nicht automatisch sagen.")
        return "frei", [], (f"Das Paket ist {sprache}-Code, und kein von außen erreichbarer Dienst läuft mit {sprache} "
                            f"(geprüft: {zahl} Prozesse mit offenem Netzwerk-Port). Über offene Ports ist die Lücke "
                            "damit nicht erreichbar.")
    if netz["ohne_prozess"]:  # ohne root sieht der Befehl fremde Prozesse nicht: keine Aussage möglich
        return "root", [], (f"Der Netz-Check lief ohne root-Rechte: Bei {netz['ohne_prozess']} offenen Ports war der "
                            "Prozess nicht sichtbar. Ob ein von außen erreichbarer Dienst das Paket nutzt, ist damit "
                            "noch offen.")
    return "unklar", [], ("Ob ein Dienst mit offenem Netzwerk-Port das Paket nutzt, ließ sich nicht feststellen "
                          "(das Paket enthält keine Programme oder Bibliotheken, die sich in laufenden Prozessen "
                          "wiederfinden lassen)." + hinweis)


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
    plattform = str(os_.get("platform", "")).lower()
    if plattform == "debian":
        r["release"] = DEBIAN_NAMEN.get(str(os_.get("version", "")).split(".")[0])
    else:  # ältere Einträge ohne host.os: Debian-Version aus dem Zusatz "+deb13u1" ablesen
        m_deb = None if plattform else re.search(r"deb(\d+)", str(r["version"]))
        r["release"] = DEBIAN_NAMEN.get(m_deb.group(1)) if m_deb else None
    # Ubuntu ist ungetestet: kein Fix-Stand-Abgleich, kein kernel.org-Versionsvergleich, Backports wie bei Debian
    r["ubuntu"] = plattform == "ubuntu" or "ubuntu" in str(r["version"]).lower()
    if r["ubuntu"]:
        r["details"].append(("Fix-Stand", "Ubuntu wird nicht abgefragt (nur der Debian-Tracker) – Bewertung über "
                                          "die Prüfbefehle"))
    m_fix = re.fullmatch(r"Package less than (\S+)", str(r["bedingung"]).strip())
    r["fix_wazuh"] = m_fix.group(1) if m_fix else None
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
        namen = [t for t in teile if t.lower() not in ALLGEMEIN] or teile  # "smb: client:" -> smb
        r["treiber"] = namen[-1] if namen else None
        fremd = [t.lower() for t in teile if t.lower() in ARCHITEKTUREN]
        r["tun_update"] = ("Kernel-Update einspielen, sobald Debian es liefert (`sudo apt update && sudo apt "
                           "full-upgrade`), danach neu starten.")
        if fremd and r["arch"] in X86:
            r["ampel"] = "gruen"
            r["gruende"].append(f"Die Lücke steckt im Kernel-Teil `{r['bereich']}`. Diesen Teil gibt es nur für "
                                f"{ARCHITEKTUREN[fremd[0]]}, dieser Rechner ist aber ein PC ({r['arch']}).")
        elif kernbereich(teile):
            r["ampel"], r["treiber"] = "gelb", None
            r["kopf"] = "🟡 Betroffen – Kernel-Update einspielen, sobald verfügbar"
            r["gruende"].append(f"Die Lücke steckt im Kernel-Bereich `{r['bereich']}`. Das ist Kerncode, der in jedem "
                                "Kernel fest eingebaut ist – einen Treiber, der fehlen könnte, gibt es hier nicht.")
            r["gruende"].append("Kernel-Lücken dieser Art lassen sich meist nur von jemandem ausnutzen, der schon auf "
                                "dem Rechner angemeldet ist.")
            r["tun"] = r["tun_update"]
            r["ergebnis"] = {"betroffen": "Ja", "angreifbar": "Unklar"}
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
    backport = "deb" in zusatz.lower() or "ubuntu" in zusatz.lower()
    distri = "Ubuntu" if "ubuntu" in zusatz.lower() else "Debian"
    bereiche = bereiche_aus_beschreibung(beschreibung)
    ver, bereich, fix = pruefe_version(rein, bereiche)
    regel = ", ".join(text_bereich(*b) for b in bereiche) if bereiche else "keine Grenze genannt"
    teile = namens_teile(name)
    komponente = "ja" if any(t in beschreibung.lower() for t in teile) else "unklar"

    if ver == "nein" and komponente == "ja":
        r["ampel"] = "gruen"
        r["gruende"].append(f"Betroffen sind Versionen {regel}. Installiert ist {rein} – das liegt außerhalb.")
    elif ver == "nein":  # Versionsangabe kann zu einem anderen Bestandteil gehören: kein Grün allein daraus
        r["ampel"] = "gelb"
        r["gruende"].append(f"Die Beschreibung nennt Versionen {regel}; installiert ist {rein}, das läge außerhalb. "
                            f"Sie nennt aber das Paket `{name}` nicht. Die Versionsangabe kann also zu einem anderen "
                            "Bestandteil gehören und reicht allein nicht für eine Entwarnung.")
    elif ver == "ja":
        r["gruende"].append(f"Betroffen sind Versionen {text_bereich(*bereich)}. Installiert ist {rein} – "
                            "das liegt im betroffenen Bereich.")
        if backport:
            r["ampel"] = "gelb"
            r["gruende"].append(f"Aber: Die Version trägt den {distri}-Zusatz `{zusatz}`. {distri} baut Sicherheits-Fixes "
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
                      "Programme das Paket nutzen. Der dritte (als root ausführen) zeigt, ob ein Dienst mit offenem "
                      "Netzwerk-Port das Paket nutzt: `LAUSCHT-IST-PAKET` = Dienst aus diesem Paket, "
                      "`LAUSCHT-NUTZT-PAKET` = Dienst hat das Paket geladen, nur `LAUSCHT` = unbeteiligt.")
        if r["fix_wazuh"] and dpkg_vergleich(r["version"], r["fix_wazuh"]) < 0:
            r["gruende"].append(f"Wazuh nennt als behobene Version `{r['fix_wazuh']}`; installiert ist die ältere "
                                f"`{r['version']}`. Ein Update sollte also bereitstehen (`sudo apt update && apt list "
                                f"--upgradable 2>/dev/null | grep '^{name}/'`).")
        if "tiocsti" in r["beschreibung"].lower():  # entscheidet allein die Kernel-Sperre
            r["gruende"].append("Die Lücke braucht den Terminal-Trick **TIOCSTI** (Zeichen in ein fremdes Terminal "
                                "schieben) und ist nur lokal ausnutzbar. Neuere Kernel sperren den Trick – der Befehl "
                                "unten zeigt, ob das hier so ist.")
            r["befehle"] = "sysctl dev.tty.legacy_tiocsti"
            r["lesen"] = ("**= 0** heißt: Der Kernel sperrt TIOCSTI, die Lücke ist nicht ausnutzbar. **= 1** oder "
                          "„unknown key“ heißt: ausnutzbar für jemanden, der schon angemeldet ist.")
    r["details"] += [("Bereinigte Version", rein), (f"{distri}-Zusatz", zusatz or "–"),
                     ("Regel aus der Beschreibung", regel), ("Fix-Version", fix or "–"),
                     ("Paket im Text genannt", "ja" if komponente == "ja" else "nein")]
    if r["fix_wazuh"]:
        r["details"].append(("Behoben laut Wazuh ab", r["fix_wazuh"]))
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
    if treffer:
        return {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein",
                "gruende": [f"Der Treiber `{r['treiber']}` ist in deinem Kernel nicht eingebaut (`{treffer[0]}`)."],
                "tun": "Nichts. Die Meldung kann in Wazuh ignoriert werden."}
    return {"ampel": "gelb", "betroffen": "Unklar (vermutlich nein)", "angreifbar": "Nein", "kopf": "🟡 Vermutlich "
            "nicht betroffen – nicht sicher belegt",
            "gruende": [f"Der Prüfbefehl fand in der Kernel-Config keine Zeile zu `{r['treiber']}`. Das heißt meist: "
                        "Der Treiber ist nicht eingebaut.",
                        "Sicher ist das aber nicht: Der Name stammt aus der Beschreibung und muss nicht der Name in "
                        "der Kernel-Config sein. Mit Internet-Zugang (Einstellung `ONLINE`) liest die Funktion die "
                        "betroffenen Quelldateien und prüft genau."],
            "tun": "Nichts Dringendes. " + (r.get("tun_update") or "Kernel-Updates wie gewohnt einspielen.")}


def werte_kernel_exakt(r, text):
    """Ausgabe von kernel_befehle_exakt(): je Quelldatei steht in der KERNEL-CHECK-Zeile, welche CONFIG-Symbole
    gesetzt sein müssen und wie das Modul heißt. Die Auswertung braucht deshalb keine Online-Daten."""
    pruefungen = list(dict.fromkeys(re.findall(r"KERNEL-CHECK (\S+) (CONFIG_[\w,]+) ([\w-]+)", text)))
    if not pruefungen:
        return None
    if re.search(r"/boot/config\S*: (No such file|Datei oder Verzeichnis nicht gefunden)", text):
        return {"ampel": "gelb", "betroffen": "Unklar", "angreifbar": "Unklar",
                "gruende": ["Die Kernel-Config (`/boot/config-…`) fehlt auf diesem Rechner, die Prüfung war nicht "
                            "möglich."], "tun": r.get("tun_update") or "Kernel-Updates wie gewohnt einspielen."}
    config = {}
    for sym, wert in re.findall(r"^\s*(?:# )?(CONFIG_\w+)(?:=(\S+)| is not set)", text, re.M):
        config[sym] = wert or "n"
    geladen = {z.split()[0] for z in text.splitlines() if re.match(r"\s*[\w-]+\s+\d+\s+\d+", z)}
    selbst = set(re.findall(r"^AUTOLOAD net-pf-\S+ (\S+)", text, re.M))
    aus, module, fest, laeuft, bedarf = [], [], [], [], []
    for datei, symbole, modul in pruefungen:
        werte = {sym: config.get(sym, "n") for sym in symbole.split(",")}
        fehlt = [sym for sym, w in werte.items() if w == "n"]
        if fehlt:
            aus.append((datei, fehlt[0]))
        elif "m" in werte.values():
            name = modul.replace("-", "_")
            (laeuft if name in geladen or modul == "-" else bedarf if name in selbst else module).append((datei, name))
        else:
            fest.append((datei, next(iter(werte))))
    if bedarf and not fest and not laeuft:
        namen = list(dict.fromkeys(n for _, n in bedarf))
        return {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Nein", "lokal": "Ja",
                "kopf": "🟡 Betroffen – Modul wird bei Bedarf automatisch geladen",
                "gruende": ["Der betroffene Teil ist ein Netzwerk-Modul und gerade nicht geladen: "
                            + ", ".join(f"`{n}`" for n in namen) + ".",
                            "Der Kernel lädt solche Module aber von selbst, sobald ein Programm den passenden "
                            "Netzwerk-Typ anspricht – das kann auch ein normal angemeldeter Benutzer auslösen."],
                "tun": (r.get("tun_update") or "Kernel-Update einspielen, sobald Debian es liefert.") + " Wird das "
                       "Modul nicht gebraucht, lässt es sich bis dahin sperren: " + " ".join(
                           f"`echo 'install {n} /bin/false' > /etc/modprobe.d/{n}-sperre.conf`" for n in namen[:2])}
    if not fest and not laeuft:
        gruende = []
        if aus:
            gruende.append("Der betroffene Kernel-Teil ist in deinem Kernel nicht eingebaut: "
                           + ", ".join(f"`{d}` (`{sym}` ist nicht gesetzt)" for d, sym in aus[:3]) + ".")
        if module:
            gruende.append("Der betroffene Teil ist nur als Modul vorhanden und gerade nicht geladen: "
                           + ", ".join(f"`{name}`" for name in dict.fromkeys(n for _, n in module)) + ". Solange "
                           "das Modul nicht geladen wird, ist die Lücke nicht erreichbar. Geladen würde es nur auf "
                           "passender Hardware bzw. wenn die Funktion genutzt wird.")
        return {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein", "gruende": gruende,
                "tun": ("Nichts sofort. Das nächste reguläre Kernel-Update schließt die Lücke ohnehin "
                        "(`sudo apt update && sudo apt full-upgrade`)." if module
                        else "Nichts. Die Meldung kann in Wazuh ignoriert werden.")}
    gruende = []
    if laeuft:
        gruende.append("Der betroffene Kernel-Teil ist als Modul geladen: "
                       + ", ".join(f"`{name}`" if name != "-" else f"`{d}`" for d, name in laeuft[:3]) + ".")
    if fest:
        gruende.append("Der betroffene Kernel-Teil ist fest eingebaut: "
                       + ", ".join(f"`{d}` (`{sym}=y`)" for d, sym in fest[:3]) + ".")
    gruende.append("Ausnutzen lässt sich so eine Kernel-Lücke meist nur von jemandem, der schon auf dem Rechner ist "
                   "oder passende Hardware anschließt.")
    return {"ampel": "gelb", "betroffen": "Ja", "angreifbar": "Nein", "gruende": gruende,
            "tun": r.get("tun_update") or "Kernel-Update einspielen, sobald Debian es liefert, danach neu starten."}


def kernel_nachbessern(r, ergebnis, text):
    """Folgeantwort Kernel: laufende Version (uname -v) gegen den Debian-Fix, Angriffsweg laut NVD."""
    fix = (r.get("debian") or {}).get("fix")
    m = re.search(r"Debian (\d[\w.:~+-]*)", text)
    laufend = m.group(1) if m else None
    if ergebnis["betroffen"] == "Nein":
        return ergebnis
    if fix and laufend and dpkg_vergleich(laufend, fix) >= 0:
        return {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein",
                "gruende": [f"Der laufende Kernel (`{laufend}`) enthält den Fix schon: Debian hat die Lücke in "
                            f"Version `{fix}` behoben.",
                            f"Gemeldet wurde das Paket `{r['paket']}` in Version `{r['version']}` – vermutlich ein "
                            "altes Kernel-Paket, das noch installiert ist."],
                "tun": "Alte Kernel-Pakete entfernen, dann verschwindet die Meldung: `sudo apt autoremove --purge`."}
    if fix and laufend and dpkg_vergleich(r["version"], fix) >= 0:
        ergebnis["gruende"].append(f"Das Paket mit dem Fix (`{fix}`) ist schon installiert, es läuft aber noch der "
                                   f"alte Kernel `{laufend}`.")
        ergebnis["tun"] = "Neu starten, damit der neue Kernel läuft."
    weg = (r.get("nvd") or {}).get("weg")
    if ergebnis["betroffen"] == "Ja" and weg == "NETWORK":
        ergebnis.update(ampel="rot", angreifbar="Ja")
        ergebnis["gruende"] = [g for g in ergebnis["gruende"] if not g.startswith("Ausnutzen lässt sich")]
        ergebnis["gruende"].append(f"Angriffsweg laut {r['nvd'].get('quelle', 'NVD')}: {nvd_text(r['nvd'])}.")
    return ergebnis


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
    netz = lies_netz(text)
    lage, erreichbar, netz_satz = netz_lage(netz, r["paket"]) if netz else (None, [], "")
    nur_lokal = lokale_luecke(r.get("beschreibung", "")) or (r.get("nvd") or {}).get("weg") in ("LOCAL", "PHYSICAL")
    if lage == "dienst" and not nur_lokal:
        gruende.append(netz_satz)
        return {"ampel": "rot", "betroffen": "Ja", "angreifbar": "Ja", "gruende": gruende,
                "tun": tun + " Bis dahin den Dienst nur aus dem eigenen Netz erreichbar machen "
                             "(Firewall) oder abschalten, wenn er nicht gebraucht wird."}
    ports, dienst = (None, None) if netz else (ports_fuer(r["paket"]), None)
    if not ports and not netz:
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
    if netz and erg["angreifbar"] == "Unklar":  # der Netz-Check beantwortet „von außen erreichbar?“ direkt
        gruende.append(netz_satz)
        if lage == "frei":
            erg["angreifbar"] = "Nein"
            gruende.append("Ein Risiko bleibt nur, wenn ein Programm auf diesem Rechner mit dem Paket selbst Daten "
                           "aus fremder Quelle verarbeitet (Dateien, Antworten aus dem Internet).")
        elif lage == "nutzt":
            erg["angreifbar"] = "Möglich"
        elif lage == "root":
            erg["kopf"] = "🟡 Betroffen – Netz-Check bitte als root wiederholen"
            erg["befehle"] = paket_befehle(r["paket"], r["cve"])
            erg["befehle_text"] = ("Bitte als root wiederholen (vorher `sudo -i` oder `su -`) und die Ausgabe hier "
                                   "einfügen:")
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
        if "Reverse Depends:" in text or not netz:
            gruende.append("Kein installiertes Programm hängt von diesem Paket ab.")
        if not netz:
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
          "gelb_moeglich": "🟡 Betroffen – ein von außen erreichbarer Dienst nutzt das Paket",
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
    if r.get("befehle") and r.get("tun"):
        t += [f"**Was tun:** {r['tun']}", "",
              f"**Optional genauer prüfen:** Diese Befehle auf **{r['host']}** ausführen und die komplette Ausgabe "
              "hier einfügen:", "", "```bash", r["befehle"], "```", "", f"**So liest du das Ergebnis:** {r['lesen']}"]
    elif r.get("befehle"):
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
    if e["betroffen"].startswith("Unklar (vermutlich nein"):
        return "Unklar"
    nvd = r.get("nvd") or {}
    if nvd.get("weg") == "PHYSICAL":
        return "Nur mit Zugriff am Gerät"
    if nvd.get("rechte") == "HIGH":
        return "Nur mit Root-Rechten"
    if nvd.get("weg") in ("NETWORK", "ADJACENT_NETWORK", "ADJACENT") and e["angreifbar"] != "Ja":
        return "Nur über ein Programm, das das Paket nutzt"  # Netz-Lücke ohne erreichbaren Dienst: kein lokaler Weg
    if nvd.get("weg"):
        return "Ja, falls betroffen" if e["betroffen"] == "Unklar" else "Ja"
    b = r.get("beschreibung", "")
    if root_luecke(b):
        return "Nur mit Root-Rechten"
    if lokale_luecke(b) or datei_luecke(b, r.get("paket", "")) or e["angreifbar"] == "Ja":
        return "Ja, falls betroffen" if e["betroffen"] == "Unklar" else "Ja"
    return "Unklar"


def antwort_b(r, e):
    if e.get("kopf"):
        kopf = e["kopf"]
    elif e["betroffen"] == "Unklar":
        kopf = "🟡 Noch unklar – Debian-Tracker ansehen" if r["typ"] == "paket" else "🟡 Noch unklar"
    elif e["ampel"] == "gelb" and e["angreifbar"] == "Möglich":
        kopf = KOPF_B["gelb_moeglich"]
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


# ---------------------------------------------------------------- Online-Daten (NVD, Debian-Tracker, CVE.org)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
TRACKER_URL = "https://security-tracker.debian.org/tracker/"
CVEORG_URL = "https://cveawg.mitre.org/api/cve/"
DEBIAN_NAMEN = {"10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}

ONLINE_FRIST = 8  # Sekunden für alle Online-Abfragen zusammen, danach ohne sie weiter
KBUILD_FRIST = 5  # Sekunden für die Kernel-Makefiles (zweite Runde, nur bei Kernel-Meldungen)
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
                        "interaktion": str(d.get("userInteraction", "")).upper(), "quelle": "NVD"}
    return {}


def vektor_aus_text(vektor):
    """'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/…' -> {'weg': 'NETWORK', 'rechte': 'NONE', 'interaktion': 'REQUIRED'}"""
    teile = dict(t.split(":", 1) for t in str(vektor).split("/") if ":" in t)
    weg = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}.get(teile.get("AV"))
    if not weg:
        return {}
    return {"weg": weg, "rechte": {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(teile.get("PR"), ""),
            "interaktion": {"N": "NONE", "R": "REQUIRED", "P": "REQUIRED", "A": "REQUIRED"}.get(teile.get("UI"), ""),
            "quelle": "CVE.org"}


def lies_cveorg(daten):
    """CVE-Datensatz von cve.org -> {'vektor', 'ausnutzung', 'dateien', 'versionen'}; {} = nichts Lesbares.
    vektor: CVSS vom Herausgeber der CVE, sonst von CISA. ausnutzung: 'none' | 'poc' | 'active' (CISA).
    dateien/versionen: betroffene Quelldateien und Versionsangaben (liefert kernel.org für jede Kernel-CVE)."""
    try:
        behaelter = daten["containers"]
        cna = behaelter.get("cna") or {}
    except (KeyError, TypeError, AttributeError):
        return {}
    aus = {"vektor": {}, "ausnutzung": "", "dateien": [], "versionen": []}
    for teil in [cna] + list(behaelter.get("adp") or []):
        for m in teil.get("metrics") or []:
            for k, v in m.items():
                if k.startswith("cvssV") and isinstance(v, dict) and not aus["vektor"]:
                    aus["vektor"] = vektor_aus_text(v.get("vectorString", ""))
            andere = m.get("other") or {}
            if andere.get("type") == "ssvc":
                for option in (andere.get("content") or {}).get("options") or []:
                    aus["ausnutzung"] = aus["ausnutzung"] or str(option.get("Exploitation", "")).lower()
    for a in cna.get("affected") or []:
        aus["dateien"] += [f for f in a.get("programFiles") or [] if f not in aus["dateien"]]
        if str(a.get("product", "")).lower() == "linux":
            aus["versionen"] += a.get("versions") or []
    return aus


AUSNUTZUNG = {"none": "keine bekannt", "poc": "Machbarkeitsnachweis (PoC) öffentlich",
              "active": "wird aktiv ausgenutzt"}


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
    quelle_weg = nvd.get("quelle", "NVD")
    if nvd:
        r["details"].append((f"Angriffsweg ({quelle_weg})", nvd_text(nvd)))
    if deb:
        r["details"].append((f"Debian-Tracker ({deb['release']})", debian_text(deb)))
    if r.get("ausnutzung") in AUSNUTZUNG:
        r["details"].append(("Bekannte Ausnutzung (CISA)", AUSNUTZUNG[r["ausnutzung"]]))
    if r.get("online_info"):
        r["details"].append(("Online-Abfrage", r["online_info"]))
    if r.get("typ") == "kernel":
        r = wende_online_kernel(r, nvd, deb)
    elif deb:
        r = wende_online_paket(r, nvd, deb)
    if r.get("ausnutzung") == "active" and r["ampel"] != "gruen":
        r["gruende"].append("**Die Lücke wird laut CISA bereits aktiv ausgenutzt** – das Update nicht aufschieben.")
    return r


def wende_online_kernel(r, nvd, deb):
    """Kernel: Debian-Tracker, Versionsangaben von kernel.org und die Bau-Regeln zu den betroffenen Quelldateien."""
    inst, rein = r["version"], bereinige_version(r["version"])[0]
    weg = nvd.get("weg", "")
    nvd_grund = [f"Angriffsweg laut {nvd.get('quelle', 'NVD')}: {nvd_text(nvd)}."] if weg else []
    angreifbar = "Ja" if weg == "NETWORK" else "Nein" if weg in ("LOCAL", "PHYSICAL") else "Unklar"
    dateien = r.get("dateien") or []
    quellen = kernel_quellen(dateien)
    if dateien:
        r["details"].append(("Betroffene Quelldateien", ", ".join(dateien[:4]) + (" …" if len(dateien) > 4 else "")))

    def fertig(ampel, kopf, grund, tun, betroffen, angr):
        # bei 🟢 steht der Angriffsweg nur in den Details: neben „nicht betroffen“ würde er nur verwirren
        r.update(ampel=ampel, kopf=kopf, tun=tun, befehle=None,
                 gruende=([grund] if isinstance(grund, str) else grund) + ([] if ampel == "gruen" else nvd_grund),
                 ergebnis={"betroffen": betroffen, "angreifbar": angr})
        return r

    def gruen(grund, tun=None):
        return fertig("gruen", None, grund, tun, "Nein", "Nein")

    fremd = sorted({d.split("/")[1] for d in quellen if d.startswith("arch/") and d.count("/") > 1} - {"x86"})
    if quellen and r["arch"] in X86 and all(d.startswith("arch/") and not d.startswith("arch/x86/") for d in quellen):
        return gruen(f"Die Lücke steckt in `{quellen[0]}`. Dieser Kernel-Teil ist nur für "
                     f"{ARCHITEKTUREN.get(fremd[0], fremd[0]) if fremd else 'andere Rechner-Arten'} gedacht, dieser "
                     f"Rechner ist aber ein PC ({r['arch']}).")
    programm = kernel_programm(dateien) if dateien and not quellen else None
    if programm:
        prog, paket = programm
        return gruen([f"Die Lücke steckt im Programm `{prog}` (`{dateien[0]}`), nicht im Kernel selbst. Der Kernel "
                      f"`{r['paket']}` ist nicht betroffen.",
                      f"`{prog}` liefert Debian im eigenen Paket `{paket}`. Ist es installiert, meldet Wazuh die Lücke "
                      "dafür gesondert – nur diese Meldung ist dann zu prüfen."],
                     f"Für `{r['paket']}` nichts. Nur falls `{paket}` installiert ist (`dpkg -l {paket} | grep ^ii`), "
                     "dessen Update einspielen, sobald Debian es liefert.")
    if dateien and not quellen and any(d.startswith("tools/") for d in dateien):
        return gruen(f"Die Lücke steckt in einem Hilfsprogramm aus dem Kernel-Quelltext (`{dateien[0]}`), nicht im "
                     "Kernel selbst. Der laufende Kernel ist nicht betroffen.")
    if dateien and not quellen:
        return gruen(f"Die Lücke steckt nur in Hilfsdateien des Kernel-Quelltexts (`{dateien[0]}`), nicht im "
                     "laufenden Kernel.")
    fix = deb.get("fix") if deb else None
    if deb and deb["status"] == "not-affected":
        return gruen(f"Laut Debian-Tracker ist der Kernel von {deb['release']} von dieser Lücke **nicht betroffen**.")
    if fix and dpkg_vergleich(inst, fix) >= 0:
        return gruen(f"Debian hat die Lücke in Kernel-Version `{fix}` behoben. Installiert ist `{inst}` – der Fix ist "
                     "drin. Falls seit dem letzten Kernel-Update nicht neu gestartet wurde: neu starten "
                     "(`uname -v` zeigt die laufende Version).")
    stand = r.get("kstand")
    if stand and stand[0] == "nie":
        return gruen("Laut kernel.org kam der Fehler erst " + (f"mit Kernel **{stand[1]}** in den Kernel"
                     if stand[1] else "über spätere Änderungen in andere Kernel-Zweige") + f". Installiert ist der "
                     f"ältere Zweig {rein} – der fehlerhafte Code ist dort nicht enthalten.")
    if stand and stand[0] == "behoben":
        return gruen(f"Laut kernel.org ist die Lücke seit Kernel **{stand[1]}** behoben. Installiert ist {rein} – "
                     "der Fix ist drin.")
    if fix:
        r["tun_update"] = (f"Kernel-Update einspielen – Debian liefert den Fix in Version `{fix}` (`sudo apt update "
                           "&& sudo apt full-upgrade`), danach neu starten.")
        offen = f"Debian hat den Fix in Kernel-Version `{fix}` geliefert, installiert ist noch `{inst}`."
    else:
        offen = (f"Für {deb['release']} gibt es noch **kein Kernel-Update** mit dem Fix." if deb else
                 "Kernel-Meldungen nennen keine Versionen; ob es schon ein Update gibt, zeigt der Debian-Tracker.")
        if stand and stand[1]:
            offen += f" Bei kernel.org ist er für diesen Zweig seit Version {stand[1]} enthalten."
    bau = r.get("bau")
    if bau and all(not b["symbole"] for b in bau):  # Kerncode: in jedem Kernel fest eingebaut, nichts zu prüfen
        kopf = (("🔴" if weg == "NETWORK" else "🟡") + " Kernel-Update verfügbar – bitte einspielen" if fix
                else "🟡 Betroffen – Kernel-Update einspielen, sobald verfügbar")
        fertig("rot" if fix and weg == "NETWORK" else "gelb", kopf,
               f"Die Lücke steckt in `{bau[0]['datei']}`. Das ist Kerncode, der in jedem Kernel fest eingebaut ist.",
               r["tun_update"], "Ja", angreifbar)
        r["gruende"].insert(1, offen)
        return r
    if bau:
        r.update(kopf=None, tun=None, ergebnis=None)  # eine Einstufung nur nach dem Namen gilt nicht mehr
        r["befehle"] = kernel_befehle_exakt(bau)
        r["lesen"] = ("Die `grep`-Zeile zeigt, ob der betroffene Teil in deinem Kernel steckt: fehlt die Zeile oder "
                      "steht dort „is not set“, ist er nicht eingebaut – dann kein Problem. `=m` heißt: als Modul "
                      "vorhanden; die letzte Zeile zeigt, ob es geladen ist. `=y` heißt: fest eingebaut.")
        teile = sorted({b["modul"] or b["datei"] for b in bau if b["symbole"]})
        r["gruende"] = [f"Die Lücke steckt in `{quellen[0]}`" + (f" und {len(quellen) - 1} weiteren Dateien"
                        if len(quellen) > 1 else "") + ". Laut den Bau-Regeln des Kernels gehört das zu: "
                        + ", ".join(f"`{t}`" for t in teile[:4]) + ".", offen,
                        "Ob dieser Teil in deinem Kernel eingebaut und geladen ist, zeigen die Befehle unten – "
                        "geprüft wird genau das Config-Symbol aus den Bau-Regeln."] + nvd_grund
        r["details"].append(("Kernel-Config-Symbole", ", ".join(dict.fromkeys(x for b in bau for x in b["symbole"]))))
    else:
        r["gruende"] = r["gruende"][:2] + [offen] + nvd_grund
        if r.get("bau_info"):
            r["details"].append(("Bau-Regeln des Kernels", r["bau_info"]))
        if r.get("ergebnis"):  # Kernbereich laut Beschreibung: Angriffsweg nachtragen
            r["ergebnis"]["angreifbar"] = angreifbar
    if fix:
        r["kopf"] = ("🔴" if weg == "NETWORK" else "🟡") + " Kernel-Update verfügbar – bitte einspielen"
        r["tun"] = r["tun_update"]
    return r


def wende_online_paket(r, nvd, deb):
    quelle_weg = nvd.get("quelle", "NVD")
    r["alt"] = False  # der Tracker ist schon gelesen, „im Tracker nachsehen“ entfällt
    quelle = deb.get("quellpaket")
    quell_grund = []
    if quelle:
        r["details"].append(("Debian-Quellpaket", quelle))
        herkunft = f"`{r['paket']}` stammt aus dem Debian-Quellpaket `{quelle}`. " if quelle != r["paket"] else ""
        quell_grund = [herkunft + f"Meldet Wazuh {r['cve']} für weitere Pakete aus `{quelle}`, gilt dieselbe "
                       "Bewertung – die müssen nicht einzeln geprüft werden."]
    weg = nvd.get("weg", "")
    nvd_grund = [f"Angriffsweg laut {quelle_weg}: {nvd_text(nvd)}."] if weg else []
    angreifbar = "Ja" if weg == "NETWORK" else "Nein" if weg in ("LOCAL", "PHYSICAL") else "Unklar"

    def fertig(ampel, kopf, grund, tun, betroffen, angr):
        r.update(ampel=ampel, kopf=kopf, tun=tun, befehle=None,
                 gruende=[grund] + ([] if ampel == "gruen" else nvd_grund) + quell_grund,
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
        ergebnis["gruende"].append(f"Angriffsweg laut {r['nvd'].get('quelle', 'NVD')}: {nvd_text(r['nvd'])} – "
                                   "nicht über das Netz.")
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
        ONLINE: bool = Field(default=True, description="NVD und CVE.org (Angriffsweg), Debian-Tracker (Fix-Stand) "
                             "und bei Kernel-Meldungen die Bau-Regeln des Kernels (GitHub) abfragen. "
                             "Braucht Internet im Open-WebUI-Container; ohne gelten nur die festen Regeln. "
                             "Prüfen: im Chat 'Verbindungstest' schreiben")
        NVD_KEY: str = Field(default="", description="Optionaler NVD-API-Key (mehr Anfragen pro Minute), "
                             "kostenlos bei nvd.nist.gov/developers/request-an-api-key")

    def __init__(self):
        self.valves = self.Valves()
        self._zuletzt = ""  # zuletzt erreichbare LLM-Adresse, wird zuerst probiert
        self._online = {}  # CVE -> (NVD-Daten, Tracker-Seite, CVE.org-Daten), nur erfolgreiche Abfragen
        self._kbuild = {}  # (Kernel-Zweig, Pfad) -> Makefile-Text oder None (gibt es nicht)
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

    def hole_alle(self, auftraege, frist=None):
        """{name: (url, kopf)} parallel holen, zusammen höchstens ONLINE_FRIST Sekunden -> {name: (code, text)}.
        Hängt eine Abfrage (z. B. DNS ohne Antwort), läuft sie im Hintergrund aus, die Antwort kommt trotzdem."""
        if not auftraege:
            return {}
        pool = ThreadPoolExecutor(max_workers=min(len(auftraege), 16))
        jobs = {name: pool.submit(self.hole, url, kopf) for name, (url, kopf) in auftraege.items()}
        wait(list(jobs.values()), timeout=frist or ONLINE_FRIST)
        pool.shutdown(wait=False)
        return {name: (j.result() if j.done() else (0, "")) for name, j in jobs.items()}

    def nvd_kopf(self):
        return {"apiKey": self.valves.NVD_KEY} if self.valves.NVD_KEY else {}

    def online(self, r):
        """NVD und Debian-Tracker abfragen und ins Ergebnis schreiben (r["nvd"], r["debian"], r["online_info"])."""
        if not self.valves.ONLINE or not re.fullmatch(r"CVE-\d{4}-\d+", str(r["cve"])):
            return r
        nvd_daten, seite, cveorg = self._online.get(r["cve"], (None, None, None))
        auftraege = {}
        if nvd_daten is None:
            auftraege["nvd"] = (NVD_URL + r["cve"], self.nvd_kopf())
        if seite is None and r.get("release"):
            auftraege["deb"] = (TRACKER_URL + r["cve"], {})
        if cveorg is None:
            auftraege["cveorg"] = (CVEORG_URL + r["cve"], {})
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
        if "cveorg" in geholt:
            code, text = geholt["cveorg"]
            try:
                cveorg = json.loads(text) if code == 200 else None
            except ValueError:
                cveorg = None
            if cveorg is None and code != 404:
                fehler.append("CVE.org: " + code_text(code))
        if nvd_daten is not None and cveorg is not None and (seite is not None or not r.get("release")):
            if len(self._online) > 500:
                self._online.clear()
            self._online[r["cve"]] = (nvd_daten, seite, cveorg)
        org = lies_cveorg(cveorg) if cveorg else {}
        r["nvd"] = (lies_nvd(nvd_daten) if nvd_daten else {}) or org.get("vektor") or {}
        r["debian"] = lies_tracker(seite, r["release"], r["paket"]) if seite else {}
        r["ausnutzung"] = org.get("ausnutzung", "")
        hinweis = " – Bewertung nur nach den festen Regeln. Prüfen: im Chat „Verbindungstest“ schreiben."
        if nvd_daten and not r["nvd"] and not fehler:
            fehler.append("NVD und CVE.org haben den Angriffsweg dieser CVE noch nicht bewertet")
            hinweis = ""
        if r["typ"] == "kernel" and org:
            r["dateien"] = org.get("dateien") or []
            # Ubuntu-Kernel (6.8.0-45) zählen anders als kernel.org und enthalten eigene Backports: kein Vergleich
            r["kstand"] = None if r.get("ubuntu") else kernel_stand(bereinige_version(r["version"])[0],
                                                                     org.get("versionen"))
            r["bau"], r["bau_info"] = self.kernel_bau(r)
            hinweis = hinweis and (" – soweit möglich mit den übrigen Quellen bewertet. Prüfen: im Chat "
                                   "„Verbindungstest“ schreiben.")
        if fehler:
            r["online_info"] = " · ".join(fehler) + hinweis
        return r

    def kernel_bau(self, r):
        """Betroffene Quelldateien über die Makefiles des Kernels auflösen -> (Liste aus kbuild_loese, Hinweis).
        Liste None = nicht auflösbar, dann gelten die Namen aus der Beschreibung."""
        quellen = [d for d in kernel_quellen(r.get("dateien") or []) if d.endswith((".c", ".S", ".rs"))][:4]
        zweig = ".".join(bereinige_version(r["version"])[0].split(".")[:2])
        if not quellen or not re.fullmatch(r"\d+\.\d+", zweig):
            return None, ""
        if all(d.startswith("arch/") and not d.startswith("arch/x86/") for d in quellen) and r["arch"] in X86:
            return None, ""  # fremde Architektur: entscheidet schon der Dateipfad
        if len(self._kbuild) > 3000:
            self._kbuild.clear()
        gestoert = []
        for quelle in [KBUILD_URL] + KBUILD_ERSATZ:  # was eine Quelle nicht liefert, bei der nächsten holen
            fehlend = [p for p in kbuild_pfade(quellen) if (zweig, p) not in self._kbuild]
            if not fehlend:
                break
            geholt = self.hole_alle({p: (quelle.format(zweig=zweig, pfad=p), {}) for p in fehlend}, KBUILD_FRIST)
            for pfad, (code, text) in geholt.items():
                if code in (200, 404):
                    self._kbuild[(zweig, pfad)] = text if code == 200 else None
            gestoert += [code for code, _ in geholt.values() if code not in (200, 404)]
        if any((zweig, p) not in self._kbuild for p in kbuild_pfade(quellen)):
            return None, "Kernel-Makefiles nicht abrufbar (GitHub, jsDelivr, kernel.org): " + code_text(gestoert[0])

        def lies(verzeichnis):
            vorn = verzeichnis + "/" if verzeichnis else ""
            texte = [self._kbuild.get((zweig, vorn + n)) for n in ("Makefile", "Kbuild")]
            return "\n".join(t for t in texte if t) or None

        bau = [kbuild_loese(d, lies) for d in quellen]
        if any(b is None for b in bau):
            return None, "aus den Makefiles nicht eindeutig ablesbar – geprüft wird der Name aus der Beschreibung"
        return bau, ""

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
                                     "Debian-Tracker (Fix-Stand)": (TRACKER_URL + "CVE-2021-44228", {}),
                                     "CVE.org (Angriffsweg, Kernel-Dateien)": (CVEORG_URL + "CVE-2021-44228", {}),
                                     "GitHub (Bau-Regeln des Kernels)": (KBUILD_URL.format(zweig="6.12",
                                                                                           pfad="Kbuild"), {})})
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
        if r["typ"] == "kernel":
            ergebnis = werte_kernel_exakt(r, letzte)
            if not ergebnis and r["ampel"] == "gruen":  # schon ohne Befehle entschieden (z. B. fremde Architektur)
                ergebnis = {"ampel": "gruen", "betroffen": "Nein", "angreifbar": "Nein", "gruende": r["gruende"],
                            "tun": "Nichts. Die Meldung kann in Wazuh ignoriert werden."}
            elif not ergebnis and r.get("treiber"):
                ergebnis = werte_kernel_aus(r, letzte)
            if ergebnis:
                ergebnis = kernel_nachbessern(r, ergebnis, letzte)
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
