# Beispiele

Echte Wazuh-Meldungen (anonymisiert: Rechnernamen ersetzt, Portlisten gekürzt) und die Ausgaben der Prüfbefehle.

- `json/` – Einträge aus `wazuh-states-vulnerabilities-*`, so wie man sie in den Chat einfügt
- `ausgaben/` – Ausgabe der Prüfbefehle zum gleichnamigen JSON. Dateien `*.v2.txt` sind Ausgaben der Befehle ab
  Version 2.0 (Kernel: genaues Config-Symbol; Pakete: Netz-Check), die übrigen stammen von den Befehlen bis 1.25 und
  werden weiter verstanden

| Datei | Fall | Erwartet (erste Antwort → Folgeantwort) |
|---|---|---|
| CVE-2026-42217-openexr | Bibliothek, Version betroffen, kein Backport | 🔴 |
| CVE-2026-53791-rsync | Debian-Backport möglich, Dienst-Port nicht offen | 🟡 → 🟡 nicht angreifbar |
| CVE-2026-85977-libtirpc | Client-Lücke | 🟡 → 🟡 nicht angreifbar |
| CVE-2026-86140-libxml2 | `+really`-Version, Bibliothek | 🟡 → 🟡 Risiko hängt von Programmen ab |
| CVE-2026-89611-kernel | Kernel, Treiber ntfs | 🟡 |
| CVE-2026-91964-libwinpr | Backport, Paket nicht im Text genannt | 🟡 |
| CVE-2026-97689-urllib3 | „from X until Y“, Client-Lücke | 🟡 → 🟡 nicht angreifbar |
| CVE-2026-97876-grub | lokale Lücke, Secure Boot | 🟡 → 🟡 nicht angreifbar |
| CVE-2026-98999-xe | Kernel, Modul vorhanden, nicht geladen | 🟡 → 🟢 |
| CVE-2026-99125-pai | Kernel, fremde Architektur (s390) | 🟢 → 🟢 |
| CVE-2026-99189-gpio | Kernel, zwei Namen „gpio: mxc:“ | 🟡 |
| CVE-2019-12067-qemu | alte CVE (Changelog sagt wenig) | 🟡 → 🟡 Debian-Tracker ansehen |
| CVE-2026-118370-libexpat | „through“, Bibliothek mit vielen Nutzern | 🟡 → 🟡 Risiko hängt von Programmen ab; mit Netz-Check (`.v2.txt`): 🟡 erreichbarer Dienst nutzt das Paket |
| CVE-2016-2568-polkit, CVE-2016-2781-coreutils | alte lokale Lücke über TIOCSTI | 🟡 → 🟢 (Kernel sperrt TIOCSTI) |
| CVE-2026-7307x-vim (4 Dateien) | Datei-Lücken, eine nur in der GUI-Fassung | 🟡 → 🟡 nicht angreifbar bzw. 🟢 |
| CVE-2026-85231-libtirpc | Lücke nur im RPC-Dienst | 🟡 → 🟡 nicht angreifbar |
| CVE-2026-69248-cryptography | Version außerhalb des Bereichs | 🟢 |
| CVE-2026-78410-fdisk, CVE-2026-119591-sqlite | keine Grenze bzw. Backport möglich | 🟡 |
| CVE-2026-49265-oauthlib | Lücke im Server-Teil, nur Client-Nutzung | 🔴 → 🟢 |
| CVE-2026-97687-urllib3 | Python-Paket, Netz-Check: kein Python-Dienst lauscht (`.v2.txt`) | 🟡 → 🟡 nicht angreifbar |

Mit Internet fallen die Kernel-Beispiele genauer aus: `xe` und `gpio` bekommen Befehle mit dem genauen
Config-Symbol (Ausgaben in `*.v2.txt` → beide 🟢), `pai` ist über den Dateipfad `arch/s390/…` sofort 🟢.
