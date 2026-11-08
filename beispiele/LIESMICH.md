# Beispiele

Echte Wazuh-Meldungen (anonymisiert: Rechnernamen ersetzt, Portlisten gekürzt) und die Ausgaben der Prüfbefehle.

- `json/` – Einträge aus `wazuh-states-vulnerabilities-*`, so wie man sie in den Chat einfügt
- `ausgaben/` – Ausgabe der Prüfbefehle zum gleichnamigen JSON

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
| CVE-2026-118370-libexpat | „through“, Bibliothek mit vielen Nutzern | 🟡 → 🟡 Risiko hängt von Programmen ab |
