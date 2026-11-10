# Versionsgeschichte

## 2.4 – 10.11.2026

- Geändert: Kernel-Meldungen zu Programmen aus dem Kernel-Quelltext (z. B. `perf`) nennen das Debian-Paket, das
  stattdessen betroffen sein kann (`linux-perf`), und wie man prüft, ob es installiert ist.
- Geändert: Bei 🟢 steht der Angriffsweg nur noch in den Details.

## 2.3 – 10.11.2026

- Geändert: „Lokal ausnutzbar“ steht bei Netz-Lücken nur noch auf „Ja“, wenn ein Dienst von außen erreichbar ist.
- Geändert: Läuft die Prüfung der Erreichbarkeit ohne root, bittet die Antwort um Wiederholung als root.
- Neu: Beispiel `CVE-2026-97687-urllib3`.

## 2.1 – 10.11.2026

- Neu: Kernel-Meldungen werden über die betroffenen Quelldateien (CVE.org) und die Makefiles des Kernels dem genauen
  Config-Symbol und Modul zugeordnet. Quellen für die Makefiles: GitHub, ersatzweise jsDelivr und kernel.org.
- Neu: Kernel-Meldungen nutzen den Debian-Tracker und die Versionsangaben von kernel.org.
- Neu: Prüfung der Erreichbarkeit an den laufenden Prozessen statt über eine feste Port-Liste.
- Neu: Angriffsweg zusätzlich von CVE.org, bekannte Ausnutzung laut CISA.
- Geändert: Weitere Schreibweisen von Versionsbereichen; 🟢 bei Kernel-Meldungen nur mit eindeutigem Beleg.
- Ausgaben der Prüfbefehle aus früheren Versionen werden weiter verstanden.

## 1.25 – 09.11.2026

- Neu: Online-Abfrage von NVD (Angriffsweg) und Debian-Tracker (Fix-Stand), Befehl `Verbindungstest`.
- Neu: Angabe „Lokal ausnutzbar“, Regeln für Datei-Lücken, Secure Boot und weitere Fälle.

## 1.8 – 08.11.2026

- Neu: mehrere Adressen für das Sprachmodell, automatische Umschaltung.

## 1.7 – 08.11.2026

- Erste veröffentlichte Fassung.
