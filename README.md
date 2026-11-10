# Wazuh-Analyse für Open WebUI

Eine Funktion für [Open WebUI](https://github.com/open-webui/open-webui), die **Schwachstellen-Meldungen aus Wazuh**
bewertet: Meldung in den Chat einfügen und eine klare Antwort bekommen – **betroffen? von außen angreifbar? was tun?**

**Debian** · **läuft auch ohne Sprachmodell** · **Antworten auf Deutsch** · [MIT-Lizenz](LICENSE)

## So funktioniert es

1. In Wazuh einen Eintrag aus `wazuh-states-vulnerabilities-*` als JSON kopieren und in den Chat einfügen.
2. Die Funktion antwortet mit Ampel, Begründung und – falls nötig – Prüfbefehlen für den betroffenen Rechner.
3. Die Ausgabe der Befehle in denselben Chat einfügen. Die Funktion nennt das Endergebnis.

| Ampel | Bedeutung |
|---|---|
| 🟢 | Kein Handlungsbedarf – mit Begründung, warum der Rechner nicht betroffen ist |
| 🟡 | Betroffen oder noch offen – mit Angabe, ob die Lücke erreichbar ist und was zu tun ist |
| 🔴 | Handlungsbedarf – Update verfügbar oder Lücke von außen erreichbar |

Viele Meldungen klären sich schon in der ersten Antwort, ohne Befehle: etwa wenn Debian die Lücke längst behoben hat,
der Fehler erst in einer neueren Version entstand oder ein Update bereitsteht.

## Beispiel

**Kernel-Meldung.** Wazuh meldet CVE-2026-98999 für `linux-image-amd64`. Erste Antwort (gekürzt):

> **🟡 Unklar – bitte prüfen**
>
> **CVE-2026-98999** · `linux-image-amd64` 6.12.115-2 auf **server01** · Schweregrad High (CVSS 7.8)
>
> **Warum diese Einstufung:**
> - Die Lücke steckt in `drivers/gpu/drm/xe/xe_bo.c`. Laut den Bau-Regeln des Kernels gehört das zu: `xe`.
> - Für trixie gibt es noch **kein Kernel-Update** mit dem Fix.
> - Ob dieser Teil in deinem Kernel eingebaut und geladen ist, zeigen die Befehle unten – geprüft wird genau das
>   Config-Symbol aus den Bau-Regeln.
> - Angriffsweg laut NVD: nur lokal (angemeldet oder über eine präparierte Datei), normales Benutzerkonto nötig.
>
> **Was tun:** Diese Befehle auf **server01** ausführen und die komplette Ausgabe hier einfügen:
>
> ```bash
> uname -rv
> echo 'KERNEL-CHECK drivers/gpu/drm/xe/xe_bo.c CONFIG_DRM_XE xe'
> grep -E '^(# )?CONFIG_(DRM_XE)[= ]' /boot/config-$(uname -r)
> lsmod | grep -E '^(xe) ' || echo 'Modul nicht geladen'
> …
> ```

Nach dem Einfügen der Ausgabe:

> **🟢 Kein Problem**
>
> **Ergebnis:** Betroffen: **Nein** · Von außen angreifbar: **Nein** · Lokal ausnutzbar: **Nein**
>
> **Warum:**
> - Der betroffene Teil ist nur als Modul vorhanden und gerade nicht geladen: `xe`. Solange das Modul nicht geladen
>   wird, ist die Lücke nicht erreichbar. Geladen würde es nur auf passender Hardware bzw. wenn die Funktion genutzt
>   wird.
>
> **Was tun:** Nichts sofort. Das nächste reguläre Kernel-Update schließt die Lücke ohnehin.

**Paket-Meldung.** Wazuh meldet CVE-2026-97687 für `python3-urllib3`. Erste Antwort (gekürzt):

> **🟡 Betroffen – bitte prüfen, ob erreichbar**
>
> **CVE-2026-97687** · `python3-urllib3` 2.3.0-3+deb13u2 auf **server01** · Schweregrad High (CVSS 8.1)
>
> **Warum diese Einstufung:**
> - Debian kennt die Lücke, für trixie gibt es aber **noch keinen Fix**.
> - Angriffsweg laut NVD: über das Netzwerk, keine Rechte nötig, jemand muss mitwirken (z. B. Datei öffnen).
> - `python3-urllib3` stammt aus dem Debian-Quellpaket `python-urllib3`. Meldet Wazuh CVE-2026-97687 für weitere
>   Pakete aus `python-urllib3`, gilt dieselbe Bewertung – die müssen nicht einzeln geprüft werden.
> - Ob die Lücke auf diesem Rechner erreichbar ist, zeigen die Befehle unten.

Nach dem Einfügen der Ausgabe:

> **🟡 Betroffen, aber derzeit nicht angreifbar**
>
> **Ergebnis:** Betroffen: **Ja** · Von außen angreifbar: **Nein** · Lokal ausnutzbar: **Nur über ein Programm, das
> das Paket nutzt**
>
> **Warum:**
> - Der Debian-Changelog von `python3-urllib3` erwähnt CVE-2026-97687 nicht. Der Fix ist also nicht eingebaut.
> - Das Paket ist Python-Code, und kein von außen erreichbarer Dienst läuft mit Python (geprüft: 14 Prozesse mit
>   offenem Netzwerk-Port). Über offene Ports ist die Lücke damit nicht erreichbar.
> - Genutzt wird das Paket von: `python3-requests`, `python3-docker`.
>
> **Was tun:** Update einspielen, sobald Debian es liefert.

Weitere Meldungen mit den zugehörigen Befehlsausgaben liegen in [`beispiele/`](beispiele/).

## Einrichten

1. Open WebUI → **Admin-Bereich → Funktionen → „+“**
2. Name `Wazuh-Analyse`, ID `wazuh_analyse`
3. Beispielcode löschen, Inhalt von [`wazuh_analyse.py`](wazuh_analyse.py) einfügen, **speichern**, Schalter **an**
4. Zahnrad an der Funktion → Einstellungen eintragen (siehe Tabelle)
5. Seite neu laden → im Chat das Modell **Wazuh-Analyse** wählen
6. Zum Prüfen `Verbindungstest` in den Chat schreiben

| Einstellung | Bedeutung | Standard |
|---|---|---|
| `LLM_URL` | OpenAI-kompatible API (llama.cpp, Ollama, vLLM, OpenAI …), aus dem Open-WebUI-Container erreichbar. Mehrere Adressen möglich, eine pro Zeile – die erste erreichbare wird genutzt | `http://localhost:8080/v1` |
| `LLM_KEY` | API-Key, falls nötig | leer |
| `LLM_MODELL` | Modellname | leer |
| `WORUM_SATZ` | Satz „Worum geht's“ vom Sprachmodell; aus = ganz ohne Sprachmodell | an |
| `ONLINE` | Öffentliche Datenquellen abfragen (siehe unten); braucht Internet im Open-WebUI-Container | an |
| `NVD_KEY` | Optionaler [NVD-API-Key](https://nvd.nist.gov/developers/request-an-api-key) für mehr Anfragen pro Minute | leer |

## Woher die Daten kommen

Die Funktion entscheidet nach öffentlichen Daten zur CVE und nach dem, was die Prüfbefehle auf dem Rechner zeigen.

| Quelle | Wofür |
|---|---|
| [Debian-Tracker](https://security-tracker.debian.org) | Stand für die Debian-Version des Rechners: behoben in Version X, offen, nicht betroffen |
| [NVD](https://nvd.nist.gov) | Angriffsweg (Netzwerk, lokal, nur am Gerät) und nötige Rechte |
| [CVE.org](https://www.cve.org) | Angriffsweg vom Herausgeber der CVE, bekannte Ausnutzung (CISA); bei Kernel-Meldungen die betroffenen Quelldateien und Versionen |
| Makefiles des Linux-Kernels (GitHub, ersatzweise jsDelivr und kernel.org) | Nur bei Kernel-Meldungen: Quelldatei → Config-Symbol → Modulname, damit der Prüfbefehl genau das Richtige abfragt |

**Ohne Internet** arbeitet die Funktion mit den Angaben aus der Meldung und den Prüfbefehlen. Die Antwort nennt dann in
den Details, welche Quelle fehlte.

**Verbindung prüfen:** `Verbindungstest` in den Chat schreiben. Die Antwort zeigt für jede Quelle einen Code:

| Code | Bedeutung |
|---|---|
| **200** | erreichbar, alles in Ordnung |
| **000** | keine Verbindung oder keine Antwort innerhalb von 8 Sekunden – der Open-WebUI-Container kommt nicht ins Internet (DNS, Firewall oder Proxy prüfen) |
| **403** | Zugriff verweigert – meist zu viele Anfragen ohne API-Key, oder ein Proxy blockt |
| **429** | zu viele Anfragen – eine Minute warten |
| **5xx** | der Dienst ist gerade gestört – später noch mal |

Dasselbe von Hand auf dem Docker-Host:
`docker exec open-webui curl -s -m 10 -o /dev/null -w '%{http_code}\n' https://security-tracker.debian.org/tracker/CVE-2021-44228`

## Was geprüft wird

| Bereich | Prüfung |
|---|---|
| **Pakete** | Ist die Lücke in der eigenen Debian-Version behoben, und ist die installierte Version neu genug (Vergleich wie `dpkg`)? Versionsbereiche aus der Beschreibung, Debian-Backports, Debian-Changelog. |
| **Kernel** | Ist der betroffene Teil im Kernel eingebaut, und ist das Modul geladen? Dazu: fremde Architektur, Fehler erst in neuerem Kernel, Fix schon installiert, laufender Kernel älter als der installierte. |
| **Erreichbarkeit** | Nutzt ein Dienst mit offenem Netzwerk-Port das Paket? Geprüft an den laufenden Prozessen, ohne feste Port-Liste. Dazu der Angriffsweg: Netzwerk, nur lokal, nur über eine geöffnete Datei oder eine ausgehende Verbindung. |

Alle Prüfbefehle lesen nur, sie ändern nichts am Rechner.

## Warum feste Regeln?

- **Gleiche Eingabe, gleiches Ergebnis.** Die Bewertung rechnet Python nach festen Regeln, nicht ein Sprachmodell.
- **Jede Einstufung nennt ihren Beleg** – die Quelle, die Zeile aus der Kernel-Config, den Prozess mit offenem Port.
- **Schnell und ohne Grafikkarte nutzbar.** Das Sprachmodell schreibt nur den Satz „Worum geht's“ und lässt sich
  abschalten.

## Welches Sprachmodell?

Jedes kleine Modell, das Deutsch kann – es schreibt nur einen Satz. Getestet mit **Qwen3.5-9B** (Unsloth UD-Q4_K_XL) auf
`llama-server`, RTX 3060 Ti 8 GB, Debian 13, Open WebUI 0.13.0, Wazuh 4.14.10: 1–4 Sekunden pro Antwort. Ein
3–4B-Modell oder reine CPU reicht auch.

## Grenzen

- Nur Debian (getestet mit 12 und 13) und nur Schwachstellen-Einträge (keine Alerts). Ubuntu ist ungetestet: Die
  Funktion arbeitet dort vorsichtig (kein Abgleich mit dem Fix-Stand, eher 🟡), aber ohne Gewähr.
- Ob ein Paket den betroffenen Code wirklich enthält, prüft die Funktion über den Namen; im Zweifel bleibt es bei 🟡.
- Rund jede achte Kernel-Meldung lässt sich nicht genau einer Kernel-Option zuordnen. Dann wird über den Namen aus
  der Beschreibung geprüft, und 🟢 gibt es nur mit eindeutigem Beleg.
- Die Prüfung der Erreichbarkeit sieht nur Prozesse, die gerade laufen, und braucht root.
- **Ein 🟢 ist eine begründete Einschätzung, keine Garantie.**

## Test

`python3 -I test/test_wazuh_analyse.py` prüft die [`beispiele/`](beispiele/) ohne Open WebUI und ohne Sprachmodell. Nur
für Änderungen am Code nötig. Die Versionsgeschichte steht in [`CHANGELOG.md`](CHANGELOG.md).

## Lizenz

[MIT](LICENSE) – ohne Gewähr. Entstanden für den eigenen Einsatz mit Wazuh und Open WebUI. Issues und Pull Requests sind
willkommen.

Entwickelt von Elwin Ehlers mit [Claude](https://claude.ai) (Anthropic).
