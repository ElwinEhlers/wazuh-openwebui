# Wazuh-Analyse für Open WebUI

Eine Funktion für [Open WebUI](https://github.com/open-webui/open-webui), die **Schwachstellen-Meldungen aus Wazuh** auf
Debian/Ubuntu bewertet. JSON aus `wazuh-states-vulnerabilities-*` in den Chat einfügen → Ampel 🟢/🟡/🔴, Begründung und
Prüfbefehle. Ausgabe der Befehle einfügen → Endergebnis: **betroffen? von außen angreifbar? was tun?**

## Beispiel

> ## 🟡 Unklar – bitte prüfen
> **CVE-2026-53791** · `rsync` 3.2.7-1+deb12u6 auf **monitor01** · Schweregrad Critical (CVSS 9.1)
>
> **Warum diese Einstufung:**
> - Betroffen sind Versionen vor 3.5.0. Installiert ist 3.2.7 – das liegt im betroffenen Bereich.
> - Aber: Debian-Zusatz `-1+deb12u6` – Debian baut Fixes oft nachträglich ein. Ob der Fix drin ist, zeigt der erste Befehl.
>
> **Was tun:** Diese Befehle auf **monitor01** ausführen und die Ausgabe hier einfügen: …

Nach dem Einfügen der Ausgabe:

> ## 🟡 Betroffen, aber derzeit nicht angreifbar
> **Ergebnis:** Betroffen: **Ja** · Von außen angreifbar: **Nein** – Fix fehlt, Port 873 (rsync) lauscht nicht.
> **Was tun:** Update einspielen, sobald Debian es liefert.

## Warum Python und nicht das Sprachmodell?

Zuerst bekam ein lokales LLM (Qwen3.5-9B, Qwen3.6-35B) das JSON mit einem Regel-Prompt. Die Ampel stimmte oft, aber nicht
zuverlässig – und die Fehler waren gefährlich:

- „3.1.13 < 3.2.9 → **nicht** betroffen“ → echte Lücke als 🟢
- Debian-Backport-Regel übersprungen → 🔴 statt 🟡
- Kernel-Prüfbefehl `grep -i drm/xe` findet nie etwas → falsche Entwarnung
- Regeltext und doppelte Tabellen in der Antwort, 35–115 Sekunden pro Meldung

Die Regeln (Versionen vergleichen, „deb“ suchen, Treibernamen lesen, Ports finden) sind eindeutig – das kann Code besser:
immer gleiches Ergebnis, ~1 Sekunde, testbar. Das LLM schreibt nur noch den Satz „Worum geht's“.

## Einbau

1. Open WebUI → **Admin-Bereich → Funktionen → „+“**
2. Name `Wazuh-Analyse`, ID `wazuh_analyse`
3. Beispielcode löschen, Inhalt von [`wazuh_analyse.py`](wazuh_analyse.py) einfügen, **speichern**, Schalter **an**
4. Zahnrad an der Funktion → Einstellungen eintragen
5. Seite neu laden → Modell **Wazuh-Analyse** wählen

| Einstellung | Bedeutung | Standard |
|---|---|---|
| `LLM_URL` | OpenAI-kompatible API (llama.cpp, Ollama, vLLM, OpenAI …), aus dem Open-WebUI-Container erreichbar. Mehrere Adressen möglich, eine pro Zeile – die erste erreichbare wird genutzt | `http://localhost:8080/v1` |
| `LLM_KEY` | API-Key, falls nötig | leer |
| `LLM_MODELL` | Modellname | leer |
| `WORUM_SATZ` | Satz „Worum geht's“ vom LLM; aus = ganz ohne LLM | an |

## Welches Sprachmodell?

Jedes kleine Modell, das Deutsch kann – es schreibt nur einen Satz. Getestet mit **Qwen3.5-9B** (Unsloth UD-Q4_K_XL) auf
`llama-server`, **RTX 3060 Ti 8 GB**, Ryzen 7 3700X, 32 GB RAM, Debian 13, Open WebUI 0.13.0, Wazuh 4.14.10: ~1 Sekunde pro
Antwort. Ein 3–4B-Modell oder reine CPU reicht auch.

## Was geprüft wird

- **Version:** Bereiche aus der Beschreibung („before“, „through“, „from X until Y“ …), Epoche, `+really`, Debian-Backport (`deb` → nie 🔴)
- **Kernel:** Treiber aus der Beschreibung, fremde Architektur → 🟢, Kernel-Config und `lsmod` (Modul nicht geladen → 🟢)
- **Nach den Ausgaben:** Debian-Changelog, offene Ports bekannter Dienste, lokale Lücken, Client-Lücken, Secure Boot, Bibliotheken → nutzende Programme, alte CVEs → Debian-Tracker

## Grenzen

Nur Debian/Ubuntu und nur Schwachstellen-Einträge (keine Alerts). Die Beschreibung wird per Muster gelesen. Ob ein Paket den
betroffenen Code wirklich enthält, prüft die Funktion nur über den Namen (im Zweifel 🟡). Ausgabe auf Deutsch.
**Ein 🟢 ist eine begründete Einschätzung, keine Garantie.**

## Test

`python3 -I test/test_wazuh_analyse.py` prüft die [`beispiele/`](beispiele/) ohne Open WebUI und ohne LLM. Nur für Änderungen
am Code nötig.

## Lizenz

[MIT](LICENSE) – ohne Gewähr. Entstanden für den eigenen Einsatz mit Wazuh und Open WebUI. Issues und Pull Requests sind
willkommen.

Entwickelt von Elwin Ehlers mit [Claude](https://claude.ai) (Anthropic).
