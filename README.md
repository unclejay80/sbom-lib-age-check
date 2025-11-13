# sbom-check

Dieses Repository enthält ein kleines Python-CLI-Tool `sbom-check.py`, das CycloneDX (JSON) SBOMs analysiert, das Veröffentlichungsdatum von Komponenten ermittelt und für Komponenten, die älter als eine konfigurierbare Anzahl von Tagen sind, eine ALARM-Zeile ausgibt.

Wichtige Eigenschaften
- Unterstützte Registries: crates.io (Cargo), npm, PyPI, Maven Central / Google Maven, CocoaPods.
- Optionaler Update-Check: mit `--check-updates` werden für ALARM-Komponenten verfügbare neuere Versionen bei den jeweiligen Registries geprüft.
- Parallelisiert: Registry-Abfragen werden mit einem konfigurierbaren Worker-Count parallel ausgeführt (`--max-workers`).
- Persistenter Cache: Ergebnisse (neueste Versionen und Release-Daten) werden in einer JSON-Cache-Datei zwischengespeichert, um wiederholte Requests zu vermeiden.

Voraussetzungen
- Python 3.8+ (empfohlen 3.10+)

Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Schnellstart / Beispiele
- Ein schnelles Run (nur Alter prüfen, Standard-Cache):

```bash
python3 sbom-check.py --sbom sbom-all-v1_5_web.json --age 30
```

- Mit Update-Prüfung, Cache-Datei und 6 parallelen Workern:

```bash
python3 sbom-check.py --sbom sbom-all-v1_5_web.json --age 30 --check-updates --max-workers 6 --cache .sbom-check-cache.json
```

CLI-Flags (wichtige)
- `--sbom PATH`  : Pfad zur CycloneDX JSON SBOM (v1.5)
- `--age N`      : Altersgrenze in Tagen (Komponenten, deren letzter Release älter sind, werden als ALARM gelistet)
- `--check-updates`: Wenn gesetzt, prüft das Tool für ALARM-Komponenten, ob neuere Versionen verfügbar sind
- `--max-workers N`: Anzahl paralleler Worker für Registry-Anfragen (empfohlen 4-8 für große SBOMs)
- `--cache PATH` : Pfad zur persistierenden Cache-Datei (Standard: `.sbom-check-cache.json`)

Ausgabeformat
Das Tool schreibt Zeilen mit folgendem Grundmuster in stdout:

ALARM: <purl>@<version> | VÖ: <release-date> | Alter: <n> Tage (Limit: <age> Tage) | UPDATE_AVAILABLE: latest: <x.y.z> (aktuell: <a.b.c>)

Hinweise
- Die erste Ausführung auf einer großen SBOM kann viele HTTP-Requests auslösen und einige Minuten dauern. Der persistente Cache reduziert wiederholte Last bei späteren Durchläufen.
- Manche Registries liefern Pre-Releases oder RCs; das Tool versucht, vernünftige Entscheidungen zu treffen, kann aber je nach Paket-Ökosystem unterschiedliche Ergebnisse liefern.
