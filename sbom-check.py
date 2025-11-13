#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ein Python-Skript zur Analyse von CycloneDX 1.5 SBOMs (JSON)
um das Alter von Software-Komponenten zu überprüfen.

Nutzung:
    python sbom_age_analyzer.py --sbom /pfad/zu/sbom.json --age 90
"""

import json
import argparse
import sys
from datetime import datetime, timezone
import requests
from typing import Optional, Dict, Any

# Konfigurieren Sie ein einfaches Logging für Fehlermeldungen auf stderr
def log_error(message: str):
    """Schreibt eine Fehlermeldung auf stderr."""
    print(f"FEHLER: {message}", file=sys.stderr)

def parse_purl(purl: str) -> Optional[Dict[str, str]]:
    """
    Parst eine Package URL (PURL), um Typ, Namen, Version und optional die Gruppe zu extrahieren.
    
    HINWEIS: Dies ist ein vereinfachter Parser. Für eine robuste Produktion
    wird die Bibliothek 'packageurl-python' empfohlen.
    """
    if not purl or not purl.startswith("pkg:"):
        log_error(f"Ungültiges oder leeres PURL-Format: {purl}")
        return None

    try:
        # Entferne 'pkg:' und teile bei '@' für Version
        main_part, version_part = purl[4:].split('@', 1)
        
        # Isoliere die Version von Qualifizierern
        version = version_part.split('?')[0].split('#')[0]
        
        # Teile den Hauptteil, um Typ und Namensraum/Name zu erhalten
        parts = main_part.split('/')
        pkg_type = parts[0]
        
        name_parts = parts[1:]
        
        result = {
            "type": pkg_type,
            "version": version
        }

        if pkg_type == "maven":
            if len(name_parts) < 2:
                raise ValueError("Maven PURL fehlt group oder artifact")
            result["group"] = name_parts[0]
            result["artifact"] = name_parts[1]
        elif pkg_type in ["npm", "pypi", "cargo", "composer"]:
            # Behandelt Fälle wie 'npm/react' oder 'npm/@angular/core'
            result["name"] = "/".join(name_parts)
        else:
            # Fallback für andere Typen
            result["name"] = "/".join(name_parts)
            
        return result
        
    except ValueError as e:
        log_error(f"PURL-Parsing fehlgeschlagen für {purl}: {e}")
        return None
    except Exception as e:
        log_error(f"Unerwarteter PURL-Parsing-Fehler für {purl}: {e}")
        return None

def get_pypi_release_date(name: str, version: str) -> Optional[datetime]:
    """
    Ruft das Veröffentlichungsdatum einer bestimmten Paketversion von PyPI ab.
    """
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Löst eine Ausnahme für 4xx/5xx-Status aus
        
        data = response.json()
        
        # Finde das früheste Upload-Datum (normalerweise das erste)
        if "urls" in data and data["urls"]:
            # Daten können None sein, also filtern wir
            upload_times = [
                entry["upload_time_iso_8601"] 
                for entry in data["urls"] 
                if entry.get("upload_time_iso_8601")
            ]
            if not upload_times:
                log_error(f"Keine Upload-Zeiten gefunden für pypi:{name}@{version}")
                return None
                
            first_upload_str = min(upload_times)
            # Konvertiere ISO-String (z.B. "2024-01-01T12:00:00.000000Z")
            return datetime.fromisoformat(first_upload_str.replace("Z", "+00:00"))
        
        log_error(f"Keine 'urls'-Sektion gefunden für pypi:{name}@{version}")
        return None

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            log_error(f"PyPI-Paket nicht gefunden (404): {url}")
        else:
            log_error(f"HTTP-Fehler beim Abrufen von PyPI-Daten für {name}@{version}: {e}")
        return None
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        log_error(f"Fehler beim Abrufen von PyPI-Daten für {name}@{version}: {e}")
        return None

def get_npm_release_date(name: str, version: str) -> Optional[datetime]:
    """
    Ruft das Veröffentlichungsdatum einer bestimmten Paketversion von npm registry ab.
    """
    # URL-kodiert den Namen, falls er einen Schrägstrich enthält (z.B. @angular/core)
    url = f"https://registry.npmjs.org/{requests.utils.quote(name)}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if "time" in data and version in data["time"]:
            date_str = data["time"][version]
            # Konvertiere ISO-String
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        
        log_error(f"Version {version} nicht im 'time'-Objekt für npm:{name} gefunden")
        return None

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            log_error(f"NPM-Paket nicht gefunden (404): {url}")
        else:
            log_error(f"HTTP-Fehler beim Abrufen von NPM-Daten für {name}@{version}: {e}")
        return None
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        log_error(f"Fehler beim Abrufen von NPM-Daten für {name}@{version}: {e}")
        return None

def get_maven_release_date(group: str, artifact: str, version: str) -> Optional[datetime]:
    """
    Ruft das Veröffentlichungsdatum (Timestamp) eines Maven-Artefakts ab.
    """
    # Nutzt die Maven Central Search API
    query = f'g:"{group}"+AND+a:"{artifact}"+AND+v:"{version}"'
    url = f"https://search.maven.org/solrsearch/select?q={query}&rows=1&wt=json"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get("response", {}).get("numFound", 0) > 0:
            doc = data["response"]["docs"][0]
            timestamp_ms = doc["timestamp"]
            # Konvertiere Millisekunden-Timestamp in ein datetime-Objekt (UTC)
            return datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
            
        log_error(f"Maven-Artefakt nicht gefunden: g={group} a={artifact} v={version}")
        return None

    except (requests.exceptions.RequestException, json.JSONDecodeError, IndexError) as e:
        log_error(f"Fehler beim Abrufen von Maven-Daten für {group}:{artifact}:{version}: {e}")
        return None

def analyze_sbom(sbom_path: str, max_age_days: int):
    """
    Lädt, parst und analysiert die SBOM-Datei auf veraltete Komponenten.
    """
    try:
        with open(sbom_path, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)
    except FileNotFoundError:
        log_error(f"SBOM-Datei nicht gefunden: {sbom_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        log_error(f"SBOM-Datei konnte nicht als JSON geparst werden: {sbom_path}")
        sys.exit(1)
    except Exception as e:
        log_error(f"Fehler beim Lesen der SBOM-Datei {sbom_path}: {e}")
        sys.exit(1)

    if "components" not in sbom_data:
        log_error("SBOM-Datei enthält keinen 'components'-Schlüssel der obersten Ebene.")
        return

    components = sbom_data.get("components", [])
    if not components:
        print("Keine Komponenten in der SBOM gefunden.", file=sys.stderr)
        return

    now = datetime.now(timezone.utc)
    found_vulnerable = False

    for component in components:
        purl = component.get("purl")
        if not purl:
            # Ignoriere Komponenten ohne PURL
            continue

        parsed_purl = parse_purl(purl)
        if not parsed_purl:
            log_error(f"Überspringe Komponente aufgrund eines PURL-Parsing-Fehlers: {purl}")
            continue
            
        pkg_type = parsed_purl["type"]
        version = parsed_purl["version"]
        release_date: Optional[datetime] = None

        try:
            if pkg_type == "pypi":
                release_date = get_pypi_release_date(parsed_purl["name"], version)
            elif pkg_type == "npm":
                release_date = get_npm_release_date(parsed_purl["name"], version)
            elif pkg_type == "maven":
                release_date = get_maven_release_date(parsed_purl["group"], parsed_purl["artifact"], version)
            elif pkg_type in ["cargo", "composer", "golang", "spm"]:
                # Platzhalter für zukünftige Implementierungen
                # log_error(f"Überspringe nicht unterstützten PURL-Typ: {pkg_type}")
                pass
            else:
                # Unbekannte Typen protokollieren, falls gewünscht
                # log_error(f"Unbekannter PURL-Typ: {pkg_type}")
                pass

            if release_date:
                # Sicherstellen, dass das Datum Zeitzonen-bewusst ist (sollte es sein)
                if release_date.tzinfo is None:
                    log_error(f"Abgerufenes Datum für {purl} ist nicht Zeitzonen-bewusst. Nehme UTC an.")
                    release_date = release_date.replace(tzinfo=timezone.utc)

                age = now - release_date
                age_in_days = age.days
                
                if age_in_days > max_age_days:
                    found_vulnerable = True
                    print(f"ALARM: {purl} | VÖ: {release_date.date().isoformat()} | Alter: {age_in_days} Tage (Limit: {max_age_days} Tage)")

        except Exception as e:
            # Fängt alle unerwarteten Fehler während der Verarbeitung einer einzelnen Komponente ab
            log_error(f"Unerwarteter Fehler bei der Verarbeitung von {purl}: {e}")
            
    if not found_vulnerable:
        print(f"Analyse abgeschlossen. Keine Komponenten älter als {max_age_days} Tage gefunden.", file=sys.stderr)

def main():
    """
    Hauptfunktion zum Parsen von Argumenten und Starten der Analyse.
    """
    parser = argparse.ArgumentParser(
        description="Analysiert eine CycloneDX 1.5 SBOM auf veraltete Komponenten.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "--sbom",
        required=True,
        help="Der Dateipfad zur CycloneDX 1.5 JSON-Datei."
    )
    
    parser.add_argument(
        "--age",
        required=True,
        type=int,
        help="Das maximal zulässige Alter einer Komponente in Tagen (z. B. 90)."
    )
    
    args = parser.parse_args()
    
    if args.age <= 0:
        log_error("--age muss ein positiver Integer sein.")
        sys.exit(1)
        
    analyze_sbom(args.sbom, args.age)

if __name__ == "__main__":
    main()