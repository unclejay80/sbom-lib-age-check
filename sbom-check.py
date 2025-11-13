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
import xml.etree.ElementTree as ET
import os

# Optional strong version compare libs (best effort)
try:
    from packaging.version import Version as PackagingVersion
except Exception:
    PackagingVersion = None

try:
    import semver
except Exception:
    semver = None

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
    # Einfacher In-Memory-Cache, damit bei mehrfachen Vorkommen nicht erneut
    # dieselben HTTP-Anfragen ausgeführt werden.
    if not hasattr(get_maven_release_date, "_cache"):
        get_maven_release_date._cache = {}

    cache_key = (group, artifact, version)
    if cache_key in get_maven_release_date._cache:
        return get_maven_release_date._cache[cache_key]

    # Nutzt die Maven Central Search API mit URL-Parametern (robusteres Encoding)
    search_url = "https://search.maven.org/solrsearch/select"
    query = f'g:"{group}" AND a:"{artifact}" AND v:"{version}"'
    params = {"q": query, "rows": 1, "wt": "json"}
    
    try:
        response = requests.get(search_url, params=params, timeout=5)
        response.raise_for_status()

        data = response.json()

        if data.get("response", {}).get("numFound", 0) > 0:
            doc = data["response"]["docs"][0]
            timestamp_ms = doc.get("timestamp")
            if timestamp_ms:
                dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
                get_maven_release_date._cache[cache_key] = dt
                return dt

        # Fallback: Versuche, das Artefakt-URL auf repo1.maven.org zu prüfen
        # Baue Pfad: /{groupId path}/{artifact}/{version}/{artifact}-{version}.pom
        group_path = group.replace('.', '/')
        pom_url = f"https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}.pom"

        # Zunächst HEAD anfragen, um Last-Modified zu erhalten
        head_resp = requests.head(pom_url, timeout=4)
        if head_resp.status_code == 200:
            last_mod = head_resp.headers.get("Last-Modified")
            if last_mod:
                try:
                    # Parse RFC 2822/1123 dates
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(last_mod)
                    # Ensure timezone-aware
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    get_maven_release_date._cache[cache_key] = dt
                    return dt
                except Exception:
                    # Ignoriere Parsefehler und fahre mit GET fort
                    pass

        # Wenn HEAD nichts liefert, versuche GET und prüfe Last-Modified
        get_resp = requests.get(pom_url, timeout=6)
        if get_resp.status_code == 200:
            last_mod = get_resp.headers.get("Last-Modified")
            if last_mod:
                from email.utils import parsedate_to_datetime
                try:
                    dt = parsedate_to_datetime(last_mod)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    get_maven_release_date._cache[cache_key] = dt
                    return dt
                except Exception:
                    pass

        # Fallback 2: Google's Maven repository (enthält viele AndroidX/Google-Artefakte)
        google_pom_url = f"https://dl.google.com/dl/android/maven2/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"
        try:
            head_resp = requests.head(google_pom_url, timeout=4)
            if head_resp.status_code == 200:
                last_mod = head_resp.headers.get("Last-Modified")
                if last_mod:
                    from email.utils import parsedate_to_datetime
                    try:
                        dt = parsedate_to_datetime(last_mod)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        get_maven_release_date._cache[cache_key] = dt
                        return dt
                    except Exception:
                        pass
        except requests.exceptions.RequestException:
            # Ignoriere Google-Repo-Ausfälle und fahre fort
            pass

        log_error(f"Maven-Artefakt nicht gefunden oder kein Datum verfügbar: g={group} a={artifact} v={version}")
        get_maven_release_date._cache[cache_key] = None
        return None

    except (requests.exceptions.RequestException, json.JSONDecodeError, IndexError) as e:
        log_error(f"Fehler beim Abrufen von Maven-Daten für {group}:{artifact}:{version}: {e}")
        return None


def get_latest_maven_version(group: str, artifact: str) -> Optional[str]:
    """
    Prüfe die neueste verfügbare Version eines Maven-Artefakts.
    Versucht zuerst die `maven-metadata.xml` auf repo1.maven.org, fallback auf search.maven.org.
    """
    try:
        group_path = group.replace('.', '/')
        metadata_url = f"https://repo1.maven.org/maven2/{group_path}/{artifact}/maven-metadata.xml"
        resp = requests.get(metadata_url, timeout=6)
        if resp.status_code == 200 and resp.text:
            try:
                root = ET.fromstring(resp.text)
                # Suche nach <versioning><release> oder <versioning><latest>
                versioning = root.find('versioning')
                if versioning is not None:
                    release = versioning.findtext('release')
                    if release:
                        return release
                    latest = versioning.findtext('latest')
                    if latest:
                        return latest
                    # Fallback: die letzte in <versions>
                    versions = versioning.find('versions')
                    if versions is not None:
                        vers = [v.text for v in versions.findall('version') if v.text]
                        if vers:
                            return vers[-1]
            except ET.ParseError:
                pass

        # Fallback: search.maven.org
        search_url = "https://search.maven.org/solrsearch/select"
        query = f'g:"{group}" AND a:"{artifact}"'
        params = {"q": query, "rows": 1, "wt": "json"}
        resp = requests.get(search_url, params=params, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get('response', {}).get('numFound', 0) > 0:
            doc = data['response']['docs'][0]
            # Versuche Felder, die Version angeben können
            for key in ('latestVersion', 'v', 'version'):
                if key in doc:
                    return doc[key]
        return None
    except requests.exceptions.RequestException:
        return None


def _load_persistent_cache(cache_file: str) -> Dict[str, Any]:
    if not cache_file:
        return {}
    try:
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as cf:
                return json.load(cf)
    except Exception:
        # ignore cache load errors
        pass
    return {}


def _save_persistent_cache(cache_file: str, cache: Dict[str, Any]):
    if not cache_file:
        return
    try:
        with open(cache_file, 'w', encoding='utf-8') as cf:
            json.dump(cache, cf, ensure_ascii=False, indent=2)
    except Exception:
        # ignore cache write errors
        pass


def compare_versions(current: str, latest: str, pkg_type: str) -> Optional[bool]:
    """Return True if latest > current, False if not, None if unknown/uncomparable."""
    if not current or not latest:
        return None
    # PyPI: use packaging if available
    try:
        if PackagingVersion and pkg_type == 'pypi':
            try:
                return PackagingVersion(latest) > PackagingVersion(current)
            except Exception:
                pass

        # npm/maven/others: try semver if available
        if semver:
            try:
                # semver.compare returns >0 when v1>v2
                cmp = semver.compare(str(latest), str(current))
                return cmp > 0
            except Exception:
                pass

        # Fallback: loose numeric comparison of dot-separated integers
        def norm(v: str):
            parts = []
            for p in v.split('.'):
                try:
                    parts.append(int(''.join(ch for ch in p if ch.isdigit()) or 0))
                except Exception:
                    parts.append(0)
            return parts

        cur = norm(current)
        lat = norm(latest)
        # compare element-wise
        for a, b in zip(lat, cur):
            if a != b:
                return a > b
        return len(lat) > len(cur)
    except Exception:
        return None


def get_latest_npm_version(name: str) -> Optional[str]:
    url = f"https://registry.npmjs.org/{requests.utils.quote(name)}"
    try:
        resp = requests.get(url, timeout=6)
        resp.raise_for_status()
        data = resp.json()
        # dist-tags.latest ist die übliche Quelle für die aktuelle Version
        latest = data.get('dist-tags', {}).get('latest')
        if latest:
            return latest
        # Fallback: höchste in versions
        versions = data.get('versions', {})
        if versions:
            # versions keys sind Strings; wir geben den letzten lexikographisch
            return sorted(versions.keys())[-1]
        return None
    except requests.exceptions.RequestException:
        return None


def get_latest_pypi_version(name: str) -> Optional[str]:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        resp = requests.get(url, timeout=6)
        resp.raise_for_status()
        data = resp.json()
        info = data.get('info', {})
        version = info.get('version')
        if version:
            return version
        return None
    except requests.exceptions.RequestException:
        return None

def analyze_sbom(sbom_path: str, max_age_days: int, check_updates: bool = False, cache_file: Optional[str] = None):
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

    # Load persistent cache for latest-version lookups
    persistent_cache = _load_persistent_cache(cache_file) if check_updates else {}

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
                # Handle unspecified or placeholder versions
                if not version or version.lower() == "unspecified":
                    log_error(f"Maven-Version fehlt oder ist 'unspecified' für g={parsed_purl.get('group')} a={parsed_purl.get('artifact')} v={version}")
                    release_date = None
                else:
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

                    # Prüfe nur für ALARM-Fälle, ob ein Update verfügbar ist
                    try:
                        latest = None
                        if pkg_type == "pypi":
                            latest = get_latest_pypi_version(parsed_purl["name"])
                        elif pkg_type == "npm":
                            latest = get_latest_npm_version(parsed_purl["name"])
                        elif pkg_type == "maven":
                            latest = get_latest_maven_version(parsed_purl.get("group"), parsed_purl.get("artifact"))

                            if check_updates and latest and latest != version:
                                # consult persistent cache key
                                cache_key = f"latest:{pkg_type}:{parsed_purl.get('group') or parsed_purl.get('name')}:{parsed_purl.get('artifact') or ''}"
                                # if cached result exists, use it
                                cached = persistent_cache.get(cache_key)
                                if cached and cached.get('latest') == latest:
                                    newer = cached.get('newer')
                                else:
                                    newer = compare_versions(version, latest, pkg_type)
                                    persistent_cache[cache_key] = {'latest': latest, 'newer': newer}

                                # only print update if latest > current (newer == True) or unknown but different
                                if newer is True or (newer is None and latest != version):
                                    print(f"UPDATE_AVAILABLE: {purl} -> latest: {latest} (aktuell: {version})")
                    except Exception:
                        # Nicht kritisch, nur Info-Versuche
                        pass

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

    parser.add_argument(
        "--check-updates",
        action="store_true",
        help="Wenn gesetzt, prüft das Skript zusätzlich, ob für ALARM-Komponenten neuere Versionen in den Registries vorliegen."
    )

    parser.add_argument(
        "--cache-file",
        default=".sbom-check-cache.json",
        help="Datei, in der Lookup-Ergebnisse (z.B. gefundene neueste Versionen) zwischengespeichert werden.")
    
    args = parser.parse_args()
    
    if args.age <= 0:
        log_error("--age muss ein positiver Integer sein.")
        sys.exit(1)
        
    analyze_sbom(args.sbom, args.age, check_updates=args.check_updates, cache_file=(args.cache_file if args.check_updates else None))

    # Wenn Update-Checks aktiv und Cache-File angegeben, persistieren wir den Cache
    if args.check_updates and args.cache_file:
        # persistent cache wurde im analyze_sbom geladen und gefüllt; lade & save (defensive)
        # _save_persistent_cache wird in analyze_sbom am Ende aufgerufen, aber wir rufen es hier nochmal sicherheitshalber
        try:
            # Re-load to merge possible in-memory modifications
            # (analyze_sbom nutzt interne Variable; to keep it simple we re-run save with same file)
            _save_persistent_cache(args.cache_file, _load_persistent_cache(args.cache_file))
        except Exception:
            pass

if __name__ == "__main__":
    main()