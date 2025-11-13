#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
sbom-check.py

Analyzes a CycloneDX 1.5 SBOM (JSON) for component ages and optionally checks for newer versions.

Features:
- resilient HTTP session with retries and sensible timeouts
- Maven latest-version discovery (maven-metadata.xml, search.maven.org, Google Maven index)
- inline UPDATE_AVAILABLE appended to ALARM lines when --check-updates is used
- persistent JSON cache for latest-version lookups
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import xml.etree.ElementTree as ET

try:
    from packaging.version import Version as PackagingVersion
except Exception:
    PackagingVersion = None

try:
    import semver
except Exception:
    semver = None


def _create_session(retries: int = 4, backoff_factor: float = 1.0,
                    status_forcelist=(429, 500, 502, 503, 504)) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=retries, backoff_factor=backoff_factor, status_forcelist=status_forcelist,
                  allowed_methods=("HEAD", "GET", "OPTIONS"))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


SESSION = _create_session()

DEFAULT_TIMEOUTS = {
    'pypi': 15,
    'npm': 15,
    'maven_search': 15,
    'maven_head': 10,
    'maven_get': 20,
    'cocoapods': 15,
    'crates': 15,
}


def log_error(message: str):
    print(f"FEHLER: {message}", file=sys.stderr)


def parse_purl(purl: str) -> Optional[Dict[str, str]]:
    if not purl or not purl.startswith('pkg:'):
        log_error(f"Ungültiges oder leeres PURL-Format: {purl}")
        return None
    try:
        main_part, version_part = purl[4:].split('@', 1)
        version = version_part.split('?')[0].split('#')[0]
        parts = main_part.split('/')
        pkg_type = parts[0]

        # maven PURLs are typically 'pkg:maven/group/artifact@version'
        if pkg_type == 'maven':
            # ensure we have group and artifact
            group = ''
            artifact = ''
            if len(parts) >= 3:
                group = parts[1]
                artifact = parts[2]
            elif len(parts) == 2:
                comp = parts[1]
                if ':' in comp:
                    group, artifact = comp.split(':', 1)
                else:
                    artifact = comp
            return {'type': pkg_type, 'version': version, 'group': group, 'artifact': artifact}

        # other pkg types: join remaining parts as name (handles scoped npm etc.)
        name = '/'.join(parts[1:]) if len(parts) > 1 else ''
        return {'type': pkg_type, 'version': version, 'name': name}
    except Exception as e:
        log_error(f"PURL-Parsing fehlgeschlagen für {purl}: {e}")
        return None


def get_pypi_release_date(name: str, version: str) -> Optional[datetime]:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUTS['pypi'])
        r.raise_for_status()
        data = r.json()
        if 'urls' in data and data['urls']:
            times = [u.get('upload_time_iso_8601') for u in data['urls'] if u.get('upload_time_iso_8601')]
            if not times:
                return None
            return datetime.fromisoformat(min(times).replace('Z', '+00:00'))
        return None
    except Exception:
        return None


def get_npm_release_date(name: str, version: str) -> Optional[datetime]:
    url = f"https://registry.npmjs.org/{requests.utils.quote(name)}"
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUTS['npm'])
        r.raise_for_status()
        data = r.json()
        if 'time' in data and version in data['time']:
            return datetime.fromisoformat(data['time'][version].replace('Z', '+00:00'))
        return None
    except Exception:
        return None


def get_maven_release_date(group: str, artifact: str, version: str) -> Optional[datetime]:
    if not hasattr(get_maven_release_date, '_cache'):
        get_maven_release_date._cache = {}
    key = (group, artifact, version)
    if key in get_maven_release_date._cache:
        return get_maven_release_date._cache[key]

    # 1) search.maven.org timestamp
    try:
        search = 'https://search.maven.org/solrsearch/select'
        q = f'g:"{group}" AND a:"{artifact}" AND v:"{version}"'
        r = SESSION.get(search, params={"q": q, "rows": 1, "wt": "json"}, timeout=DEFAULT_TIMEOUTS['maven_search'])
        r.raise_for_status()
        data = r.json()
        if data.get('response', {}).get('numFound', 0) > 0:
            doc = data['response']['docs'][0]
            ts = doc.get('timestamp')
            if ts:
                dt = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
                get_maven_release_date._cache[key] = dt
                return dt
    except Exception:
        pass

    # 2) repo1.maven.org .pom HEAD/GET
    try:
        group_path = group.replace('.', '/')
        pom = f'https://repo1.maven.org/maven2/{group_path}/{artifact}/{version}/{artifact}-{version}.pom'
        h = SESSION.head(pom, timeout=DEFAULT_TIMEOUTS['maven_head'])
        if h.status_code == 200:
            lm = h.headers.get('Last-Modified')
            if lm:
                from email.utils import parsedate_to_datetime
                try:
                    dt = parsedate_to_datetime(lm)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    get_maven_release_date._cache[key] = dt
                    return dt
                except Exception:
                    pass
        g = SESSION.get(pom, timeout=DEFAULT_TIMEOUTS['maven_get'])
        if g.status_code == 200:
            lm = g.headers.get('Last-Modified')
            if lm:
                from email.utils import parsedate_to_datetime
                try:
                    dt = parsedate_to_datetime(lm)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    get_maven_release_date._cache[key] = dt
                    return dt
                except Exception:
                    pass
    except Exception:
        pass

    # 3) google maven
    try:
        # first try dl.google.com (legacy), then maven.google.com
        gpom = f'https://dl.google.com/dl/android/maven2/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom'
        h = SESSION.head(gpom, timeout=DEFAULT_TIMEOUTS['maven_head'])
        if h.status_code == 200:
            lm = h.headers.get('Last-Modified')
            if lm:
                from email.utils import parsedate_to_datetime
                try:
                    dt = parsedate_to_datetime(lm)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    get_maven_release_date._cache[key] = dt
                    return dt
                except Exception:
                    pass
        # try maven.google.com directly (hosts AndroidX artifacts)
        try:
            mgpom = f'https://maven.google.com/{group.replace(".", "/")}/{artifact}/{version}/{artifact}-{version}.pom'
            h2 = SESSION.head(mgpom, timeout=DEFAULT_TIMEOUTS['maven_head'])
            if h2.status_code == 200:
                lm = h2.headers.get('Last-Modified')
                if lm:
                    from email.utils import parsedate_to_datetime
                    try:
                        dt = parsedate_to_datetime(lm)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        get_maven_release_date._cache[key] = dt
                        return dt
                    except Exception:
                        pass
                # if no Last-Modified header, try to fetch and parse the POM for <version> info
                g2 = SESSION.get(mgpom, timeout=DEFAULT_TIMEOUTS['maven_get'])
                if g2.status_code == 200 and g2.text:
                    try:
                        root = ET.fromstring(g2.text)
                        # try to extract a date from <distributionManagement>/<snapshotRepository> not reliable; skip
                        pass
                    except Exception:
                        pass
        except Exception:
            pass

    except Exception:
        pass

    get_maven_release_date._cache[key] = None
    return None


def get_latest_maven_version(group: str, artifact: str) -> Optional[str]:
    # repo1 metadata
    try:
        group_path = group.replace('.', '/')
        meta = f'https://repo1.maven.org/maven2/{group_path}/{artifact}/maven-metadata.xml'
        r = SESSION.get(meta, timeout=DEFAULT_TIMEOUTS['maven_get'])
        if r.status_code == 200 and r.text:
            try:
                root = ET.fromstring(r.text)
                v = root.findtext('versioning/release') or root.findtext('versioning/latest')
                if v:
                    return v
                vers = root.findall('versioning/versions/version')
                if vers:
                    return vers[-1].text
            except Exception:
                pass
    except Exception:
        pass

    # search.maven.org (broader)
    try:
        search = 'https://search.maven.org/solrsearch/select'
        q = f'g:"{group}" AND a:"{artifact}"'
        r = SESSION.get(search, params={"q": q, "rows": 50, "wt": "json"}, timeout=DEFAULT_TIMEOUTS['maven_search'])
        r.raise_for_status()
        data = r.json()
        docs = data.get('response', {}).get('docs', [])
        if not docs:
            r = SESSION.get(search, params={"q": f'a:"{artifact}"', "rows": 50, "wt": "json"}, timeout=DEFAULT_TIMEOUTS['maven_search'])
            r.raise_for_status()
            data = r.json()
            docs = data.get('response', {}).get('docs', [])
        candidates = []
        for d in docs:
            for k in ('latestVersion', 'v', 'version'):
                if k in d and d[k]:
                    candidates.append(str(d[k]))
        if candidates:
            uniq = sorted(set(candidates))
            try:
                if semver:
                    uniq = sorted(uniq, key=lambda v: semver.VersionInfo.parse(v))
                return uniq[-1]
            except Exception:
                return uniq[-1]
    except Exception:
        pass

    # google index
    try:
        base = f'https://dl.google.com/dl/android/maven2/{group.replace('.', '/')}/{artifact}/'
        r = SESSION.get(base, timeout=DEFAULT_TIMEOUTS['maven_search'])
        if r.status_code == 200 and r.text:
            import re
            vers = set(re.findall(r'href="([0-9A-Za-z\.\-]+)/"', r.text))
            vers = [v.rstrip('/') for v in vers if v]
            if vers:
                uniq = sorted(set(vers))
                try:
                    if semver:
                        uniq = sorted(uniq, key=lambda v: semver.VersionInfo.parse(v))
                    return uniq[-1]
                except Exception:
                    return uniq[-1]
    except Exception:
        pass

    # try maven.google.com metadata or directory listing as a final fallback
    try:
        group_path = group.replace('.', '/')
        meta = f'https://maven.google.com/{group_path}/{artifact}/maven-metadata.xml'
        rmeta = SESSION.get(meta, timeout=DEFAULT_TIMEOUTS['maven_get'])
        if rmeta.status_code == 200 and rmeta.text:
            try:
                root = ET.fromstring(rmeta.text)
                v = root.findtext('versioning/release') or root.findtext('versioning/latest')
                if v:
                    return v
                vers = root.findall('versioning/versions/version')
                if vers:
                    return vers[-1].text
            except Exception:
                pass
        # directory listing on maven.google.com (HTML) — parse anchors
        base2 = f'https://maven.google.com/{group_path}/{artifact}/'
        r2 = SESSION.get(base2, timeout=DEFAULT_TIMEOUTS['maven_search'])
        if r2.status_code == 200 and r2.text:
            import re
            vers = set(re.findall(r'href="([0-9A-Za-z\.\-]+)/"', r2.text))
            vers = [v.rstrip('/') for v in vers if v]
            if vers:
                uniq = sorted(set(vers))
                try:
                    if semver:
                        uniq = sorted(uniq, key=lambda v: semver.VersionInfo.parse(v))
                    return uniq[-1]
                except Exception:
                    return uniq[-1]
    except Exception:
        pass

    return None

    

    


def get_latest_npm_version(name: str) -> Optional[str]:
    url = f"https://registry.npmjs.org/{requests.utils.quote(name)}"
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUTS['npm'])
        r.raise_for_status()
        data = r.json()
        latest = data.get('dist-tags', {}).get('latest')
        if latest:
            return latest
        versions = data.get('versions', {})
        if versions:
            return sorted(versions.keys())[-1]
        return None
    except Exception:
        return None


def get_latest_pypi_version(name: str) -> Optional[str]:
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUTS['pypi'])
        r.raise_for_status()
        data = r.json()
        return data.get('info', {}).get('version')
    except Exception:
        return None


def get_latest_cocoapods_version(name: str) -> Optional[str]:
    """Query CocoaPods Trunk API to list versions and return the newest one."""
    if not name:
        return None
    url = f'https://trunk.cocoapods.org/api/v1/pods/{name}'
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUTS['cocoapods'])
        r.raise_for_status()
        data = r.json()
        versions = [v.get('name') for v in data.get('versions', []) if v.get('name')]
        if not versions:
            return None
        # prefer semver if available
        try:
            if semver:
                versions = sorted(set(versions), key=lambda v: semver.VersionInfo.parse(v))
                return versions[-1]
        except Exception:
            pass
        return sorted(set(versions))[-1]
    except Exception:
        return None


def get_cocoapods_release_date(name: str, version: str) -> Optional[datetime]:
    """Return release date for a CocoaPod version using Trunk API entries."""
    if not name or not version:
        return None
    url = f'https://trunk.cocoapods.org/api/v1/pods/{name}'
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUTS['cocoapods'])
        r.raise_for_status()
        data = r.json()
        for v in data.get('versions', []):
            if v.get('name') == version:
                created = v.get('created_at') or v.get('created')
                if created:
                    # Trunk uses 'YYYY-MM-DD HH:MM:SS UTC'
                    try:
                        dt = datetime.strptime(created.split(' ')[0], '%Y-%m-%d').replace(tzinfo=timezone.utc)
                        return dt
                    except Exception:
                        try:
                            # fallback to full parse
                            dt = datetime.fromisoformat(created.replace(' UTC', '+00:00'))
                            return dt
                        except Exception:
                            return None
        return None
    except Exception:
        return None


def get_latest_crates_version(name: str) -> Optional[str]:
    """Query crates.io for crate metadata and return latest version."""
    if not name:
        return None
    url = f'https://crates.io/api/v1/crates/{name}'
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUTS['crates'])
        r.raise_for_status()
        data = r.json()
        raw_versions = data.get('versions', [])
        if not raw_versions:
            return None

        # prefer non-yanked releases
        candidates = [v.get('num') for v in raw_versions if v.get('num') and not v.get('yanked')]
        if not candidates:
            # fall back to any version (including yanked)
            candidates = [v.get('num') for v in raw_versions if v.get('num')]
        candidates = list(set([c for c in candidates if c]))
        if not candidates:
            return None

        # sorting key: prefer semver if available, else packaging, else numeric-dot fallback
        def version_key(s: str):
            if semver:
                try:
                    return (0, semver.VersionInfo.parse(s))
                except Exception:
                    pass
            if PackagingVersion:
                try:
                    return (1, PackagingVersion(s))
                except Exception:
                    pass
            # numeric-dot fallback: convert segments to ints where possible
            parts = []
            for p in s.split('.'):
                num = ''.join(ch for ch in p if ch.isdigit())
                try:
                    parts.append(int(num) if num != '' else 0)
                except Exception:
                    parts.append(0)
            return (2, tuple(parts))

        try:
            candidates.sort(key=version_key)
            return candidates[-1]
        except Exception:
            return sorted(candidates)[-1]
    except Exception:
        return None


def get_crates_release_date(name: str, version: str) -> Optional[datetime]:
    """Get the created_at date for a specific crates.io version."""
    if not name or not version:
        return None
    url = f'https://crates.io/api/v1/crates/{name}/versions'
    try:
        r = SESSION.get(url, timeout=DEFAULT_TIMEOUTS['crates'])
        r.raise_for_status()
        data = r.json()
        for v in data.get('versions', []):
            if v.get('num') == version:
                created = v.get('created_at')
                if created:
                    try:
                        dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        return dt
                    except Exception:
                        return None
        return None
    except Exception:
        return None


def _load_persistent_cache(cache_file: str) -> Dict[str, Any]:
    if not cache_file:
        return {}
    try:
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as cf:
                return json.load(cf)
    except Exception:
        pass
    return {}


def _save_persistent_cache(cache_file: str, cache: Dict[str, Any]):
    if not cache_file:
        return
    try:
        with open(cache_file, 'w', encoding='utf-8') as cf:
            json.dump(cache, cf, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _make_release_cache_key(pkg_type: str, parsed: Dict[str, str]) -> str:
    # key: release:{pkg_type}:{name or group}:{artifact or ''}:{version}
    if pkg_type == 'maven':
        return f"release:{pkg_type}:{parsed.get('group') or ''}:{parsed.get('artifact') or ''}:{parsed.get('version') or ''}"
    return f"release:{pkg_type}:{parsed.get('name') or ''}::{parsed.get('version') or ''}"


def compare_versions(current: str, latest: str, pkg_type: str) -> Optional[bool]:
    if not current or not latest:
        return None
    try:
        if PackagingVersion and pkg_type == 'pypi':
            try:
                return PackagingVersion(latest) > PackagingVersion(current)
            except Exception:
                pass
        if semver:
            try:
                cmp = semver.compare(str(latest), str(current))
                return cmp > 0
            except Exception:
                pass
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
        for a, b in zip(lat, cur):
            if a != b:
                return a > b
        return len(lat) > len(cur)
    except Exception:
        return None


def analyze_sbom(sbom_path: str, max_age_days: int, check_updates: bool = False, cache_file: Optional[str] = None, max_workers: int = 6):
    try:
        with open(sbom_path, 'r', encoding='utf-8') as f:
            sbom = json.load(f)
    except FileNotFoundError:
        log_error(f"SBOM-Datei nicht gefunden: {sbom_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        log_error(f"SBOM-Datei konnte nicht als JSON geparst werden: {sbom_path}")
        sys.exit(1)
    except Exception as e:
        log_error(f"Fehler beim Lesen der SBOM-Datei {sbom_path}: {e}")
        sys.exit(1)

    components = sbom.get('components', [])
    if not components:
        print('Keine Komponenten in der SBOM gefunden.', file=sys.stderr)
        return

    now = datetime.now(timezone.utc)
    found_vuln = False
    persistent_cache = _load_persistent_cache(cache_file) if check_updates else {}

    # transient in-memory caches for this run
    transient_latest_cache: Dict[str, str] = {}
    transient_release_cache: Dict[str, Optional[datetime]] = {}

    # build list of components to fetch release dates for
    work_items: list[Tuple[str, Dict[str, str], str]] = []  # (purl, parsed, pkg_type)
    for comp in components:
        purl = comp.get('purl')
        if not purl:
            continue
        parsed = parse_purl(purl)
        if not parsed:
            continue
        pkg_type = parsed['type']
        work_items.append((purl, parsed, pkg_type))

    # helper to fetch release date with cache
    def fetch_release(item: Tuple[str, Dict[str, str], str]) -> Tuple[str, Optional[datetime], Dict[str, str]]:
        purl, parsed, pkg_type = item
        cache_key = _make_release_cache_key(pkg_type, parsed)
        # check persistent cache first
        if check_updates and cache_file:
            cached = persistent_cache.get(cache_key)
            if cached and cached.get('date'):
                try:
                    return purl, datetime.fromisoformat(cached['date']), parsed
                except Exception:
                    pass
        # transient release cache
        if cache_key in transient_release_cache:
            return purl, transient_release_cache[cache_key], parsed
        # perform lookup
        version = parsed.get('version')
        rd = None
        try:
            if pkg_type == 'pypi':
                rd = get_pypi_release_date(parsed.get('name'), version)
            elif pkg_type == 'npm':
                rd = get_npm_release_date(parsed.get('name'), version)
            elif pkg_type == 'cocoapods':
                rd = get_cocoapods_release_date(parsed.get('name'), version)
            elif pkg_type == 'cargo':
                rd = get_crates_release_date(parsed.get('name'), version)
            elif pkg_type == 'maven':
                if not version or version.lower() == 'unspecified':
                    log_error(f"Maven-Version fehlt oder ist 'unspecified' für g={parsed.get('group')} a={parsed.get('artifact')} v={version}")
                else:
                    rd = get_maven_release_date(parsed.get('group'), parsed.get('artifact'), version)
        except Exception:
            rd = None

        if rd and rd.tzinfo is None:
            rd = rd.replace(tzinfo=timezone.utc)

        transient_release_cache[cache_key] = rd
        # persist release date if requested
        if check_updates and cache_file:
            try:
                persistent_cache[cache_key] = {'date': rd.isoformat() if rd else None}
            except Exception:
                pass
        return purl, rd, parsed

    # fetch release dates in parallel
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fetch_release, it): it for it in work_items}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception:
                pass

    # collect ALARM candidates
    alarms = []  # (purl, parsed, release_date, age_days)
    for purl, rd, parsed in results:
        if not rd:
            continue
        age_days = (now - rd).days
        if age_days > max_age_days:
            alarms.append((purl, parsed, rd, age_days))

    # fetch latest versions for alarm items in parallel
    def fetch_latest_for_alarm(alarm_item):
        purl, parsed, rd, age_days = alarm_item
        pkg_type = parsed['type']
        version = parsed.get('version')
        latest = None
        cache_key = None
        try:
            if pkg_type == 'pypi':
                cache_key = f"latest:{pkg_type}:{parsed.get('name')}"
                latest = transient_latest_cache.get(cache_key) or persistent_cache.get(cache_key, {}).get('latest')
                if not latest:
                    latest = get_latest_pypi_version(parsed.get('name'))
            elif pkg_type == 'npm':
                cache_key = f"latest:{pkg_type}:{parsed.get('name')}"
                latest = transient_latest_cache.get(cache_key) or persistent_cache.get(cache_key, {}).get('latest')
                if not latest:
                    latest = get_latest_npm_version(parsed.get('name'))
            elif pkg_type == 'maven':
                lookup_name = f"{parsed.get('group') or ''}:{parsed.get('artifact') or ''}"
                cache_key = f"latest:{pkg_type}:{lookup_name}"
                latest = transient_latest_cache.get(cache_key) or persistent_cache.get(cache_key, {}).get('latest')
                if not latest:
                    latest = get_latest_maven_version(parsed.get('group'), parsed.get('artifact'))
            elif pkg_type == 'cocoapods':
                cache_key = f"latest:{pkg_type}:{parsed.get('name')}"
                latest = transient_latest_cache.get(cache_key) or persistent_cache.get(cache_key, {}).get('latest')
                if not latest:
                    latest = get_latest_cocoapods_version(parsed.get('name'))
            elif pkg_type == 'cargo':
                cache_key = f"latest:{pkg_type}:{parsed.get('name')}"
                latest = transient_latest_cache.get(cache_key) or persistent_cache.get(cache_key, {}).get('latest')
                if not latest:
                    latest = get_latest_crates_version(parsed.get('name'))
        except Exception:
            latest = None

        if latest and cache_key:
            transient_latest_cache[cache_key] = latest
            cached = persistent_cache.get(cache_key)
            if not (cached and cached.get('latest') == latest):
                try:
                    newer = compare_versions(parsed.get('version'), latest, parsed.get('type'))
                except Exception:
                    newer = None
                persistent_cache[cache_key] = {'latest': latest, 'newer': newer}

        return (purl, parsed, rd, age_days, latest)

    latest_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(fetch_latest_for_alarm, a): a for a in alarms}
        for fut in as_completed(futures):
            try:
                latest_results.append(fut.result())
            except Exception:
                pass

    # print alarms with inline update info
    for purl, parsed, rd, age_days, latest in latest_results:
        found_vuln = True
        alarm = f"ALARM: {purl} | VÖ: {rd.date().isoformat()} | Alter: {age_days} Tage (Limit: {max_age_days} Tage)"
        if latest and latest != parsed.get('version'):
            newer = persistent_cache.get(f"latest:{parsed.get('type')}:{parsed.get('name')}", {}).get('newer')
            if newer is True or (newer is None and latest != parsed.get('version')):
                alarm += f" | UPDATE_AVAILABLE: latest: {latest} (aktuell: {parsed.get('version')})"
        print(alarm)

    if not found_vuln:
        print(f"Analyse abgeschlossen. Keine Komponenten älter als {max_age_days} Tage gefunden.", file=sys.stderr)
    else:
        if check_updates and cache_file:
            _save_persistent_cache(cache_file, persistent_cache)
    # always save persistent cache if requested (also when found_vuln True)
    if check_updates and cache_file:
        try:
            _save_persistent_cache(cache_file, persistent_cache)
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Analysiert eine CycloneDX 1.5 SBOM auf veraltete Komponenten.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("--sbom", required=True, help="Der Dateipfad zur CycloneDX 1.5 JSON-Datei.")
    parser.add_argument("--age", required=True, type=int, help="Das maximal zulässige Alter einer Komponente in Tagen (z. B. 90).")
    parser.add_argument("--check-updates", action="store_true", help="Wenn gesetzt, prüft das Skript zusätzlich, ob für ALARM-Komponenten neuere Versionen in den Registries vorliegen.")
    parser.add_argument("--cache-file", default=".sbom-check-cache.json", help="Datei, in der Lookup-Ergebnisse (z.B. gefundene neueste Versionen) zwischengespeichert werden.")
    parser.add_argument("--max-workers", type=int, default=6, help="Maximale Anzahl paralleler Worker für Registry-Anfragen.")

    args = parser.parse_args()
    if args.age <= 0:
        log_error("--age muss ein positiver Integer sein.")
        sys.exit(1)

    analyze_sbom(args.sbom, args.age, check_updates=args.check_updates, cache_file=(args.cache_file if args.check_updates else None), max_workers=args.max_workers)

    # ensure cache persisted
    if args.check_updates and args.cache_file:
        try:
            _save_persistent_cache(args.cache_file, _load_persistent_cache(args.cache_file))
        except Exception:
            pass

if __name__ == "__main__":
    main()