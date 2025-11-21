# sbom-check

This repository contains a small Python CLI tool, `sbom-check.py`, which analyzes CycloneDX (JSON) SBOMs, determines the release date of components, and emits an ALARM line for components whose last release is older than a configurable number of days.

Key features
- Supported registries: crates.io (Cargo), npm, PyPI, Maven Central / Google Maven, CocoaPods.
- Optional update check: with `--check-updates` the tool queries the respective registries for newer versions of components that are flagged as ALARM.
- Parallelized: registry queries run in parallel using a configurable worker count (`--max-workers`).
- Persistent cache: results (latest versions and release dates) are stored in a JSON cache file to avoid repeated requests.
- Robust Maven lookup: Google Maven (dl.google.com / maven.google.com) is now prioritized for `com.google*` and `androidx*` groups to avoid noisy artifact-only matches from other groups.
- Heuristic validation of "latest" versions: the script suppresses clearly noisy version strings (non-numeric) unless the candidate's release date can be validated as newer than the current release.
- Source auditing: the persistent cache records the source used to find a `latest` (e.g. `repo1`, `google-meta`, `central-fallback`) and ALARM lines show `[source=...]` when available.
- Manifest overlay & manifest parsers: use `--manifest <path>` + `--manifest-overlay` to restrict checks to direct dependencies from manifests. Supported manifests include `package.json`, `Cargo.toml` (workspace-aware), `pyproject.toml`, `requirements.txt`, `Podfile.lock`, and Gradle `build.gradle` heuristics.
- crates.io and CocoaPods support added; parallelized checks and persistent cache were extended to these ecosystems.

Requirements
- Python 3.8+ (3.10+ recommended)

Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Quick start / Examples
- A quick run (only age check, default cache):

```bash
python3 sbom-check.py --sbom sbom-all-v1_5_web.json --age 30
```

- With update checking, a cache file and 6 parallel workers:

```bash
python3 sbom-check.py --sbom sbom-all-v1_5_web.json --age 30 --check-updates --max-workers 6 --cache-file .sbom-check-cache.json
```

CLI flags (important)
- `--sbom PATH`  : Path to the CycloneDX JSON SBOM (v1.5)
- `--age N`      : Age threshold in days (components whose latest release is older will be listed as ALARM)
- `--check-updates`: If set, the tool checks whether newer versions are available for ALARM components
- `--max-workers N`: Number of parallel workers for registry queries (4-8 recommended for large SBOMs)
 - `--cache-file PATH` : Path to the persistent cache file (default: `.sbom-check-cache.json`)
 - `--ignore-file PATH` : Path to a YAML ignore file. See examples below.
 - `--show-ignored` : When set, the tool will print a summary of findings that matched the ignore file.

Examples (Android project)

```bash
# check Android SBOM and only consider direct manifest deps from an Android project root
python3 sbom-check.py --sbom sbom-all-v1_5_android.json --age 300 --manifest /path/to/android/project --manifest-overlay --check-updates --max-workers 10 --cache-file .sbom-check-cache.json
```

Ignore file examples

Create a YAML file (for example `.sbom-ignore.yaml`) to suppress certain findings. The ignore file supports either a simple list of PURLs or structured entries with optional `reason` and `until` (expiry) fields.

Simple PURL list:

```yaml
- pkg:maven/com.google.android.gms/play-services-location@17.0.0
- pkg:cargo/serde@1.0.130
```

Structured entries (with reason and expiry):

```yaml
- purl: pkg:maven/com.example/some-lib@1.2.3
	reason: 'In-house fork - ignore until upstream fixes CVE-1234'
	until: '2026-01-31'
- purl_regex: '^pkg:maven/com\\.google\\.android\\.gms/.*'
	reason: 'Ignore group-wide play-services variants temporarily'
```

To run while showing which items were ignored:

```bash
python3 sbom-check.py --sbom sbom-all-v1_5_android.json --age 30 --check-updates --ignore-file .sbom-ignore.yaml --show-ignored
```

Notes on behavior

- The manifest overlay attempts to extract direct dependencies from common manifest files. Gradle parsing is heuristic; for authoritative direct dependencies prefer generating a CycloneDX SBOM from Gradle or using the Gradle CycloneDX plugin.
- The cache stores keys like `latest:maven:group:artifact` and includes a `source` field to help you audit which registry produced the `latest` value.
- You can control the strictness of update detection by inspecting the cache and re-running with an empty cache if you want a fresh lookup.

Output format
The tool writes lines to stdout using this pattern:

ALARM: <purl>@<version> | Released: <release-date> | Age: <n> days (Limit: <age> days) | UPDATE_AVAILABLE: latest: <x.y.z> (current: <a.b.c>)

Notes
- The first run on a large SBOM can trigger many HTTP requests and take several minutes. The persistent cache reduces repeated load on subsequent runs.
- Some registries provide pre-releases or RCs; the tool attempts reasonable choices but results may vary across ecosystems.
