# sbom-check

This repository contains a small Python CLI tool, `sbom-check.py`, which analyzes CycloneDX (JSON) SBOMs, determines the release date of components, and emits an ALARM line for components whose last release is older than a configurable number of days.

Key features
- Supported registries: crates.io (Cargo), npm, PyPI, Maven Central / Google Maven, CocoaPods.
- Optional update check: with `--check-updates` the tool queries the respective registries for newer versions of components that are flagged as ALARM.
- Parallelized: registry queries run in parallel using a configurable worker count (`--max-workers`).
- Persistent cache: results (latest versions and release dates) are stored in a JSON cache file to avoid repeated requests.

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
python3 sbom-check.py --sbom sbom-all-v1_5_web.json --age 30 --check-updates --max-workers 6 --cache .sbom-check-cache.json
```

CLI flags (important)
- `--sbom PATH`  : Path to the CycloneDX JSON SBOM (v1.5)
- `--age N`      : Age threshold in days (components whose latest release is older will be listed as ALARM)
- `--check-updates`: If set, the tool checks whether newer versions are available for ALARM components
- `--max-workers N`: Number of parallel workers for registry queries (4-8 recommended for large SBOMs)
- `--cache PATH` : Path to the persistent cache file (default: `.sbom-check-cache.json`)

Output format
The tool writes lines to stdout using this pattern:

ALARM: <purl>@<version> | Released: <release-date> | Age: <n> days (Limit: <age> days) | UPDATE_AVAILABLE: latest: <x.y.z> (current: <a.b.c>)

Notes
- The first run on a large SBOM can trigger many HTTP requests and take several minutes. The persistent cache reduces repeated load on subsequent runs.
- Some registries provide pre-releases or RCs; the tool attempts reasonable choices but results may vary across ecosystems.
