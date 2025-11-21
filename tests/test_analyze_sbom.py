import importlib.util
import os
from importlib.machinery import SourceFileLoader
from datetime import datetime, timezone, timedelta
import tempfile


def load_module():
    path = os.path.join(os.path.dirname(__file__), '..', 'sbom-check.py')
    path = os.path.abspath(path)
    loader = SourceFileLoader('sbom_check', path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_analyze_sbom_alarm_and_update(tmp_path, monkeypatch, capsys):
    mod = load_module()
    # prepare SBOM fixture path
    sbom_fixture = os.path.join(os.path.dirname(__file__), 'fixtures', 'simple_sbom.json')
    cache_file = tmp_path / 'cache.json'

    # mock release date to be old
    def fake_get_maven_release_date(group, artifact, version):
        return datetime.now(timezone.utc) - timedelta(days=400)

    def fake_get_latest_maven_version(group, artifact):
        return '2.0.0', 'mock-source'

    monkeypatch.setattr(mod, 'get_maven_release_date', fake_get_maven_release_date)
    monkeypatch.setattr(mod, 'get_latest_maven_version', fake_get_latest_maven_version)

    # run analyze_sbom with update checks
    mod.analyze_sbom(sbom_fixture, max_age_days=30, check_updates=True, cache_file=str(cache_file), max_workers=1, show_ignored=True)
    captured = capsys.readouterr()
    out = captured.out
    assert 'ALARM:' in out
    assert 'UPDATE_AVAILABLE' in out


def test_analyze_sbom_ignored(tmp_path, monkeypatch, capsys):
    mod = load_module()
    sbom_fixture = os.path.join(os.path.dirname(__file__), 'fixtures', 'simple_sbom.json')
    cache_file = tmp_path / 'cache.json'

    def fake_get_maven_release_date(group, artifact, version):
        return datetime.now(timezone.utc) - timedelta(days=400)

    def fake_get_latest_maven_version(group, artifact):
        return '2.0.0', 'mock-source'

    monkeypatch.setattr(mod, 'get_maven_release_date', fake_get_maven_release_date)
    monkeypatch.setattr(mod, 'get_latest_maven_version', fake_get_latest_maven_version)

    # create ignore file that matches the component
    ignore_file = tmp_path / 'ignore.yaml'
    ignore_file.write_text('- pkg:maven/com.example/lib-example@1.0.0\n')

    mod.analyze_sbom(sbom_fixture, max_age_days=30, check_updates=True, cache_file=str(cache_file), max_workers=1, ignore_file=str(ignore_file), show_ignored=True)
    captured = capsys.readouterr()
    out = captured.out
    assert 'ALARM:' not in out
    assert 'IGNORED:' in out
