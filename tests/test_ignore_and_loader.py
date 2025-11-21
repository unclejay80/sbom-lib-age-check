import importlib.util
import os
from importlib.machinery import SourceFileLoader
import tempfile
import yaml


def load_module():
    path = os.path.join(os.path.dirname(__file__), '..', 'sbom-check.py')
    path = os.path.abspath(path)
    loader = SourceFileLoader('sbom_check', path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_load_ignore_file_and_match():
    mod = load_module()
    data = [
        'pkg:maven/com.example/lib-example@1.0.0',
        {'purl_regex': '^pkg:maven/com\\.example\\.lib.*', 'reason': 'test'}
    ]
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.yaml') as f:
        yaml.safe_dump(data, f)
        fname = f.name
    try:
        entries = mod._load_ignore_file(fname)
        assert len(entries) == 2
        parsed = mod.parse_purl('pkg:maven/com.example/lib-example@1.0.0')
        match = mod._is_ignored('pkg:maven/com.example/lib-example@1.0.0', parsed, entries)
        assert match is not None
        assert match.get('purl') == 'pkg:maven/com.example/lib-example@1.0.0'
    finally:
        os.unlink(fname)
