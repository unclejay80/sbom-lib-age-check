import importlib.util
import os
from importlib.machinery import SourceFileLoader


def load_module():
    path = os.path.join(os.path.dirname(__file__), '..', 'sbom-check.py')
    path = os.path.abspath(path)
    loader = SourceFileLoader('sbom_check', path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_parse_purl_basic():
    mod = load_module()
    p = 'pkg:maven/com.google.guava/guava@31.0.1'
    parsed = mod.parse_purl(p)
    assert parsed['type'] == 'maven'
    assert parsed['group'] == 'com.google.guava' or parsed['group'] == 'com.google.guava'
    assert parsed['artifact'] == 'guava'
    assert parsed['version'] == '31.0.1'

    p2 = 'pkg:npm/%40scope%2Fname/package@2.0.0'
    parsed2 = mod.parse_purl(p2)
    assert parsed2['type'] == 'npm'
    assert parsed2['name'] == '@scope/name/package'
    assert parsed2['version'] == '2.0.0'


def test_is_semver_like():
    mod = load_module()
    assert mod._is_semver_like('1.2.3')
    assert mod._is_semver_like('33.5.0-jre')
    assert not mod._is_semver_like('momo5.1f.medialive.20210427105401')
