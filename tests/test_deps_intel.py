"""Offline tests for parsing, ranking and issue text. No network."""

from patchpilot.deps import find_dependencies, parse_html_cdn, parse_package_lock, parse_requirements
from patchpilot.intel import fixed_versions, priority


def test_requirements_only_pinned():
    assert parse_requirements("jinja2==2.4.1\nrequests>=2\n# c\nflask[async]==0.12  # old") == [("jinja2", "2.4.1"), ("flask", "0.12")]


def test_package_lock_v3():
    lock = '{"packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}, "node_modules/@a/b": {"version": "1.0.0"}}}'
    assert parse_package_lock(lock) == [("lodash", "4.17.15"), ("@a/b", "1.0.0")]


def test_html_cdn_scoped_and_cdnjs():
    html = ('<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.39.0/dist/umd/supabase.min.js"></script>'
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>')
    assert parse_html_cdn(html) == [("@supabase/supabase-js", "2.39.0"), ("jquery", "3.4.1")]


def test_find_dependencies_dedupes(tmp_path):
    page = '<script src="https://unpkg.com/lodash@4.17.15/lodash.js"></script>'
    (tmp_path / "a.html").write_text(page)
    (tmp_path / "b.html").write_text(page)
    deps = find_dependencies(tmp_path)
    assert len(deps) == 1 and deps[0]["ecosystem"] == "npm"


def test_fixed_versions():
    vuln = {"affected": [{"package": {"name": "lodash"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
    assert fixed_versions(vuln, "lodash") == ["4.17.21"]


def test_priority_kev_beats_severity():
    assert priority(["CVE-2021-1"], {"CVE-2021-1"}, "LOW") == "P0"
    assert priority(["CVE-2021-2"], set(), "HIGH") == "P1"
    assert priority([], set(), None) == "P3"
