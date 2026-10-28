"""Offline test for issue filing: dry run only, no network."""

from patchpilot.issues import file_issues, issue_title


def test_dry_run_files_nothing(capsys):
    f = {"id": "GHSA-x", "cves": [], "package": "lodash", "version": "4.17.15", "ecosystem": "npm", "source": "a.html",
         "summary": "Prototype pollution", "severity": "HIGH", "known_exploited": False, "priority": "P1",
         "fixed_in": ["4.17.21"], "url": "https://osv.dev/vulnerability/GHSA-x"}
    titles = file_issues({"findings": [f]}, "me/repo", dry_run=True)
    assert titles == [issue_title(f)] and "Upgrade to 4.17.21" in capsys.readouterr().out
