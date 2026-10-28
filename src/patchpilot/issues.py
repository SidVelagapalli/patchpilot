"""Step 2 of the pipeline: file one GitHub issue per finding. This is the only step that WRITES,
so in the GitHub Action it runs in a separate job behind a human approval gate."""

import os

import httpx

from patchpilot.summarize import summarize

API = "https://api.github.com"
LABELS = {"patchpilot": "5319e7", "security": "d73a4a", "P0": "b60205", "P1": "d93f0b", "P2": "fbca04", "P3": "c5def5"}


def issue_title(f: dict) -> str:
    return f"[{f['priority']}] {f['id']} in {f['package']}@{f['version']}"


def issue_body(f: dict, summary: str) -> str:
    return "\n".join([
        summary, "",
        f"- **Package:** `{f['package']}` {f['version']} ({f['ecosystem']}), found in `{f['source']}`",
        f"- **Advisory:** [{f['id']}]({f['url']}) {', '.join(f['cves'])}",
        f"- **Known exploited (CISA KEV):** {'YES' if f['known_exploited'] else 'no'}",
        f"- **Fixed in:** {', '.join(f['fixed_in']) or 'no fix released'}",
        "", "_Filed by PatchPilot after human approval._",
    ])


def file_issues(report: dict, repo: str, dry_run: bool = True) -> list[str]:
    """Create issues for new findings; skip ones already open (matched by advisory id). Returns titles filed."""
    findings = report["findings"]
    if dry_run:
        for f in findings:
            print(f"--- would file: {issue_title(f)}\n{issue_body(f, summarize(f))}\n")
        return [issue_title(f) for f in findings]

    headers = {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}", "Accept": "application/vnd.github+json"}
    filed = []
    with httpx.Client(base_url=API, headers=headers, timeout=30) as gh:
        for name, color in LABELS.items():  # 422 = label already exists, which is fine
            gh.post(f"/repos/{repo}/labels", json={"name": name, "color": color})
        existing = gh.get(f"/repos/{repo}/issues", params={"labels": "patchpilot", "state": "open", "per_page": 100})
        existing.raise_for_status()
        open_titles = " ".join(i["title"] for i in existing.json())
        for f in findings:
            if f["id"] in open_titles:  # dedupe: never file the same advisory twice
                continue
            r = gh.post(f"/repos/{repo}/issues", json={"title": issue_title(f), "body": issue_body(f, summarize(f)),
                                                       "labels": ["patchpilot", "security", f["priority"]]})
            r.raise_for_status()
            filed.append(issue_title(f))
    return filed
