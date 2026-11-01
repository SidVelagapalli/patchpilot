"""Step 2 of the pipeline: file one GitHub issue per finding. This is the only step that WRITES,
so in the GitHub Action it runs in a separate job behind a human approval gate."""

import os
import re

import httpx

from patchpilot.summarize import summarize

API = "https://api.github.com"
LABELS = {"patchpilot": "5319e7", "security": "d73a4a", "P0": "b60205", "P1": "d93f0b", "P2": "fbca04", "P3": "c5def5"}


def issue_title(f: dict) -> str:
    return f"[{f['priority']}] {f['id']} in {f['package']}@{f['version']}"


def fenced(text: str) -> str:
    """Advisory/LLM text is untrusted, so it goes in a code block: GitHub renders no @mentions, HTML or entities there.
    The fence is longer than any run of backticks in the text, so the text can't close the block early."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def issue_body(f: dict, summary: str) -> str:
    return "\n".join([
        fenced(summary), "",
        f"- **Package:** `{f['package']}` {f['version']} ({f['ecosystem']}), found in `{f['source']}`",
        f"- **Advisory:** [{f['id']}]({f['url']}) {', '.join(f['cves'])}",
        f"- **Known exploited (CISA KEV):** {'YES' if f['known_exploited'] else 'no'}",
        f"- **Fixed in:** {', '.join(f['fixed_in']) or 'no fix released'}",
        "", "_Filed by PatchPilot after human approval._",
    ])


def new_findings(findings: list[dict], seen: set[str]) -> list[dict]:
    """Drop findings whose advisory id is in `seen` (exact match) or already earlier in this run. Mutates `seen`."""
    out = []
    for f in findings:
        if f["id"] not in seen:
            seen.add(f["id"])
            out.append(f)
    return out


def open_issue_ids(gh: httpx.Client, repo: str) -> set[str]:
    """Advisory ids of every open patchpilot issue, across all pages. Title format: "[P1] <id> in pkg@ver"."""
    ids, page = set(), 1
    while True:
        r = gh.get(f"/repos/{repo}/issues", params={"labels": "patchpilot", "state": "open", "per_page": 100, "page": page})
        r.raise_for_status()
        batch = r.json()
        ids |= {i["title"].split()[1] for i in batch if len(i["title"].split()) > 1}
        if len(batch) < 100:
            return ids
        page += 1


def file_issues(report: dict, repo: str, dry_run: bool = True, llm=None) -> list[str]:
    """Create issues for new findings; skip ones already open (matched by advisory id). Returns titles filed.
    `llm` is an Anthropic client, used only with --apply; dry runs always use the free template."""
    if dry_run:
        findings = new_findings(report["findings"], set())
        for f in findings:
            print(f"--- would file: {issue_title(f)}\n{issue_body(f, summarize(f))}\n")
        return [issue_title(f) for f in findings]

    headers = {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}", "Accept": "application/vnd.github+json"}
    filed = []
    with httpx.Client(base_url=API, headers=headers, timeout=30) as gh:
        for name, color in LABELS.items():  # 422 = label already exists, which is fine
            gh.post(f"/repos/{repo}/labels", json={"name": name, "color": color})
        for f in new_findings(report["findings"], open_issue_ids(gh, repo)):  # dedupe: never file the same advisory twice
            r = gh.post(f"/repos/{repo}/issues", json={"title": issue_title(f), "body": issue_body(f, summarize(f, llm)),
                                                       "labels": ["patchpilot", "security", f["priority"]]})
            r.raise_for_status()
            filed.append(issue_title(f))
    return filed
