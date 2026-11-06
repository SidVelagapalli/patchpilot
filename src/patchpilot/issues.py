"""Step 2 of the pipeline: file one GitHub issue per finding. This is the only step that WRITES,
so in GitHub Actions it runs in its own workflow that a human triggers by hand after reading the scan's summary."""

import os
import re
import sys

import httpx

from patchpilot.summarize import summarize

API = "https://api.github.com"
LABELS = {"patchpilot": "5319e7", "security": "d73a4a", "P0": "b60205", "P1": "d93f0b", "P2": "fbca04", "P3": "c5def5"}


# Characters a real package name, version, file path or CVE id uses. No backtick, newline, < & \ [ ], so a value
# inside `code` can't break out, and @mentions inside code spans don't notify anyone.
SAFE = re.compile(r"[\w.+!~/@() -]+")


def code(value: str) -> str:
    """Repo- or OSV-supplied value as inline code; anything outside SAFE is hidden rather than rendered."""
    return f"`{value}`" if SAFE.fullmatch(value) else "`(hidden: unexpected characters)`"


def issue_title(f: dict) -> str:
    """Plain text (GitHub doesn't render titles), but the dry run shows it on the summary page, so hide unsafe values."""
    plain = [v if SAFE.fullmatch(v) else "(hidden)" for v in (f["id"], f["package"], f["version"])]
    return f"[{f['priority']}] {plain[0]} in {plain[1]}@{plain[2]}"


def fenced(text: str) -> str:
    """Advisory/LLM text is untrusted, so it goes in a code block: GitHub renders no @mentions, HTML or entities there.
    The fence is longer than any run of backticks in the text, so the text can't close the block early."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def issue_body(f: dict, summary: str) -> str:
    advisory = f"[{f['id']}]({f['url']})" if SAFE.fullmatch(f["id"]) else code(f["id"])  # id is from OSV: still check
    return "\n".join([
        fenced(summary), "",
        f"- **Package:** {code(f['package'])} {code(f['version'])} ({f['ecosystem']}), found in {code(f['source'])}",
        f"- **Advisory:** {advisory} {', '.join(code(c) for c in f['cves'])}",
        f"- **Known exploited (CISA KEV):** {'YES' if f['known_exploited'] else 'no'}",
        f"- **Fixed in:** {', '.join(code(v) for v in f['fixed_in']) or 'no fix released'}",
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
            print(f"--- would file: `{issue_title(f)}`\n{issue_body(f, summarize(f))}\n")
        return [issue_title(f) for f in findings]

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("error: GITHUB_TOKEN is not set; --apply needs it (in Actions it comes from github.token)")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    filed = []
    with httpx.Client(base_url=API, headers=headers, timeout=30) as gh:
        for name, color in LABELS.items():
            r = gh.post(f"/repos/{repo}/labels", json={"name": name, "color": color})
            if r.status_code not in (201, 422):  # 422 = label already exists, which is fine; anything else is not
                sys.exit(f"error: could not create label {name!r} in {repo} ({r.status_code}): {r.text[:200]}")
        for f in new_findings(report["findings"], open_issue_ids(gh, repo)):  # dedupe: never file the same advisory twice
            r = gh.post(f"/repos/{repo}/issues", json={"title": issue_title(f), "body": issue_body(f, summarize(f, llm)),
                                                       "labels": ["patchpilot", "security", f["priority"]]})
            if r.is_error:  # say what already went through, so a half-finished run isn't a mystery
                sys.exit(f"error: GitHub refused {issue_title(f)!r} ({r.status_code}): {r.text[:200]}\n"
                         f"Filed before this ({len(filed)}): {filed}. Re-running is safe: open issues are skipped.")
            filed.append(issue_title(f))
    return filed
