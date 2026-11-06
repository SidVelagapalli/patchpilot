# PatchPilot

A scheduled GitHub Action that finds pinned dependencies (`requirements.txt`, `package-lock.json`, CDN script
tags in HTML), checks them against [OSV.dev](https://osv.dev), ranks CISA Known-Exploited ones as P0, and files
GitHub issues **only after a human approves**.

## How it works
Two workflows, so nothing writes to GitHub until a person has read the findings:

| Workflow | Runs | Can write? | Does |
|---|---|---|---|
| `PatchPilot: scan` | every Monday + manual | no (`contents: read`) | `patchpilot scan`, uploads `report.json`, lists what *would* be filed on the run's summary page |
| `PatchPilot: file issues` | only when you click "Run workflow" | `issues: write` (+ `actions: read` for the report) | checks the run ID is a real scan run, downloads its report, `patchpilot file-issues --apply` |

- Re-runs never duplicate an issue: they dedupe by advisory id.
- Advisory text goes in a code block and other fields in inline code, so nothing in an advisory can @mention anyone.
- Summaries come from a free template. `--llm` (with `--apply` and `ANTHROPIC_API_KEY`) switches to paid LLM summaries (Anthropic API).

Why not a GitHub Environment with required reviewers? Those only work on public repos on the Free plan, and
shraddha-store is private, so the gate is the manual trigger instead.

## Use it on your repo
The workflows live in [`examples/`](examples/), **not** in this repo's `.github/workflows/`, so they never run here.
1. Copy `examples/patchpilot-scan.yml` and `examples/patchpilot-file-issues.yml` into the target repo's
   `.github/workflows/` (e.g. shraddha-store).
2. In both, replace `REPLACE_WITH_PATCHPILOT_COMMIT_SHA` with the full SHA of the PatchPilot commit you reviewed.
   Until you do, the install step fails on purpose.
3. Each Monday: open the scan run, read its summary, copy its run ID, then Actions -> "PatchPilot: file issues" ->
   Run workflow -> paste the ID.

## Run locally
```
uv run pytest
uv run patchpilot scan --path /tmp/demo --out /tmp/demo/report.json
uv run patchpilot file-issues --report /tmp/demo/report.json --repo owner/name   # dry run
```
