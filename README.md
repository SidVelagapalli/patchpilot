# PatchPilot

A scheduled GitHub Action that finds pinned dependencies (`requirements.txt`, `package-lock.json`, CDN script
tags in HTML), checks them against [OSV.dev](https://osv.dev), ranks CISA Known-Exploited ones as P0, and files
GitHub issues **only after a human approves**.

## How it works
1. **scan** (read-only): `patchpilot scan --path . --out report.json`
2. **file-issues** (writes, behind the `patchpilot-approval` environment):
   `patchpilot file-issues --report report.json --repo owner/name --apply`.
   Without `--apply` it is a dry run. Re-runs never duplicate an issue: they dedupe by advisory id.
   Summaries come from a free template. `--llm` (with `--apply` and `ANTHROPIC_API_KEY`) switches to paid LLM summaries (Anthropic API).

## Use it on your repo
The workflow lives in [`examples/patchpilot.yml`](examples/patchpilot.yml), **not** in this repo's
`.github/workflows/`, so it never runs here. To use it:
1. Copy it into the target repo as `.github/workflows/patchpilot.yml` (e.g. shraddha-store).
2. In the target repo, go to Settings -> Environments, create `patchpilot-approval`, and add yourself as a required reviewer.
   Do this **before** the first run. Otherwise GitHub auto-creates the environment with no reviewers.

## Run locally
```
uv run pytest
uv run patchpilot scan --path /tmp/demo --out /tmp/demo/report.json
uv run patchpilot file-issues --report /tmp/demo/report.json --repo owner/name   # dry run
```
