"""patchpilot scan --path . --out report.json
patchpilot file-issues --report report.json --repo owner/name [--apply] [--llm]   (without --apply = dry run)"""

import argparse
import json
import os
import sys

import httpx

from patchpilot.issues import file_issues
from patchpilot.summarize import MODEL_ENV
from patchpilot.scan import scan


def main():
    p = argparse.ArgumentParser(prog="patchpilot")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--path", default=".")
    s.add_argument("--out", default="report.json")
    i = sub.add_parser("file-issues")
    i.add_argument("--report", default="report.json")
    i.add_argument("--repo", required=True)
    i.add_argument("--apply", action="store_true", help="actually create issues (default: dry run)")
    i.add_argument("--llm", action="store_true", help="with --apply: LLM summaries via the Anthropic API (paid; needs ANTHROPIC_API_KEY and PATCHPILOT_MODEL)")
    args = p.parse_args()

    if args.cmd == "scan":
        try:
            report = scan(args.path)
        except (httpx.HTTPError, ValueError, KeyError) as e:  # OSV/CISA down, slow or sending garbage: no traceback
            sys.exit(f"error: scan failed: {type(e).__name__}: {e}\n"
                     f"Usually OSV.dev or CISA KEV is down or sent bad data. Nothing was written.")
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
        counts = {}
        for f_ in report["findings"]:
            counts[f_["priority"]] = counts.get(f_["priority"], 0) + 1
        for w in report["warnings"]:
            print(f"warning: {w}", file=sys.stderr)
        print(f"{report['dependencies']} dependencies, {len(report['findings'])} findings {counts} -> {args.out}")
    else:
        with open(args.report) as f:
            report = json.load(f)
        llm = None
        if args.llm and not os.environ.get(MODEL_ENV):
            sys.exit(f"error: --llm needs {MODEL_ENV} set to an Anthropic model ID")
        if args.llm and args.apply:  # dry runs stay free even with --llm
            import anthropic
            llm = anthropic.Anthropic()
        elif args.llm:
            print("note: --llm ignored on a dry run (template summaries are free)", file=sys.stderr)
        filed = file_issues(report, args.repo, dry_run=not args.apply, llm=llm)
        print(f"{'filed' if args.apply else 'dry run'}: {len(filed)} issue(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
