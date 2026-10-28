"""patchpilot scan --path . --out report.json
patchpilot file-issues --report report.json --repo owner/name [--apply]   (without --apply = dry run)"""

import argparse
import json
import sys

from patchpilot.issues import file_issues
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
    args = p.parse_args()

    if args.cmd == "scan":
        report = scan(args.path)
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
        counts = {}
        for f_ in report["findings"]:
            counts[f_["priority"]] = counts.get(f_["priority"], 0) + 1
        print(f"{report['dependencies']} dependencies, {len(report['findings'])} findings {counts} -> {args.out}")
    else:
        with open(args.report) as f:
            report = json.load(f)
        filed = file_issues(report, args.repo, dry_run=not args.apply)
        print(f"{'filed' if args.apply else 'dry run'}: {len(filed)} issue(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
