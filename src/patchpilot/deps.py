"""Find pinned dependencies in a repo: requirements.txt (PyPI), package-lock.json and HTML CDN tags (npm). Read-only.
"""

import json
import os
import re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

# name, optional [extras], then exactly "==" (not ">=", "~=" or "===") and the version up to a space or ";" marker
REQ_LINE = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;=]+)")

# (?![\w.-]) rejects partial or prerelease versions like 4.17 or 4.17.15-beta: OSV needs the exact version
CDN = re.compile(
    r"(?:cdn\.jsdelivr\.net/npm/|unpkg\.com/)((?:@[\w.-]+/)?[\w.-]+)@(\d+\.\d+\.\d+)(?![\w.-])"
    r"|cdnjs\.cloudflare\.com/ajax/libs/([\w.-]+)/(\d+\.\d+\.\d+)/"
)


def parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        m = REQ_LINE.match(line.split("#", 1)[0].strip())
        if m:
            out.append((m.group(1).lower(), m.group(2)))
    return out


def parse_package_lock(text: str) -> list[tuple[str, str]]:
    out = []
    for key, info in json.loads(text).get("packages", {}).items():
        if key.startswith("node_modules/") and isinstance(info.get("version"), str):
            # nested installs look like node_modules/a/node_modules/@b/c: the package is after the last node_modules/.
            # An npm alias ("my-lodash": "npm:lodash@...") keeps the real package in "name".
            alias = info.get("name")
            out.append((alias if isinstance(alias, str) and alias else key.rsplit("node_modules/", 1)[1], info["version"]))
    return out


def parse_html_cdn(text: str) -> list[tuple[str, str]]:
    """In page order, so the report lists libraries the way the HTML loads them."""
    return [(m.group(1) or m.group(3), m.group(2) or m.group(4)) for m in CDN.finditer(text)]


def find_dependencies(root, warnings: list[str] | None = None) -> list[dict]:
    """Broken files are skipped and described in `warnings` (if given) so one bad lockfile doesn't stop the scan."""
    root = Path(root)
    deps, seen = [], set()
    for folder, dirs, files in os.walk(root):  # os.walk never descends into symlinked folders (followlinks=False)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)  # prune in place so os.walk never enters them
        for name in sorted(files):
            if name == "requirements.txt":
                parse, ecosystem = parse_requirements, "PyPI"
            elif name == "package-lock.json":
                parse, ecosystem = parse_package_lock, "npm"
            elif name.endswith((".html", ".htm")):
                parse, ecosystem = parse_html_cdn, "npm"
            else:
                continue
            path = Path(folder) / name
            source = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file():  # a link could point outside the repo; a FIFO would hang the read
                continue
            try:
                # utf-8-sig drops a BOM that would hide the first line; errors="replace": scanned repos aren't ours
                found = parse(path.read_text(encoding="utf-8-sig", errors="replace"))
            except (OSError, ValueError, TypeError, AttributeError) as e:  # ValueError covers bad JSON
                if warnings is not None:
                    warnings.append(f"skipped {source}: {type(e).__name__}: {e}")
                continue
            for pkg, version in found:
                if (ecosystem, pkg, version) not in seen:
                    seen.add((ecosystem, pkg, version))
                    deps.append({"name": pkg, "version": version, "ecosystem": ecosystem, "source": source})
    return deps
