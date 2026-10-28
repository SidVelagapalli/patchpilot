"""Step 1 of the pipeline: dependencies -> vulnerabilities -> ranked findings (report.json). Read-only."""

import httpx

from patchpilot.deps import find_dependencies
from patchpilot.intel import fixed_versions, load_kev, priority, query_osv, vuln_details


def scan(root: str) -> dict:
    deps = find_dependencies(root)
    findings = []
    with httpx.Client(headers={"User-Agent": "patchpilot/0.1"}) as client:
        if not deps:
            return {"dependencies": 0, "findings": []}
        hits = query_osv(deps, client)
        kev = load_kev(client)
        details_cache: dict[str, dict] = {}
        for i, vuln_ids in hits.items():
            dep = deps[i]
            for vid in vuln_ids:
                v = details_cache.setdefault(vid, vuln_details(vid, client))
                cves = [a for a in [v.get("id"), *v.get("aliases", [])] if a and a.startswith("CVE-")]
                severity = v.get("database_specific", {}).get("severity")
                findings.append({
                    "id": vid, "cves": cves, "package": dep["name"], "version": dep["version"],
                    "ecosystem": dep["ecosystem"], "source": dep["source"],
                    "summary": v.get("summary") or (v.get("details") or "")[:200],
                    "severity": severity, "known_exploited": any(c in kev for c in cves),
                    "priority": priority(cves, kev, severity),
                    "fixed_in": fixed_versions(v, dep["name"]),
                    "url": f"https://osv.dev/vulnerability/{vid}",
                })
    findings.sort(key=lambda f: (f["priority"], f["package"]))
    return {"dependencies": len(deps), "findings": findings}
