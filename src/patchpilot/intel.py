"""Vulnerability intelligence: OSV.dev (which versions are vulnerable) + CISA KEV (which bugs attackers really use)."""

import re

import httpx

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # packaging only arrives via pytest locally; a plain pip install may lack it
    Version = None

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TIMEOUT = 30.0


def _version_key(v: str):
    """Compare versions as numbers so 4.17.21 > 4.17.9 (as strings, "9" > "2")."""
    if Version is not None:
        try:
            return (1, Version(v))
        except InvalidVersion:
            pass
    # flag 0: unparseable sorts first, so [-1] stays a real version.
    # shortcut: without packaging, 1.0.0-rc1 ranks above 1.0.0; add packaging to pyproject deps to fix.
    return (0, tuple(int(n) for n in re.findall(r"\d+", v)))


def query_osv(deps: list[dict], client: httpx.Client) -> dict[int, list[str]]:
    """One batch request for all deps. Returns {dep index: [vuln ids]}. Results come back in input order."""
    queries = [{"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]} for d in deps]
    reply = client.post(OSV_BATCH, json={"queries": queries}, timeout=TIMEOUT)
    reply.raise_for_status()
    return {i: [v["id"] for v in r.get("vulns", [])] for i, r in enumerate(reply.json()["results"])}


def fixed_versions(vuln: dict, name: str) -> list[str]:
    """Versions that fix this vuln for this package, from the OSV 'affected' ranges."""
    out = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != name.lower():
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") == "GIT":  # GIT ranges list commit hashes, not versions you can upgrade to
                continue
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(out), key=_version_key)


def vuln_details(vuln_id: str, client: httpx.Client) -> dict:
    reply = client.get(OSV_VULN.format(vuln_id), timeout=TIMEOUT)
    reply.raise_for_status()
    return reply.json()


def load_kev(client: httpx.Client) -> set[str]:
    """CVE ids that CISA has confirmed are exploited in the wild."""
    reply = client.get(KEV_FEED, timeout=TIMEOUT)
    reply.raise_for_status()
    return {v["cveID"] for v in reply.json()["vulnerabilities"]}


def priority(cves: list[str], kev: set[str], severity: str | None) -> str:
    """P0 = known exploited (fix now), then by advisory severity."""
    if any(c in kev for c in cves):
        return "P0"
    return {"CRITICAL": "P1", "HIGH": "P1", "MODERATE": "P2", "MEDIUM": "P2"}.get((severity or "").upper(), "P3")
