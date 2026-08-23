#!/usr/bin/env python3
"""Cross-distro adaptation-yield screening study (Debian).

Measures ONE number, under the preregistration in
docs/PREREG_CROSSDISTRO_SCREENING.md: among Debian CVE patches that cite a
resolvable upstream commit, what fraction are GENUINE adaptations vs verbatim
copies of the upstream fix? Decides whether reviving the compound-guard
successor arc via cross-distro harvest is supported by data (RICH: >=8/41
genuine) or not (THIN).

Discipline (matches the July pilot): all fetched text is untrusted DATA —
allowlisted HTTPS hosts only, sha256 recorded per fetch, NEVER executed, NEVER
placed in a model prompt. The only judgement is a pure-text payload comparison
(verify_against_upstream). No model spend.

Deterministic: seeded sample, fixed before any verdict is seen. Re-running with
the same tracker JSON and seed reproduces the sample.

Usage:
  python3 scripts/crossdistro_screen.py --tracker deb-tracker.json --out data/reports
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

FETCH_DELAY_S = 0.3  # politeness toward sources.debian.org
MAX_CANDIDATES = 1500  # operational ceiling; recorded if hit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.harvest_oracle_candidates import verify_against_upstream

SEED = 20260823
TARGET_ELIGIBLE = 41
MAX_CVES_PER_PACKAGE = 4  # tries before abandoning a drawn package

DEBIAN_HOSTS = {"security-tracker.debian.org", "sources.debian.org"}
# Upstream forges we know how to turn a commit reference into a fetchable patch.
UPSTREAM_HOSTS = {"github.com", "gitlab.com", "raw.githubusercontent.com"}
ALLOWED_HOSTS = DEBIAN_HOSTS | UPSTREAM_HOSTS

CVE_PATCH_RE = re.compile(r"^CVE-\d{4}-\d+\.patch$")
GITHUB_COMMIT_RE = re.compile(
    r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/commit/([0-9a-f]{7,40})"
)
GITLAB_COMMIT_RE = re.compile(
    r"gitlab\.com/([A-Za-z0-9_./-]+?)/-/commit/([0-9a-f]{7,40})"
)


def _host(url: str) -> str:
    m = re.match(r"https?://([^/]+)/", url)
    return m.group(1).lower() if m else ""


def fetch(url: str, timeout: int = 45) -> tuple[bytes, str] | None:
    """GET an allowlisted URL. Returns (body, sha256) or None on any failure.
    Refuses non-allowlisted hosts and cross-host redirects to a non-allowlisted
    host. Never raises."""
    host = _host(url)
    if host not in ALLOWED_HOSTS:
        return None
    try:
        time.sleep(FETCH_DELAY_S)
        req = urllib.request.Request(url, headers={"User-Agent": "trace-crossdistro-screen"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            final_host = _host(resp.geturl())
            if final_host and final_host not in ALLOWED_HOSTS:
                return None
            body = resp.read()
    except Exception:
        return None
    return body, hashlib.sha256(body).hexdigest()


def pool_prefix(pkg: str) -> str:
    """Debian pool directory prefix: 'libfoo' -> 'libf', else first letter."""
    return pkg[:4] if pkg.startswith("lib") and len(pkg) >= 4 else pkg[:1]


def build_census(tracker: dict[str, Any]) -> list[dict[str, str]]:
    """(package, cve, version) for every CVE resolved in a *-security suite,
    grouped so each package's CVEs stay together for the <=1-per-package rule."""
    out: list[dict[str, str]] = []
    for pkg, cves in tracker.items():
        if not isinstance(cves, dict):
            continue
        for cve, info in cves.items():
            if not cve.startswith("CVE-"):
                continue
            releases = (info or {}).get("releases", {})
            if not isinstance(releases, dict):
                continue
            sec_version = None
            for rel in releases.values():
                if not isinstance(rel, dict) or rel.get("status") != "resolved":
                    continue
                repos = rel.get("repositories", {})
                if not isinstance(repos, dict):
                    continue
                for suite, ver in repos.items():
                    if suite.endswith("-security") and ver:
                        sec_version = ver
                        break
                if sec_version:
                    break
            if sec_version:
                out.append({"package": pkg, "cve": cve, "version": sec_version})
    return out


def debian_patch_url(pkg: str, version: str, cve: str) -> str:
    return (
        f"https://sources.debian.org/data/main/{pool_prefix(pkg)}/{pkg}/"
        f"{version}/debian/patches/{cve}.patch"
    )


def resolve_upstream(patch_text: str) -> str | None:
    """A fetchable upstream-fix URL cited in a Debian patch header, or None."""
    m = GITHUB_COMMIT_RE.search(patch_text)
    if m:
        owner, repo, sha = m.group(1), m.group(2), m.group(3)
        return f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
    m = GITLAB_COMMIT_RE.search(patch_text)
    if m:
        return f"https://gitlab.com/{m.group(1)}/-/commit/{m.group(2)}.patch"
    return None


def screen(census: list[dict[str, str]]) -> dict[str, Any]:
    rng = random.Random(SEED)
    # Group by package; sample package order, take CVEs in-package deterministically.
    by_pkg: dict[str, list[dict[str, str]]] = {}
    for row in census:
        by_pkg.setdefault(row["package"], []).append(row)
    packages = sorted(by_pkg)
    rng.shuffle(packages)
    for p in packages:
        by_pkg[p].sort(key=lambda r: r["cve"])
        rng.shuffle(by_pkg[p])

    eligible: list[dict[str, Any]] = []
    packages_drawn = 0
    candidates_tried = 0
    fetch_log: list[dict[str, str]] = []

    ceiling_hit = False
    for pkg in packages:
        if len(eligible) >= TARGET_ELIGIBLE:
            break
        if candidates_tried >= MAX_CANDIDATES:
            ceiling_hit = True
            break
        packages_drawn += 1
        got_one = False
        for row in by_pkg[pkg][:MAX_CVES_PER_PACKAGE]:
            if got_one:
                break
            candidates_tried += 1
            durl = debian_patch_url(pkg, row["version"], row["cve"])
            dres = fetch(durl)
            if dres is None:
                continue  # no CVE-named patch at that version → not citable-here
            dtext = dres[0].decode("utf-8", errors="replace")
            fetch_log.append({"url": durl, "sha256": dres[1]})
            up_url = resolve_upstream(dtext)
            if up_url is None:
                continue  # patch exists but cites no resolvable upstream ref
            ures = fetch(up_url)
            if ures is None:
                continue  # cited upstream not fetchable
            utext = ures[0].decode("utf-8", errors="replace")
            fetch_log.append({"url": up_url, "sha256": ures[1]})
            verdict = verify_against_upstream(dtext, utext)
            if verdict["verdict"] == "empty":
                continue  # unparsable one side → not a usable comparison
            eligible.append(
                {
                    "package": pkg,
                    "cve": row["cve"],
                    "debian_version": row["version"],
                    "debian_patch": durl,
                    "debian_sha256": dres[1],
                    "upstream_patch": up_url,
                    "upstream_sha256": ures[1],
                    **verdict,
                }
            )
            got_one = True

    genuine = [e for e in eligible if e["verdict"] == "genuine-adaptation"]
    verbatim = [e for e in eligible if e["verdict"] == "verbatim-copy"]
    ambiguous = [e for e in eligible if e["verdict"] == "provenance-ambiguous"]
    g = len(genuine)
    n = len(eligible)
    decision = "RICH" if g >= 8 else "THIN"
    lo, hi = wilson_ci(g, n) if n else (0.0, 0.0)

    return {
        "schema_version": "1.0.0",
        "kind": "crossdistro-screening",
        "prereg": "docs/PREREG_CROSSDISTRO_SCREENING.md",
        "seed": SEED,
        "target_eligible": TARGET_ELIGIBLE,
        "census_size": len(census),
        "census_packages": len(by_pkg),
        "packages_drawn": packages_drawn,
        "candidates_tried": candidates_tried,
        "eligible_screened": n,
        "eligibility_rate": round(n / candidates_tried, 3) if candidates_tried else 0.0,
        "counts": {
            "genuine_adaptation": g,
            "verbatim_copy": len(verbatim),
            "provenance_ambiguous": len(ambiguous),
        },
        "decision_rule": "g>=8 -> RICH else THIN (g = strict genuine, ambiguous excluded)",
        "genuine_count": g,
        "decision": decision,
        "wilson95_genuine_rate": [round(lo, 3), round(hi, 3)],
        "eligible": eligible,
        "fetches": len(fetch_log),
        "ceiling_hit": ceiling_hit,
        "reached_target": n >= TARGET_ELIGIBLE,
    }


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z / d) * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return max(0.0, centre - half), min(1.0, centre + half)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tracker", type=Path, help="path to a pre-fetched security-tracker JSON")
    ap.add_argument("--out", type=Path, default=Path("data/reports"))
    args = ap.parse_args(argv[1:])

    if args.tracker and args.tracker.exists():
        raw = args.tracker.read_bytes()
    else:
        got = fetch("https://security-tracker.debian.org/tracker/data/json", timeout=120)
        if got is None:
            print("error: could not fetch tracker JSON", file=sys.stderr)
            return 2
        raw = got[0]
    tracker_sha = hashlib.sha256(raw).hexdigest()
    tracker = json.loads(raw)

    census = build_census(tracker)
    report = screen(census)
    report["tracker_sha256"] = tracker_sha

    args.out.mkdir(parents=True, exist_ok=True)
    out_path = args.out / "crossdistro-screening.json"
    out_path.write_text(json.dumps(report, indent=1) + "\n")

    print(f"census: {report['census_size']} (pkg={report['census_packages']})")
    print(f"packages drawn: {report['packages_drawn']}  candidates tried: {report['candidates_tried']}")
    print(f"eligible screened: {report['eligible_screened']}  eligibility rate: {report['eligibility_rate']}")
    c = report["counts"]
    print(f"  genuine={c['genuine_adaptation']}  verbatim={c['verbatim_copy']}  ambiguous={c['provenance_ambiguous']}")
    print(f"DECISION: {report['decision']} (g={report['genuine_count']}, threshold 8)")
    print(f"  Wilson95 genuine rate: {report['wilson95_genuine_rate']}")
    print(f"wrote: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
