"""Does the advisory this pair claims actually describe this package.

A training pair carries a CVE id and a package name that were supplied by hand,
and nothing checked that the two belong together. CVE-2025-46836 is a net-tools
flaw, but a minted pair labelled with it carried the corosync orf_token fix
(really CVE-2025-30472), so the model would have learned the wrong association
between an advisory and a fix.
"""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Callable

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def _norm(s: str) -> str:
    """A name reduced to what survives packaging: no case, no punctuation, no
    trailing version digits, so `grub2` meets `grub` and `net-tools` meets
    `nettools`."""
    return re.sub(r"[^a-z0-9]", "", s.lower()).rstrip("0123456789")


def package_tokens(package: str) -> set[str]:
    """Both the bare name and its version-stripped form, since `lz4` keeps its
    digit and `grub2` is packaged upstream as `grub`."""
    parts = re.split(r"[.\-_/ ]", package or "")
    out = set()
    for p in parts:
        bare = re.sub(r"[^a-z0-9]", "", (p or "").lower())
        out |= {bare, _norm(p)}
    return {t for t in out if len(t) >= 3}


def nvd_advisory_text(cve: str) -> str:
    """Description, reference URLs and CPE product strings, all in one blob."""
    with urllib.request.urlopen(_NVD + cve, timeout=30) as fh:
        data = json.load(fh)
    entries = data.get("vulnerabilities") or []
    if not entries:
        raise RuntimeError(f"{cve} is not in the NVD feed")
    cve_obj = entries[0]["cve"]
    parts = [d.get("value", "") for d in cve_obj.get("descriptions", [])]
    parts += [r.get("url", "") for r in cve_obj.get("references", [])]
    for cfg in cve_obj.get("configurations", []):
        for node in cfg.get("nodes", []):
            parts += [m.get("criteria", "") for m in node.get("cpeMatch", [])]
    return " ".join(parts)


def check_cve_names_package(
    cve: str, package: str, *, fetch: Callable[[str], str] = nvd_advisory_text
) -> str | None:
    """None when the advisory names the package, otherwise why it does not."""
    tokens = package_tokens(package)
    if not tokens:
        return f"{package}: name is too short to check against the advisory for {cve}"
    try:
        text = fetch(cve)
    except Exception as e:
        return f"{cve}: could not read the advisory: {e}"
    words = [w.lower() for w in re.split(r"[^A-Za-z0-9]+", text) if w]
    # Runs of adjacent words joined as well, since an advisory writes `net-tools`
    # or `Net::CIDR::Lite` where the attr is one word.
    if "do not use this candidate number" in text.lower():
        return f"{cve} was withdrawn by its CNA and is not a vulnerability"
    seen = {_norm(w) for w in words} | set(words)
    for n in (2, 3, 4):
        seen |= {"".join(words[i:i + n]) for i in range(len(words) - n + 1)}
    for tok in tokens:
        for word in seen:
            if word == tok:
                return None
            if len(word) >= 4 and len(tok) >= 4 and (word.startswith(tok) or tok.startswith(word)):
                return None
    return f"{cve} does not name {package}: the advisory is about something else"


def _attr_of(bundle_dir) -> str:
    for name in ("resolver-input.json", "authoring-example.json"):
        p = bundle_dir / name
        if p.is_file():
            try:
                attr = json.loads(p.read_text()).get("attr_path")
            except json.JSONDecodeError:
                continue
            if attr:
                return attr
    return ""


def audit_corpus(root, *, fetch=nvd_advisory_text, pause=None) -> list[tuple[str, str]]:
    """Every bundle whose advisory does not name the package it patches. NVD's
    anonymous rate limit is five requests per thirty seconds, hence the pause."""
    import time

    pause = pause if pause is not None else (lambda s: time.sleep(s))
    bad = []
    for d in sorted(root.glob("CVE-*")):
        attr = _attr_of(d)
        if not attr:
            continue
        reason = check_cve_names_package(d.name.split("--")[0], attr, fetch=fetch)
        if reason:
            bad.append((d.name, reason))
        pause(6.5)
    return bad


def main(argv=None) -> int:
    import argparse
    from pathlib import Path

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--corpus", type=Path, default=Path("traces/example"))
    args = ap.parse_args(argv)
    bad = audit_corpus(args.corpus)
    for name, reason in bad:
        print(f"{name}: {reason}")
    print(f"{len(bad)} mislabelled")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
