"""Transform v6 review.md PC format to v1.7 two-step extraction format.

v6 format:
  ## Patch comparison
  hunk N — description:
  - upstream-fix.patch:
    - `+ line`
  - patch.diff (desc):
    - `+ line`
  - comparison: match

v1.7 format:
  ## patch.diff extraction
  hunk N — description:
  - `+ line`

  ## upstream-fix.patch extraction
  hunk N — description:
  - `+ line`

  ## Patch comparison
  hunk N — description:
  - comparison: match

  conclusion: accept — all hunks match

Usage:
  python3 scripts/upgrade_review_to_v7.py traces/example/CVE-*/review.md
  python3 scripts/upgrade_review_to_v7.py --dry-run traces/example/CVE-*/review.md
"""

from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Hunk:
    header: str  # "hunk N — description"
    ufp_lines: list[str]  # `+ line` / `- line` from upstream-fix.patch
    pd_lines: list[str]  # `+ line` / `- line` from patch.diff
    comparison: str  # match | mismatch | missing-hunk


def _extract_bullets(section_text: str) -> list[str]:
    """Extract `+ line` / `- line` backtick bullets from a sub-section."""
    return re.findall(r"`[+\-][^`]*`", section_text)


def parse_pc_section(pc_text: str) -> tuple[list[Hunk], str]:
    """Parse the ## Patch comparison section into Hunk objects and conclusion."""
    # Split on hunk markers
    parts = re.split(r"\n(hunk\s+\d+\s*[—\-–][^\n]*)", pc_text, flags=re.IGNORECASE)
    # parts[0] = section header, then [header, body, header, body, ...]
    hunks = []
    i = 1
    while i < len(parts) - 1:
        hunk_header = parts[i].strip()
        hunk_body = parts[i + 1] if i + 1 < len(parts) else ""
        i += 2

        # Find upstream-fix.patch sub-section
        ufp_m = re.search(
            r"- upstream-fix\.patch\s*[:\(][^\n]*\n(.*?)(?=- patch\.diff|$)",
            hunk_body,
            re.DOTALL | re.IGNORECASE,
        )
        ufp_lines = _extract_bullets(ufp_m.group(1)) if ufp_m else []

        # Find patch.diff sub-section
        pd_m = re.search(
            r"- patch\.diff[^\n]*\n(.*?)(?=- comparison\s*:|$)",
            hunk_body,
            re.DOTALL | re.IGNORECASE,
        )
        pd_lines = _extract_bullets(pd_m.group(1)) if pd_m else []

        # Find comparison verdict
        comp_m = re.search(r"comparison\s*:\s*(\S[\w-]*)", hunk_body, re.IGNORECASE)
        comparison = comp_m.group(1).lower() if comp_m else "unknown"

        hunks.append(
            Hunk(
                header=hunk_header,
                ufp_lines=ufp_lines,
                pd_lines=pd_lines,
                comparison=comparison,
            )
        )

    # Extract conclusion line
    conc_m = re.search(
        r"\nconclusion\s*:(.*?)(?:\n##|\Z)", pc_text, re.DOTALL | re.IGNORECASE
    )
    conclusion = ("conclusion:" + conc_m.group(1).rstrip()).strip() if conc_m else ""

    return hunks, conclusion


def build_v7_sections(hunks: list[Hunk], conclusion: str) -> str:
    """Build the three v1.7 sections from parsed hunks."""
    # ## patch.diff extraction
    pd_lines = []
    pd_lines.append("## patch.diff extraction")
    for h in hunks:
        header = h.header.rstrip(":")
        pd_lines.append(f"{header}:")
        for line in h.pd_lines:
            pd_lines.append(f"- {line}")
        pd_lines.append("")

    # ## upstream-fix.patch extraction
    ufp_lines = []
    ufp_lines.append("## upstream-fix.patch extraction")
    for h in hunks:
        header = h.header.rstrip(":")
        ufp_lines.append(f"{header}:")
        for line in h.ufp_lines:
            ufp_lines.append(f"- {line}")
        ufp_lines.append("")

    # ## Patch comparison
    pc_lines = []
    pc_lines.append("## Patch comparison")
    for h in hunks:
        header = h.header.rstrip(":")
        pc_lines.append(f"{header}:")
        pc_lines.append(f"- comparison: {h.comparison}")
        pc_lines.append("")
    if conclusion:
        pc_lines.append(conclusion)
        pc_lines.append("")

    return (
        "\n".join(pd_lines).rstrip()
        + "\n\n"
        + "\n".join(ufp_lines).rstrip()
        + "\n\n"
        + "\n".join(pc_lines).rstrip()
    )


def transform(text: str) -> tuple[str, bool]:
    """Transform a review.md from v6 to v1.7 format. Returns (new_text, changed)."""
    if "## Patch comparison" not in text:
        return text, False
    if "## patch.diff extraction" in text:
        return text, False  # already v1.7

    pc_start = text.find("## Patch comparison")
    # Find what comes AFTER the PC section
    findings_m = re.search(r"\n## (?!Patch comparison)", text[pc_start:])
    if findings_m:
        after_start = pc_start + findings_m.start()
    else:
        after_start = len(text)

    pc_text = text[pc_start:after_start]
    before = text[:pc_start]
    after = text[after_start:]

    hunks, conclusion = parse_pc_section(pc_text)
    if not hunks:
        return text, False

    new_sections = build_v7_sections(hunks, conclusion)
    new_text = before + new_sections + "\n\n" + after.lstrip("\n")
    return new_text, new_text != text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--check", action="store_true", help="exit 1 if any file needs transform"
    )
    args = ap.parse_args()

    changed = 0
    for p in args.files:
        if not p.is_file():
            print(f"SKIP (not a file): {p}", file=sys.stderr)
            continue
        text = p.read_text()
        new_text, did_change = transform(text)
        if did_change:
            changed += 1
            print(f"{'WOULD CHANGE' if args.dry_run else 'CHANGED'}: {p}")
            if not args.dry_run:
                p.write_text(new_text)
        else:
            pass  # unchanged or not applicable

    if args.check and changed > 0:
        print(f"{changed} file(s) need v1.7 upgrade", file=sys.stderr)
        return 1
    if not args.check:
        print(f"Done: {changed} file(s) updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
