"""Relabel authoring pairs from free-form unified diff -> search/replace blocks.

Codex/Fable (2026-07-14): the authoring failure is edit-SHAPE at the addition site, and
byte-exact-on-free-form-diff wastes most of the fine-tuning gradient teaching the model to
reproduce context lines. Search/replace blocks fix both: the SEARCH span must occur
VERBATIM in the shown window (kills the hallucination class + makes the label mechanically
appliable), and the REPLACE span is the only free-generation part (where the edit lives),
so with loss-masking on SEARCH the gradient concentrates on the edit.

Format per hunk:
  <<<<<<< SEARCH
  <exact pre-fix lines (context + removed), no diff prefix>
  =======
  <post-fix lines (context + added), no diff prefix>
  >>>>>>> REPLACE

Reads exports/authoring-lora{,-supplemented}/authoring.{train,dev}.jsonl (messages format),
rewrites the assistant turn to search/replace, swaps the system prompt, and drops any pair
whose SEARCH span is not a verbatim substring of the shown window (that pair cannot be
learned as search/replace and is excluded — same exclude-not-degrade discipline).

Run: python3 lora/relabel_search_replace.py <in_dir> <out_dir>
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

_SR_SYSTEM = (
    "You are a security engineer fixing a CVE. You are given the vulnerability description "
    "(symptom only) and the vulnerable source window. Author the MINIMAL fix as one or more "
    "SEARCH/REPLACE blocks. Follow these rules exactly:\n"
    "1. Each block is:\n"
    "<<<<<<< SEARCH\n<exact lines copied verbatim from the shown source window>\n"
    "=======\n<the replacement lines>\n>>>>>>> REPLACE\n"
    "2. The SEARCH text MUST appear verbatim in the shown source window — copy it exactly, "
    "including whitespace; do not invent or paraphrase it.\n"
    "3. Change as few lines as possible; keep the SEARCH span tight around the edit.\n"
    "4. Modify ONLY code visible in the shown source window.\n"
    "5. Output only the SEARCH/REPLACE block(s) with no other text.\n"
    "6. Prefer folding a new bound or check into an existing condition over adding a "
    "separate guard, when the upstream fix does so."
)

_HUNK_RE = re.compile(r"^@@ ")


def _window_from_user(user: str) -> str:
    m = re.search(r"```[a-zA-Z0-9]*\n(.*)\n```", user, re.DOTALL)
    return m.group(1) if m else ""


def _blocks_from_diff(diff: str) -> list[tuple[str, str]]:
    """Ordered (before, after) spans per hunk, reconstructed from the unified diff."""
    blocks: list[tuple[str, str]] = []
    before: list[str] = []
    after: list[str] = []
    in_hunk = False

    def flush():
        nonlocal before, after
        if before or after:
            blocks.append(("\n".join(before), "\n".join(after)))
        before, after = [], []

    lines = diff.splitlines()
    i, n = 0, len(lines)
    while i < n:
        ln = lines[i]
        if ln.startswith("--- ") and i + 1 < n and lines[i + 1].startswith("+++ "):
            flush()
            in_hunk = False
            i += 2
            continue
        if ln.startswith("diff ") or ln.startswith("index "):
            i += 1
            continue
        if _HUNK_RE.match(ln):
            flush()
            in_hunk = True
            i += 1
            continue
        if not in_hunk:
            i += 1
            continue
        if ln.startswith("-") and not ln.startswith("---"):
            before.append(ln[1:])
        elif ln.startswith("+") and not ln.startswith("+++"):
            after.append(ln[1:])
        elif ln.startswith(" "):
            before.append(ln[1:])
            after.append(ln[1:])
        elif ln == "":
            before.append("")
            after.append("")
        else:
            flush()  # `\ No newline`, stray line
        i += 1
    flush()
    return [b for b in blocks if b[0].strip() or b[1].strip()]


def _to_search_replace(diff: str, window: str) -> str | None:
    blocks = _blocks_from_diff(diff)
    if not blocks:
        return None
    win_norm = re.sub(r"\s+", "", window)
    parts = []
    for before, after in blocks:
        # SEARCH must be a verbatim (whitespace-normalized) substring of the window.
        if re.sub(r"\s+", "", before) not in win_norm:
            return None
        parts.append(f"<<<<<<< SEARCH\n{before}\n=======\n{after}\n>>>>>>> REPLACE")
    return "\n".join(parts)


def relabel(in_dir: Path, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    stats = {}
    for split in ("train", "dev"):
        src = in_dir / f"authoring.{split}.jsonl"
        if not src.is_file():
            continue
        kept, dropped = [], 0
        for line in src.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            msgs = r["messages"]
            window = _window_from_user(msgs[1]["content"])
            sr = _to_search_replace(msgs[2]["content"], window)
            if sr is None:
                dropped += 1
                continue
            kept.append(
                {
                    "messages": [
                        {"role": "system", "content": _SR_SYSTEM},
                        {"role": "user", "content": msgs[1]["content"]},
                        {"role": "assistant", "content": sr},
                    ]
                }
            )
        (out_dir / f"authoring.{split}.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in kept)
        )
        stats[split] = {"kept": len(kept), "dropped_unlocatable_search": dropped}
    (out_dir / "manifest.json").write_text(
        json.dumps({"format": "search-replace", **stats}, indent=2) + "\n"
    )
    return stats


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(2)
    s = relabel(Path(sys.argv[1]), Path(sys.argv[2]))
    print(json.dumps(s, indent=2))
