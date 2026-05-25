"""Parse Patcher model output into the contracted shape.

Per prompts/patcher.v1.md the only two valid response shapes are:

  (a) exactly two file blocks, in order:

      === BEGIN patch.diff ===
      <unified diff>
      === END patch.diff ===
      === BEGIN patch-rationale.md ===
      <markdown with 5 level-2 sections>
      === END patch-rationale.md ===

  (b) a single refusal block:

      === BEGIN refusal ===
      rule: <1-8>
      reason: <one-line reason>
      === END refusal ===

Anything else is malformed and must fail loudly. The parser is
deliberately strict:

  * Nothing permitted before the first BEGIN marker or after the
    last END marker (beyond whitespace).
  * Block order is enforced.
  * The rationale's five required level-2 headings must all be
    present and in the contracted order.
  * Refusal rule number must be an integer in [1, 8].

Returns a structured result on success. Raises PatcherOutputMalformed
on any violation with a specific diagnosis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


class PatcherOutputMalformed(Exception):
    """Raised when model output does not match the prompt contract.

    Carries optional `raw_response` / `raw_response_sha256` / `model_id` /
    `prompt_sha256` / `user_content_sha256` attributes, attached by
    `run_patcher` so the executor can persist the failing artifact to
    `.patcher-failures/<uuid>/` for debugging. These are attached as
    plain attributes (not constructor args) so the parser layer
    remains shape-agnostic; the runner is the one with the model
    context.
    """

    raw_response: str | None = None
    raw_response_sha256: str | None = None
    model_id: str | None = None
    prompt_sha256: str | None = None
    user_content_sha256: str | None = None


@dataclass(frozen=True)
class PatcherParseResult:
    """Structured result of a successful parse."""

    kind: str  # "patch" | "refusal"
    patch_diff: str | None = None
    patch_rationale_md: str | None = None
    refusal_rule: int | None = None
    refusal_reason: str | None = None


REQUIRED_RATIONALE_HEADINGS: tuple[str, ...] = (
    "## Upstream reference",
    "## Why this version",
    "## Why minimal",
    "## Alternatives rejected",
    "## Downstream risk",
)


_PATCH_BLOCK_RE = re.compile(
    r"===\s*BEGIN patch\.diff\s*===\n(?P<diff>.*?)\n===\s*END patch\.diff\s*===\s*\n"
    r"===\s*BEGIN patch-rationale\.md\s*===\n(?P<rationale>.*?)\n===\s*END patch-rationale\.md\s*===",
    re.DOTALL,
)

_REFUSAL_BLOCK_RE = re.compile(
    r"===\s*BEGIN refusal\s*===\n(?P<body>.*?)\n===\s*END refusal\s*===",
    re.DOTALL,
)


def parse_patcher_output(raw: str) -> PatcherParseResult:
    """Parse the model's raw text output into a structured result.

    Args:
        raw: model response text, as returned by the adapter.

    Returns:
        PatcherParseResult with kind="patch" or kind="refusal".

    Raises:
        PatcherOutputMalformed: if the text violates the prompt contract.
    """
    if not isinstance(raw, str):
        raise PatcherOutputMalformed(f"expected str, got {type(raw).__name__}")
    text = raw.strip()
    if not text:
        raise PatcherOutputMalformed("model returned empty output")

    # Decide which block shape we're in by looking at the first BEGIN marker.
    first_marker_match = re.search(r"^===\s*BEGIN (patch\.diff|refusal)\s*===$", text, re.MULTILINE)
    if not first_marker_match:
        raise PatcherOutputMalformed(
            "no '=== BEGIN ... ===' marker found; model output does not match the contract"
        )

    first_block = first_marker_match.group(1)

    # No content permitted before the first BEGIN marker.
    before = text[: first_marker_match.start()].strip()
    if before:
        raise PatcherOutputMalformed(
            "content before the first '=== BEGIN' marker is forbidden; "
            f"found {len(before)} chars of prose preamble"
        )

    if first_block == "refusal":
        return _parse_refusal(text)
    return _parse_patch(text)


# ─── patch path ─────────────────────────────────────────────────────────────


def _parse_patch(text: str) -> PatcherParseResult:
    # Must begin at first BEGIN marker exactly (we already stripped leading ws).
    stripped = text.lstrip()
    if not stripped.startswith("=== BEGIN patch.diff ==="):
        raise PatcherOutputMalformed(
            "patch path requires '=== BEGIN patch.diff ===' as the first non-whitespace line"
        )

    match = _PATCH_BLOCK_RE.match(stripped)
    if not match:
        raise PatcherOutputMalformed(
            "patch output malformed: expected two sequential blocks "
            "'=== BEGIN patch.diff === ... === END patch.diff ===' "
            "followed immediately by "
            "'=== BEGIN patch-rationale.md === ... === END patch-rationale.md ==='"
        )

    # Nothing permitted after the last END marker.
    after = stripped[match.end():].strip()
    if after:
        raise PatcherOutputMalformed(
            "content after '=== END patch-rationale.md ===' is forbidden; "
            f"found {len(after)} chars of trailing prose"
        )

    diff_body = match.group("diff")
    rationale_body = match.group("rationale")

    if not diff_body.strip():
        raise PatcherOutputMalformed("patch.diff block is empty")
    if not rationale_body.strip():
        raise PatcherOutputMalformed("patch-rationale.md block is empty")

    _validate_rationale_sections(rationale_body)

    return PatcherParseResult(
        kind="patch",
        patch_diff=diff_body,
        patch_rationale_md=rationale_body,
    )


def _validate_rationale_sections(rationale: str) -> None:
    """Enforce that the five level-2 headings appear in the contracted order."""
    lines = rationale.splitlines()
    seen_positions: dict[str, int] = {}
    for i, line in enumerate(lines):
        if line.startswith("## "):
            heading = line.strip()
            if heading in REQUIRED_RATIONALE_HEADINGS and heading not in seen_positions:
                seen_positions[heading] = i

    missing = [h for h in REQUIRED_RATIONALE_HEADINGS if h not in seen_positions]
    if missing:
        raise PatcherOutputMalformed(
            "patch-rationale.md is missing required level-2 headings: "
            + ", ".join(repr(h) for h in missing)
        )

    positions = [seen_positions[h] for h in REQUIRED_RATIONALE_HEADINGS]
    if positions != sorted(positions):
        raise PatcherOutputMalformed(
            "patch-rationale.md headings are out of the contracted order; "
            f"expected {list(REQUIRED_RATIONALE_HEADINGS)}"
        )

    # No top-level heading is permitted. The contract only admits ## level.
    for line in lines:
        if line.startswith("# ") and not line.startswith("## "):
            raise PatcherOutputMalformed(
                "patch-rationale.md contains a level-1 heading ('# ...'); "
                "contract forbids any top-level heading"
            )


# ─── refusal path ───────────────────────────────────────────────────────────


_RULE_LINE_RE = re.compile(r"^rule:\s*(\d+)\s*$")
_REASON_LINE_RE = re.compile(r"^reason:\s*(\S.*)$")


def _parse_refusal(text: str) -> PatcherParseResult:
    stripped = text.lstrip()
    if not stripped.startswith("=== BEGIN refusal ==="):
        raise PatcherOutputMalformed(
            "refusal path requires '=== BEGIN refusal ===' as the first non-whitespace line"
        )
    match = _REFUSAL_BLOCK_RE.match(stripped)
    if not match:
        raise PatcherOutputMalformed(
            "refusal output malformed: expected '=== BEGIN refusal === ... === END refusal ==='"
        )

    after = stripped[match.end():].strip()
    if after:
        raise PatcherOutputMalformed(
            "content after '=== END refusal ===' is forbidden; "
            f"found {len(after)} chars of trailing prose"
        )

    body = match.group("body").strip()
    body_lines = [ln for ln in body.splitlines() if ln.strip()]
    if len(body_lines) < 2:
        raise PatcherOutputMalformed(
            "refusal body must contain at least a 'rule:' line and a 'reason:' line"
        )

    rule_match = _RULE_LINE_RE.match(body_lines[0])
    if not rule_match:
        raise PatcherOutputMalformed(
            "refusal body's first line must be 'rule: <integer>'"
        )
    rule = int(rule_match.group(1))
    if rule < 1 or rule > 8:
        raise PatcherOutputMalformed(
            f"refusal rule must be in [1, 8]; got {rule}"
        )

    reason_match = _REASON_LINE_RE.match(body_lines[1])
    if not reason_match:
        raise PatcherOutputMalformed(
            "refusal body's second line must be 'reason: <one-line reason>'"
        )
    reason = reason_match.group(1).strip()

    return PatcherParseResult(
        kind="refusal",
        refusal_rule=rule,
        refusal_reason=reason,
    )
