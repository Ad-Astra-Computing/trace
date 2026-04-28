"""Parse Reviewer model output into the contracted shape.

Per `prompts/reviewer.v1.md` the only two valid response shapes are:

  (a) a single review block:

      === BEGIN review.md ===
      ## Verdict
      <accept | reject | escalate>

      ## Reasoning
      <2-6 sentences>

      ## Findings
      - severity: ... — title — citation
      - ...   (or `(none)`)

      ## Cited evidence
      - <artifact>
      - ...

      ## Cross-family attestation
      reviewer_family: <name>
      patcher_family_observed: <name>
      rule_honored: <true|false>
      === END review.md ===

  (b) a single refusal block (same shape as Patcher):

      === BEGIN refusal ===
      rule: <1-N>
      reason: <one-line reason>
      === END refusal ===

Anything else is malformed. The parser is deliberately strict so that
schema violations fail loudly rather than producing a malformed
review.md that downstream Steward might misread.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


SCHEMA_VERSION = "1.0.0"


# Refusal rule range (1-5 per reviewer.v1.md). Aligned with the
# Reviewer prompt's "Refusal rules:" section.
_REVIEWER_REFUSAL_RULE_MIN = 1
_REVIEWER_REFUSAL_RULE_MAX = 5


REQUIRED_REVIEW_HEADINGS: tuple[str, ...] = (
    "## Verdict",
    "## Reasoning",
    "## Findings",
    "## Cited evidence",
    "## Cross-family attestation",
)

VALID_VERDICTS: tuple[str, ...] = ("accept", "reject", "escalate")
VALID_SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "blocking")


class ReviewerOutputMalformed(Exception):
    """Raised when model output does not match the prompt contract."""


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    citation: str
    detail: str | None = None

    def to_schema_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "severity": self.severity,
            "title": self.title,
            "citation": self.citation,
        }
        if self.detail is not None:
            d["detail"] = self.detail[:2048]
        return d


@dataclass(frozen=True)
class CrossFamilyAttestation:
    reviewer_family: str
    patcher_family_observed: str
    rule_honored: bool

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "reviewer_family": self.reviewer_family,
            "patcher_family_observed": self.patcher_family_observed,
            "rule_honored": self.rule_honored,
        }


@dataclass(frozen=True)
class ReviewerParseResult:
    """Structured result of a successful parse."""

    kind: str  # "review" | "refusal"
    verdict: str | None = None
    reasoning: str | None = None
    findings: list[Finding] = field(default_factory=list)
    cited_evidence: list[str] = field(default_factory=list)
    cross_family: CrossFamilyAttestation | None = None
    refusal_rule: int | None = None
    refusal_reason: str | None = None
    raw_review_md: str | None = None  # for atomic-write to disk

    def to_schema_dict(self) -> dict[str, Any]:
        if self.kind != "review":
            raise ValueError("to_schema_dict() only valid for kind=review")
        return {
            "schema_version": SCHEMA_VERSION,
            "verdict": self.verdict,
            "reasoning": self.reasoning,
            "findings": [f.to_schema_dict() for f in self.findings],
            "cited_evidence": list(self.cited_evidence),
            "cross_family_attestation": self.cross_family.to_schema_dict() if self.cross_family else None,
        }


_WRAPPING_FENCE_RE = re.compile(
    r"^```(?:[a-zA-Z0-9_-]*)?\s*\n(?P<body>.*?)\n```\s*$",
    re.DOTALL,
)


def _strip_wrapping_code_fence(text: str) -> str:
    """Remove a markdown code fence that wraps the entire response.

    Only fires when ``` is the first AND last non-whitespace token; an
    embedded fence inside the review body is left alone.
    """
    m = _WRAPPING_FENCE_RE.match(text)
    if m is None:
        return text
    return m.group("body").strip()


_REVIEW_BLOCK_RE = re.compile(
    r"===\s*BEGIN review\.md\s*===\n(?P<body>.*?)\n===\s*END review\.md\s*===",
    re.DOTALL,
)
_REFUSAL_BLOCK_RE = re.compile(
    r"===\s*BEGIN refusal\s*===\n(?P<body>.*?)\n===\s*END refusal\s*===",
    re.DOTALL,
)


def parse_reviewer_output(raw: str) -> ReviewerParseResult:
    """Parse the model's raw text output into a structured result.

    Args:
        raw: model response text, as returned by the adapter.

    Returns:
        ReviewerParseResult with kind="review" or kind="refusal".

    Raises:
        ReviewerOutputMalformed: if the text violates the prompt contract.
    """
    if not isinstance(raw, str):
        raise ReviewerOutputMalformed(f"expected str, got {type(raw).__name__}")
    text = raw.strip()
    if not text:
        raise ReviewerOutputMalformed("model returned empty output")
    # Strip a wrapping markdown code-fence if present. Some models
    # (sonnet 4.6 in particular) habitually emit the entire response
    # inside ```...```. Surfaced by the first live reviewer run on
    # traefik 2026-04-27. The fence is a formatting artifact, not
    # contract content; tolerate but only if it wraps THE WHOLE thing.
    text = _strip_wrapping_code_fence(text)

    first = re.search(r"^===\s*BEGIN (review\.md|refusal)\s*===$", text, re.MULTILINE)
    if not first:
        raise ReviewerOutputMalformed(
            "no '=== BEGIN review.md ===' or '=== BEGIN refusal ===' marker found"
        )

    before = text[: first.start()].strip()
    if before:
        raise ReviewerOutputMalformed(
            "content before the first '=== BEGIN' marker is forbidden; "
            f"found {len(before)} chars of preamble"
        )

    if first.group(1) == "refusal":
        return _parse_refusal(text)
    return _parse_review(text)


# ─── review path ───────────────────────────────────────────────────────────


def _parse_review(text: str) -> ReviewerParseResult:
    stripped = text.lstrip()
    if not stripped.startswith("=== BEGIN review.md ==="):
        raise ReviewerOutputMalformed(
            "review path requires '=== BEGIN review.md ===' as the first non-whitespace line"
        )
    match = _REVIEW_BLOCK_RE.match(stripped)
    if not match:
        raise ReviewerOutputMalformed(
            "review output malformed: expected '=== BEGIN review.md === "
            "... === END review.md ===' in that order"
        )
    after = stripped[match.end():].strip()
    if after:
        raise ReviewerOutputMalformed(
            "content after '=== END review.md ===' is forbidden; "
            f"found {len(after)} chars of trailing prose"
        )

    body = match.group("body")
    sections = _split_sections(body)
    _validate_section_order(body)

    verdict_text = (sections.get("## Verdict") or "").strip()
    if verdict_text not in VALID_VERDICTS:
        raise ReviewerOutputMalformed(
            f"verdict must be one of {VALID_VERDICTS}; got {verdict_text!r}"
        )
    reasoning = (sections.get("## Reasoning") or "").strip()
    if not reasoning:
        raise ReviewerOutputMalformed("'## Reasoning' section is empty")

    findings = _parse_findings(sections.get("## Findings") or "", verdict_text)
    cited_evidence = _parse_bulleted_list(
        sections.get("## Cited evidence") or "",
        section_name="## Cited evidence",
    )
    if not cited_evidence:
        raise ReviewerOutputMalformed(
            "'## Cited evidence' must list at least one artifact (verdict "
            "without engaging the inputs is a structural fail)"
        )

    cross_family = _parse_cross_family(
        sections.get("## Cross-family attestation") or ""
    )

    return ReviewerParseResult(
        kind="review",
        verdict=verdict_text,
        reasoning=reasoning,
        findings=findings,
        cited_evidence=cited_evidence,
        cross_family=cross_family,
        raw_review_md=body.rstrip() + "\n",
    )


def _split_sections(body: str) -> dict[str, str]:
    """Split a markdown body into a dict keyed by `## Heading` lines."""
    sections: dict[str, str] = {}
    current_key: str | None = None
    current_lines: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("## "):
            if current_key is not None:
                sections[current_key] = "\n".join(current_lines).strip("\n")
            current_key = stripped
            current_lines = []
        elif current_key is not None:
            current_lines.append(line)
    if current_key is not None:
        sections[current_key] = "\n".join(current_lines).strip("\n")
    return sections


def _validate_section_order(body: str) -> None:
    """Enforce that the five required headings appear in the contracted order."""
    seen_positions: dict[str, int] = {}
    for i, line in enumerate(body.splitlines()):
        h = line.strip()
        if h in REQUIRED_REVIEW_HEADINGS and h not in seen_positions:
            seen_positions[h] = i
    missing = [h for h in REQUIRED_REVIEW_HEADINGS if h not in seen_positions]
    if missing:
        raise ReviewerOutputMalformed(
            "review.md is missing required level-2 headings: "
            + ", ".join(repr(h) for h in missing)
        )
    positions = [seen_positions[h] for h in REQUIRED_REVIEW_HEADINGS]
    if positions != sorted(positions):
        raise ReviewerOutputMalformed(
            "review.md headings out of contracted order; "
            f"expected {list(REQUIRED_REVIEW_HEADINGS)}"
        )
    for line in body.splitlines():
        if line.startswith("# ") and not line.startswith("## "):
            raise ReviewerOutputMalformed(
                "review.md contains a level-1 heading; contract forbids them"
            )


_FINDING_LINE_RE = re.compile(
    r"^-\s*severity:\s*(?P<severity>info|low|medium|high|blocking)\s*"
    r"—|\s*—\s*"  # placeholder (replaced below)
)


def _parse_findings(section_body: str, verdict: str) -> list[Finding]:
    """Parse the `## Findings` section into Finding entries.

    Format per line: `- severity: <s> — <title> — <citation>`
    Special case: the literal line `(none)` means an empty findings list.
    """
    text = section_body.strip()
    if text == "(none)":
        if verdict != "accept":
            raise ReviewerOutputMalformed(
                f"verdict={verdict!r} but '## Findings' is '(none)'; "
                f"non-accept verdicts MUST cite at least one finding"
            )
        return []
    findings: list[Finding] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not line.startswith("- "):
            raise ReviewerOutputMalformed(
                f"finding line must start with '- '; got {line!r}"
            )
        line = line[2:]
        # Format: "severity: <s> — <title> — <citation>"
        if not line.startswith("severity:"):
            raise ReviewerOutputMalformed(
                f"finding line must start with 'severity:'; got {line!r}"
            )
        rest = line[len("severity:"):].strip()
        # Split on em-dash with surrounding whitespace.
        parts = re.split(r"\s+—\s+", rest, maxsplit=2)
        if len(parts) < 3:
            raise ReviewerOutputMalformed(
                "finding line must contain three em-dash-separated fields "
                f"(severity, title, citation); got {raw_line!r}"
            )
        sev, title, citation = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if sev not in VALID_SEVERITIES:
            raise ReviewerOutputMalformed(
                f"finding severity must be one of {VALID_SEVERITIES}; got {sev!r}"
            )
        if not title:
            raise ReviewerOutputMalformed("finding title is empty")
        if not citation:
            raise ReviewerOutputMalformed("finding citation is empty")
        findings.append(Finding(severity=sev, title=title, citation=citation))
    if verdict == "accept":
        for f in findings:
            if f.severity in ("blocking", "high"):
                raise ReviewerOutputMalformed(
                    f"verdict=accept but a finding has severity={f.severity!r}; "
                    f"high or blocking findings must trigger reject or escalate"
                )
    return findings


def _parse_bulleted_list(section_body: str, *, section_name: str) -> list[str]:
    items: list[str] = []
    for raw in section_body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("- "):
            raise ReviewerOutputMalformed(
                f"{section_name}: every line must start with '- '; got {raw!r}"
            )
        items.append(line[2:].strip())
    return items


def _parse_cross_family(section_body: str) -> CrossFamilyAttestation:
    """Parse the cross-family attestation key:value lines."""
    fields: dict[str, str] = {}
    for raw in section_body.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^(reviewer_family|patcher_family_observed|rule_honored)\s*:\s*(.+)$", line)
        if not m:
            raise ReviewerOutputMalformed(
                "## Cross-family attestation: unexpected line "
                f"(expected reviewer_family / patcher_family_observed / rule_honored): {raw!r}"
            )
        fields[m.group(1)] = m.group(2).strip()
    missing = [k for k in ("reviewer_family", "patcher_family_observed", "rule_honored") if k not in fields]
    if missing:
        raise ReviewerOutputMalformed(
            f"## Cross-family attestation: missing keys: {missing}"
        )
    rule_honored_str = fields["rule_honored"].lower()
    if rule_honored_str not in ("true", "false"):
        raise ReviewerOutputMalformed(
            f"rule_honored must be 'true' or 'false'; got {fields['rule_honored']!r}"
        )
    return CrossFamilyAttestation(
        reviewer_family=fields["reviewer_family"],
        patcher_family_observed=fields["patcher_family_observed"],
        rule_honored=(rule_honored_str == "true"),
    )


# ─── refusal path ──────────────────────────────────────────────────────────


_RULE_LINE_RE = re.compile(r"^rule:\s*(\d+)\s*$")
_REASON_LINE_RE = re.compile(r"^reason:\s*(\S.*)$")


def _parse_refusal(text: str) -> ReviewerParseResult:
    stripped = text.lstrip()
    if not stripped.startswith("=== BEGIN refusal ==="):
        raise ReviewerOutputMalformed(
            "refusal path requires '=== BEGIN refusal ===' as the first non-whitespace line"
        )
    match = _REFUSAL_BLOCK_RE.match(stripped)
    if not match:
        raise ReviewerOutputMalformed(
            "refusal output malformed: expected '=== BEGIN refusal === ... === END refusal ==='"
        )
    after = stripped[match.end():].strip()
    if after:
        raise ReviewerOutputMalformed(
            f"content after '=== END refusal ===' is forbidden; found {len(after)} chars of trailing prose"
        )
    body_lines = [ln for ln in match.group("body").strip().splitlines() if ln.strip()]
    if len(body_lines) < 2:
        raise ReviewerOutputMalformed(
            "refusal body must contain a 'rule:' line and a 'reason:' line"
        )
    rule_match = _RULE_LINE_RE.match(body_lines[0])
    if not rule_match:
        raise ReviewerOutputMalformed("refusal body's first line must be 'rule: <integer>'")
    rule = int(rule_match.group(1))
    if rule < _REVIEWER_REFUSAL_RULE_MIN or rule > _REVIEWER_REFUSAL_RULE_MAX:
        raise ReviewerOutputMalformed(
            f"refusal rule must be in [{_REVIEWER_REFUSAL_RULE_MIN}, "
            f"{_REVIEWER_REFUSAL_RULE_MAX}]; got {rule}"
        )
    reason_match = _REASON_LINE_RE.match(body_lines[1])
    if not reason_match:
        raise ReviewerOutputMalformed("refusal body's second line must be 'reason: <one-line reason>'")
    return ReviewerParseResult(
        kind="refusal",
        refusal_rule=rule,
        refusal_reason=reason_match.group(1).strip(),
    )


__all__ = [
    "CrossFamilyAttestation",
    "Finding",
    "REQUIRED_REVIEW_HEADINGS",
    "ReviewerOutputMalformed",
    "ReviewerParseResult",
    "SCHEMA_VERSION",
    "VALID_SEVERITIES",
    "VALID_VERDICTS",
    "parse_reviewer_output",
]
