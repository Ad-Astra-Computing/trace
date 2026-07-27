"""Reviewer runner. Mirrors agents/patcher/runner.py's shape.

Entry point: `run_reviewer(inputs, adapter, sampling, prompt_path)`.

Reuses the Patcher's `ModelAdapter` Protocol (the model-call interface
is general; nothing about it is patcher-specific). The runner:

  1. assembles the user-content message from the bundle inputs PLUS
     the Patcher's outputs (patch.diff, patch-rationale.md);
  2. invokes the adapter once;
  3. parses the response;
  4. returns a structured result the executor writes to disk.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.patcher.adapter import ModelAdapter, ModelResponse
from agents.reviewer.parser import (
    ReviewerOutputMalformed,
    ReviewerParseResult,
    parse_reviewer_output,
)


_DEFAULT_SAMPLING: dict[str, Any] = {
    "temperature": 0.0,
    "top_p": 1.0,
    "max_tokens": 8192,
}


@dataclass(frozen=True)
class ReviewerRunResult:
    parsed: ReviewerParseResult
    model_response: ModelResponse
    prompt_sha256: str
    user_content_sha256: str
    raw_response_sha256: str
    user_content_bytes: int
    prompt_bytes: int
    sampling: dict[str, Any]
    kind: str  # "review" | "refusal"


def assemble_user_content(inputs: dict[str, Any]) -> str:
    """Render Reviewer inputs into the user-message text.

    Keys expected:
      finding, upstream_ref, impact, maintainers   (parsed JSON)
      package_source                              (str, original package.nix)
      patch_diff, patch_rationale_md              (str, Patcher outputs)
      package_source_path, patch_diff_path, ...    (informational)
      model_attestation_context                   (dict, prompt v2; optional
                                                   for backwards compat with
                                                   v1 prompt or callers that
                                                   bypass the executor)
    """
    required = {
        "finding", "upstream_ref", "impact", "maintainers",
        "package_source", "patch_diff", "patch_rationale_md",
    }
    missing = required - set(inputs)
    if missing:
        raise ValueError(f"assemble_user_content: missing input keys: {sorted(missing)}")

    import json as _json

    def j(o: Any) -> str:
        return _json.dumps(o, indent=2, sort_keys=True)

    parts: list[str] = []

    # v2 grounding: surface the model attestation context block at the
    # very top so the Reviewer sees it before reading the bundle.
    # Omitted when the executor (or test caller) doesn't supply one —
    # the v2 prompt's "copy verbatim" instruction degrades to a fall-
    # back where the model sees no block and must hand-derive the
    # values, which is the v1 behavior.
    mac = inputs.get("model_attestation_context")
    if isinstance(mac, dict) and mac:
        parts.append("# Model attestation context (executor-supplied; load-bearing — copy verbatim)")
        parts.append(
            f"reviewer_model_id: {mac.get('reviewer_model_id', '<unknown>')}"
        )
        parts.append(
            f"reviewer_family: {mac.get('reviewer_family', '<unknown>')}"
        )
        parts.append(
            f"patcher_model_id: {mac.get('patcher_model_id', '<unknown>')}"
        )
        parts.append(
            f"patcher_family: {mac.get('patcher_family', '<unknown>')}"
        )
        parts.append(
            "cross_family_rule_honored_expected: "
            + ("true" if mac.get("cross_family_rule_honored_expected") else "false")
        )
        # v10 adaptation lane: the deterministic bootstrap verdict of whether
        # upstream-fix.patch applies to the pinned base. Rendered only for
        # source-backports that carry it. `false` = adaptation lane (judge
        # semantic equivalence against source-context/); `true` = verbatim lane.
        av = inputs.get("applies_verbatim")
        if av is not None:
            parts.append("applies_verbatim: " + ("true" if av else "false"))
        # v10 adaptation lane: the executor's deterministic applicability attestation
        # for the canonical patch.diff. Mechanical applicability is machine-verified
        # here, so the Reviewer must NOT re-litigate whether the patch applies — it
        # judges semantic equivalence. Rendered only when present.
        pa = mac.get("patch_applicability")
        if isinstance(pa, dict):
            parts.append(
                "patch_applicability: applies_at_fuzz0="
                + ("true" if pa.get("applies_at_fuzz0") else "false")
                + " unique_source_match="
                + ("true" if pa.get("unique_source_match") else "false")
                + f" (canonicalizer {pa.get('canonicalizer_version', '<unknown>')}) "
                + "— mechanical applicability is machine-attested; assess semantic "
                "equivalence, not whether the patch applies"
            )
        parts.append("")

    pkg_path = inputs.get("package_source_path", "<package.nix>")
    parts.extend([
        "# finding.json",
        j(inputs["finding"]),
        "",
        "# upstream-ref.json",
        j(inputs["upstream_ref"]),
        "",
        "# impact.json",
        j(inputs["impact"]),
        "",
        "# maintainers.json",
        j(inputs["maintainers"]),
        "",
        f"# {pkg_path} (original; pre-patch)",
        inputs["package_source"],
        "",
        "# patch.diff (Patcher's emitted unified diff)",
        inputs["patch_diff"],
        "",
        "# patch-rationale.md (Patcher's emitted rationale)",
        inputs["patch_rationale_md"],
    ])

    # Source-backport: supply the resolver's upstream fix diff as ground truth.
    # The Patcher authored an in-tree backport (a new .patch file + a package.nix
    # patches=[] wiring) instead of a version bump; the Reviewer must verify the
    # AUTHORED patch content faithfully transcribes THIS upstream fix (do not
    # check against any remembered/assumed version of the fix), and that the
    # package.nix edit only adds the patch (no version/hash/build changes).
    if inputs.get("patch_strategy") == "source-backport" and inputs.get("upstream_fix_patch"):
        parts.extend([
            "",
            "# upstream-fix.patch (resolver-supplied GROUND TRUTH — the upstream fix commit diff)",
            "# Verify the authored patch.diff transcribes THIS diff faithfully. Do not",
            "# compare against any fix you recall from training; this file is authoritative.",
            inputs["upstream_fix_patch"],
        ])

    # v10 adaptation lane: the pinned PRE-PATCH source of the files the authored
    # patch touches. This is the actual code the adaptation is applied to — the
    # Reviewer's ground truth for judging that the adaptation applies to the
    # pinned base and uses only constructs present there (not the upstream fix's
    # constructs). Present only when applies_verbatim is false.
    source_context = inputs.get("source_context")
    if isinstance(source_context, dict) and source_context:
        parts.append("")
        parts.append(
            "# source-context/ (pinned PRE-PATCH source of the affected files — "
            "adaptation-lane ground truth)"
        )
        parts.append(
            "# The authored patch is applied to THIS code. Judge that every -/context"
        )
        parts.append(
            "# line exists here and that + lines use only constructs present here."
        )
        for rel in sorted(source_context):
            parts.append(f"## source-context/{rel}")
            parts.append(source_context[rel])

    return "\n".join(parts)


def run_reviewer(
    *,
    inputs: dict[str, Any],
    adapter: ModelAdapter,
    sampling: dict[str, Any] | None = None,
    prompt_path: Path,
) -> ReviewerRunResult:
    """Run the Reviewer once and parse its output.

    Args:
        inputs:      dict of bundle artifacts; see assemble_user_content().
        adapter:     a ModelAdapter (FakeAdapter for tests, AnthropicAdapter
                     for live runs). Reuses agents.patcher.adapter; nothing
                     about it is patcher-specific.
        sampling:    optional override of _DEFAULT_SAMPLING.
        prompt_path: path to the Reviewer system prompt
                     (prompts/reviewer.v1.md by default for the executor).

    Returns:
        ReviewerRunResult with parse + sha256s + adapter response metadata.

    Raises:
        ReviewerOutputMalformed: if the model's output violates the contract.
    """
    system_prompt = prompt_path.read_text()
    prompt_bytes = len(system_prompt.encode("utf-8"))
    prompt_sha256 = _sha256_text(system_prompt)

    user_content = assemble_user_content(inputs)
    user_content_bytes = len(user_content.encode("utf-8"))
    user_content_sha256 = _sha256_text(user_content)

    sampling_used: dict[str, Any] = dict(_DEFAULT_SAMPLING)
    if sampling:
        sampling_used.update(sampling)

    response = adapter.invoke(
        system_prompt=system_prompt,
        user_content=user_content,
        sampling=sampling_used,
    )
    raw_response_sha256 = _sha256_text(response.text)
    # Attach model context to ReviewerOutputMalformed so the executor can
    # persist `.reviewer-failures/<uuid>/raw-response.txt` for debugging.
    # Mirrors the Patcher failure-capture pattern (F19, 2026-05-25).
    try:
        parsed = parse_reviewer_output(response.text)
    except ReviewerOutputMalformed as exc:
        exc.raw_response = response.text or ""
        exc.raw_response_sha256 = raw_response_sha256
        exc.model_id = response.model_id
        exc.prompt_sha256 = prompt_sha256
        exc.user_content_sha256 = user_content_sha256
        # Carry the full response so the executor can recover this failed
        # attempt's realized token usage — a retried review must bill the
        # spend of every attempt, not only the one that finally conformed.
        exc.model_response = response
        raise

    return ReviewerRunResult(
        parsed=parsed,
        model_response=response,
        prompt_sha256=prompt_sha256,
        user_content_sha256=user_content_sha256,
        raw_response_sha256=raw_response_sha256,
        user_content_bytes=user_content_bytes,
        prompt_bytes=prompt_bytes,
        sampling=sampling_used,
        kind=parsed.kind,
    )


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


__all__ = [
    "ReviewerRunResult",
    "assemble_user_content",
    "run_reviewer",
]
