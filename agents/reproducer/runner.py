"""Reproducer runner. Mirrors agents/reviewer/runner.py's shape.

Entry point: `run_reproducer(inputs, adapter, sampling, prompt_path)`.

Reuses the Patcher's `ModelAdapter` Protocol (the model-call interface
is general; nothing about it is patcher-specific). The runner:

  1. assembles the user-content message from the bundle inputs PLUS
     the Patcher's outputs (patch.diff, patch-rationale.md);
  2. invokes the adapter once;
  3. parses the response;
  4. returns a structured result the executor writes to disk.

The runner enforces output SHAPE only. Execution-truth checks (does
the test actually emit the named signal? does the unpatched build
crash?) are Builder's territory. Per the 2026-04-28 architectural
split: runner owns shape; Builder owns execution truth; build.json
is exclusively Builder's.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.patcher.adapter import ModelAdapter, ModelResponse
from agents.reproducer.parser import (
    ReproducerOutputMalformed,
    ReproducerParseResult,
    parse_reproducer_output,
)


# max_tokens is 16384, not 8192: the three-block reproducer output (a full Nix
# expression, the predicted run log, and passthru-tests.json) after a large
# system prompt routinely ran past 8192 and truncated mid-output, losing the
# reproducer-log.txt / passthru-tests.json blocks. The larger ceiling is only an
# upper bound: a short reproducer still bills only the tokens it emits.
_DEFAULT_SAMPLING: dict[str, Any] = {
    "temperature": 0.0,
    "top_p": 1.0,
    "max_tokens": 16384,
}


@dataclass(frozen=True)
class ReproducerRunResult:
    parsed: ReproducerParseResult
    model_response: ModelResponse
    prompt_sha256: str
    user_content_sha256: str
    raw_response_sha256: str
    user_content_bytes: int
    prompt_bytes: int
    sampling: dict[str, Any]
    kind: str  # "reproducer" | "refusal"


def assemble_user_content(inputs: dict[str, Any]) -> str:
    """Render Reproducer inputs into the user-message text.

    Keys expected:
      finding, upstream_ref, impact, maintainers   (parsed JSON)
      package_source                              (str, original package.nix)
      patch_diff, patch_rationale_md              (str, Patcher outputs)
      package_source_path                         (str, informational)
      bundle_local_pocs                            (list[dict], prompt v5;
                                                   optional for backwards
                                                   compat. See execute._collect_bundle_local_pocs)
    """
    required = {
        "finding", "upstream_ref", "impact", "maintainers",
        "package_source", "patch_diff", "patch_rationale_md",
    }
    missing = required - set(inputs)
    if missing:
        raise ValueError(
            f"assemble_user_content: missing input keys: {sorted(missing)}"
        )

    import json as _json

    def j(o: Any) -> str:
        return _json.dumps(o, indent=2, sort_keys=True)

    pkg_path = inputs.get("package_source_path", "<package.nix>")
    parts: list[str] = [
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
        f"# {pkg_path} (pre-patch package definition)",
        inputs["package_source"],
        "",
        "# patch.diff (Patcher's emitted unified diff)",
        inputs["patch_diff"],
        "",
        "# patch-rationale.md (Patcher's emitted rationale)",
        inputs["patch_rationale_md"],
    ]

    # v5 grounding: surface bundle-local PoC artifacts under repro/.
    # When the bundle ships a PoC at repro/<name>.<ext> (e.g. a
    # fuzzer-attached crash file from upstream), the model sees the
    # path + sha256 + size, plus either inline content (small files)
    # or first/last 256-byte previews (oversized files). The path is
    # the authoritative reference the reproducer.nix should use; the
    # inlined / preview content is for the model to understand shape.
    pocs = inputs.get("bundle_local_pocs")
    if isinstance(pocs, list) and pocs:
        parts.append("")
        parts.append("# Bundle-local PoC artifacts (under repro/; v5 contract)")
        parts.append(j(pocs))

    return "\n".join(parts)


def run_reproducer(
    *,
    inputs: dict[str, Any],
    adapter: ModelAdapter,
    sampling: dict[str, Any] | None = None,
    prompt_path: Path,
) -> ReproducerRunResult:
    """Run the Reproducer once and parse its output.

    Args:
        inputs:      dict of bundle artifacts; see assemble_user_content().
        adapter:     a ModelAdapter (FakeAdapter for tests, AnthropicAdapter
                     for live runs). Reuses agents.patcher.adapter.
        sampling:    optional override of _DEFAULT_SAMPLING.
        prompt_path: path to the Reproducer system prompt.

    Returns:
        ReproducerRunResult with parse + sha256s + adapter response metadata.

    Raises:
        ReproducerOutputMalformed: if the model's output violates the contract.
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
    # Attach model context to ReproducerOutputMalformed so the executor can
    # persist `.reproducer-failures/<uuid>/raw-response.txt` for debugging.
    # Mirrors the Patcher failure-capture pattern (F19, 2026-05-25).
    try:
        parsed = parse_reproducer_output(response.text)
    except ReproducerOutputMalformed as exc:
        exc.raw_response = response.text or ""
        exc.raw_response_sha256 = raw_response_sha256
        exc.model_id = response.model_id
        exc.prompt_sha256 = prompt_sha256
        exc.user_content_sha256 = user_content_sha256
        raise

    return ReproducerRunResult(
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
    "ReproducerRunResult",
    "assemble_user_content",
    "run_reproducer",
]
