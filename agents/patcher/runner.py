"""Patcher runner: assembles the prompt, invokes the adapter, parses output.

Entry point: `run_patcher(inputs, adapter, sampling, prompt_path)`.

Scope constraints (deliberate):
  * This function only RUNS the Patcher role. It does not decide
    eligibility. It does not re-litigate the upstream ref. It does
    not walk the nixpkgs tree.
  * It expects inputs already resolved to parsed-JSON dicts (or
    raw text for the package source). The replay runner upstream
    handles file loading + sha256 verification.
  * It fails loudly on malformed model output.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.patcher.adapter import ModelAdapter, ModelResponse
from agents.patcher.parser import (
    PatcherOutputMalformed,
    PatcherParseResult,
    parse_patcher_output,
)


# Default sampling for Patcher — deterministic temp 0 to reduce run-to-run
# variance during prompt iteration. The runner's caller may override.
DEFAULT_SAMPLING: dict[str, Any] = {
    "temperature": 0.0,
    "top_p": 1.0,
    "max_tokens": 8192,
}


@dataclass(frozen=True)
class PatcherRunResult:
    """Everything the replay runner needs to record one Patcher invocation."""

    kind: str  # "patch" | "refusal"
    raw_response: str
    raw_response_sha256: str
    parsed: PatcherParseResult
    prompt_sha256: str
    prompt_bytes: int
    user_content_sha256: str
    user_content_bytes: int
    model_response: ModelResponse
    sampling: dict[str, Any]


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def assemble_user_content(inputs: dict[str, Any]) -> str:
    """Render Patcher inputs into the user-message text.

    `inputs` keys expected:
      finding          — parsed finding.json dict
      upstream_ref     — parsed upstream-ref.json dict
      impact           — parsed impact.json dict
      maintainers      — parsed maintainers.json dict
      package_source   — text (usually package.nix content)
      package_source_path — str relative path, informational
    """
    required = {"finding", "upstream_ref", "impact", "maintainers", "package_source"}
    missing = required - set(inputs)
    if missing:
        raise ValueError(f"assemble_user_content: missing input keys: {sorted(missing)}")

    def j(obj: Any) -> str:
        return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)

    path = inputs.get("package_source_path", "<package_source>")
    parts = [
        "# Patcher invocation — v1",
        "",
        "## finding.json",
        "```json",
        j(inputs["finding"]),
        "```",
        "",
        "## upstream-ref.json (qualifying fix target — treat as given truth)",
        "```json",
        j(inputs["upstream_ref"]),
        "```",
        "",
        "## impact.json",
        "```json",
        j(inputs["impact"]),
        "```",
        "",
        "## maintainers.json",
        "```json",
        j(inputs["maintainers"]),
        "```",
        "",
        f"## Package source at path: {path}",
        "```",
        inputs["package_source"],
        "```",
        "",
    ]

    # Source-backport strategy: surface the resolver-supplied upstream fix diff
    # as ground truth for the fix content. Only present when the resolver
    # authorized patch_strategy="source-backport" in upstream-ref.json.
    if inputs.get("patch_strategy") == "source-backport" and inputs.get("upstream_fix_patch"):
        parts += [
            "## patch_strategy: source-backport (resolver-authorized)",
            "Do NOT bump the version. Author the upstream fix below as an in-tree",
            "patch file under the package directory and wire it into the package's",
            "`patches = [ ... ]` list, per the v3 source-backport contract.",
            "",
            "## upstream-fix.patch (the upstream fix commit diff — ground truth for the fix content)",
            "```diff",
            inputs["upstream_fix_patch"].rstrip(),
            "```",
            "",
        ]

    parts.append("Produce the contracted output now.")
    return "\n".join(parts)


def run_patcher(
    *,
    inputs: dict[str, Any],
    adapter: ModelAdapter,
    sampling: dict[str, Any] | None = None,
    prompt_path: Path,
) -> PatcherRunResult:
    """Invoke the Patcher on one input bundle.

    Args:
        inputs: see assemble_user_content() for required keys.
        adapter: ModelAdapter implementation.
        sampling: sampling parameters (temperature, top_p, max_tokens).
        prompt_path: path to the Patcher system prompt (prompts/patcher.v1.md).

    Returns:
        PatcherRunResult with raw text, sha256s, parsed result, and
        the ModelResponse for replay-writer consumption.

    Raises:
        PatcherOutputMalformed: if the model response violates the
            prompt contract. The replay runner must treat this as a
            hard failure (write no outputs; record invocation with
            malformed flag).
        FileNotFoundError: if prompt_path does not exist.
    """
    if not prompt_path.is_file():
        raise FileNotFoundError(f"Patcher prompt not at {prompt_path}")

    system_prompt = prompt_path.read_text(encoding="utf-8")
    user_content = assemble_user_content(inputs)
    sampling_used = dict(DEFAULT_SAMPLING)
    if sampling:
        sampling_used.update(sampling)

    response = adapter.invoke(
        system_prompt=system_prompt,
        user_content=user_content,
        sampling=sampling_used,
    )
    raw = response.text or ""

    # fail LOUDLY on malformed output — no swallowing. Attach model context to
    # the exception so the executor can persist `.patcher-failures/<uuid>/raw-
    # response.txt` + `failure.json` for debugging without inventing model
    # state at the catch site. (Added 2026-05-25 with patcher.v2 / F19.)
    try:
        parsed = parse_patcher_output(raw)
    except PatcherOutputMalformed as exc:
        exc.raw_response = raw
        exc.raw_response_sha256 = _sha256_text(raw)
        exc.model_id = response.model_id
        exc.prompt_sha256 = _sha256_text(system_prompt)
        exc.user_content_sha256 = _sha256_text(user_content)
        raise

    return PatcherRunResult(
        kind=parsed.kind,
        raw_response=raw,
        raw_response_sha256=_sha256_text(raw),
        parsed=parsed,
        prompt_sha256=_sha256_text(system_prompt),
        prompt_bytes=len(system_prompt.encode("utf-8")),
        user_content_sha256=_sha256_text(user_content),
        user_content_bytes=len(user_content.encode("utf-8")),
        model_response=response,
        sampling=sampling_used,
    )
