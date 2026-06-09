"""Render a GitHub Actions step summary for the cert + steward workflows.

The cert (`bundle-linux-cert.yml`) and steward (`steward.yml`) workflows
produce JSON evidence — `build.json`, the OPA decision, the signed
`bundle.json` — but historically wrote nothing to `$GITHUB_STEP_SUMMARY`, so a
completed run's summary page said nothing about what actually happened. This
module turns that evidence into a compact Markdown verdict.

Design constraints:
  * **Never raise.** These steps run under `if: always()`, so on a failed run
    the evidence files may be missing or truncated. Missing data renders as
    "n/a", not a traceback that masks the real failure.
  * **Never emit secrets.** The renderer reads only known-safe fields
    (verdicts, build outcomes, public Rekor coordinates, the OIDC identity
    subject — all already public in the PR body). It never reads or echoes
    `cosign-cert.pem`, `bundle.sig`, or any token.

Usage (from a workflow step):
    python3 -m tools.trace_cli.ci_summary --mode cert \
        --bundle-dir "$RUNNER_TEMP/bundle" --bundle-name "$BUNDLE" \
        --kind auto-merge --decision "$RUNNER_TEMP/opa-decision.json" \
        --artifact-name "bundle-linux-cert-$BUNDLE-$GITHUB_RUN_ID" \
        >> "$GITHUB_STEP_SUMMARY"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

REKOR_ENTRY_API = "https://rekor.sigstore.dev/api/v1/log/entries?logIndex="

PASS = "✅"
FAIL = "❌"
NA = "➖"


def _load(path: Path) -> Any | None:
    """Read + parse JSON, returning None on any error (missing/garbage)."""
    try:
        # Tolerant decode: evidence files can embed arbitrary captured program
        # output; undecodable bytes must not crash this always()-run renderer.
        return json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError):  # ValueError covers json.JSONDecodeError
        return None


def _extract_decision(obj: Any) -> dict[str, Any] | None:
    """Normalize an OPA decision to ``{"allow": bool, "deny": [...]}``.

    Accepts both the raw `opa eval --format=json` envelope
    (``result[0].expressions[0].value``) and an already-unwrapped decision
    dict. Returns None when neither shape is present.
    """
    if not isinstance(obj, dict):
        return None
    if "allow" in obj or "deny" in obj:
        return {"allow": bool(obj.get("allow", False)), "deny": obj.get("deny", []) or []}
    try:
        value = obj["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    return {"allow": bool(value.get("allow", False)), "deny": value.get("deny", []) or []}


def _deny_table(deny: list[dict[str, Any]]) -> str:
    rows = ["", "| Rule | Message |", "|---|---|"]
    for d in deny:
        rule = str(d.get("rule_id", "?")).replace("|", "\\|")
        msg = str(d.get("message", "")).replace("|", "\\|").replace("\n", " ")
        rows.append(f"| `{rule}` | {msg} |")
    return "\n".join(rows)


def _signal_match(
    build: dict[str, Any], log_text: str, name: str, observed_key: str
) -> tuple[str, bool]:
    """Whether the SIGNAL_<name> line from the reproducer log appears verbatim
    in the corresponding build.json observed output. Returns (cell, ok) where
    ok mirrors the workflow's `Verify SIGNAL substrings present` gate: a
    missing signal line or an absent substring both fail it."""
    sig = None
    for line in log_text.splitlines():
        stripped = line.strip()
        prefix = f"{name}:"
        if stripped.startswith(prefix):
            sig = stripped[len(prefix):].strip()
            break
    if not sig:
        return f"{FAIL} no signal line", False
    observed = (build.get(observed_key, {}) or {}).get("stdout_stderr", "")
    if sig in observed:
        return f"{PASS} present", True
    return f"{FAIL} absent", False


def render_cert_summary(
    *,
    bundle_dir: Path,
    bundle_name: str,
    kind: str | None,
    decision_path: Path | None,
    artifact_name: str | None,
) -> str:
    build = _load(bundle_dir / "build.json") or {}
    decision = _extract_decision(_load(decision_path)) if decision_path else None
    log_path = bundle_dir / "reproducer-log.txt"
    try:
        # Tolerant decode — reproducer logs carry raw program output (ASAN
        # traces etc.) that may not be valid UTF-8; never raise here.
        log_text = log_path.read_text(errors="replace") if log_path.is_file() else ""
    except OSError:
        log_text = ""

    applied = build.get("patch_apply", {}).get("applied")
    built = build.get("patched_build", {}).get("outcome")
    host = build.get("host", {}).get("system")

    def mark(ok: bool | None, label_true: str, label_false: str) -> str:
        if ok is None:
            return f"{NA} n/a"
        return f"{PASS} {label_true}" if ok else f"{FAIL} {label_false}"

    rows = [
        "| Check | Result |",
        "|---|---|",
        f"| Bundle kind | {kind or 'n/a'} |",
        f"| Host | {host or 'n/a'} |",
        f"| Patch applied | {mark(applied if applied is not None else None, 'true', 'false')} |",
        f"| Patched build | {mark(built == 'succeeded' if built else None, built or '', built or '')} |",
    ]
    # SIGNAL match mirrors the workflow's verify-signals gate. When the log is
    # absent the gate is skipped (refusal-shaped bundles), so signals don't
    # constrain green; when present, both must match for the cert to be green.
    signals_ok = True
    if log_text:
        cell_u, ok_u = _signal_match(build, log_text, "SIGNAL_UNPATCHED", "unpatched")
        cell_p, ok_p = _signal_match(build, log_text, "SIGNAL_PATCHED", "patched")
        rows.append(f"| SIGNAL_UNPATCHED | {cell_u} |")
        rows.append(f"| SIGNAL_PATCHED | {cell_p} |")
        signals_ok = ok_u and ok_p

    # The cert job only *gates* on the Steward verdict for auto-merge bundles
    # (see the workflow's "Verify Steward verdict matches bundle.kind" step).
    # For human-review-required / advisory-only kinds a deny set is expected and
    # the job still succeeds, so the verdict is informational there — a deny
    # must not paint those runs red.
    verdict_gates = kind == "auto-merge"
    deny: list[dict[str, Any]] = []
    if decision is None:
        rows.append(f"| Steward verdict | {NA} n/a |")
        verdict_ok: bool | None = None
    else:
        deny = decision["deny"]
        allowed = decision["allow"] and not deny
        verdict_ok = allowed
        if allowed:
            rows.append(f"| Steward verdict | {PASS} allow (0 deny) |")
        elif verdict_gates:
            rows.append(f"| Steward verdict | {FAIL} deny ({len(deny)} rule(s)) |")
        else:
            rows.append(f"| Steward verdict | {NA} deny ({len(deny)} rule(s)) — informational for {kind} |")

    build_ok = applied is True and built == "succeeded" and host == "x86_64-linux"
    verdict_blocks = verdict_gates and verdict_ok is not True
    # The Steward eval step runs for every bundle kind, so a MISSING decision
    # is an infra/job failure (not an informational deny) and can never be a
    # successful cert — even for human-review/advisory kinds.
    green = build_ok and signals_ok and decision is not None and not verdict_blocks
    if green and verdict_gates:
        banner = f"### {PASS} CERT GREEN"
    elif green:
        banner = f"### {PASS} CERT COMPLETE ({kind or 'unknown kind'})"
    else:
        banner = f"### {FAIL} CERT FAILED"

    parts = [f"## Bundle Linux cert — `{bundle_name}`", "", banner, "", "\n".join(rows)]
    if deny:
        parts.append(_deny_table(deny))
    if artifact_name:
        parts += ["", f"Artifacts: `{artifact_name}`"]
    return "\n".join(parts) + "\n"


def render_steward_summary(
    *,
    bundle_dir: Path,
    bundle_name: str,
    decision_path: Path | None,
    artifact_name: str | None,
    verified: str | None = None,
) -> str:
    """`verified` is the GitHub Actions `outcome` of the "Verify signature
    against locked identity policy" step ('success' / 'failure' / 'skipped' /
    'cancelled' / '' / None). A populated Rekor index proves cosign signed, but
    only a 'success' here proves the signature verifies under the locked
    identity policy — so the green "SIGNED" banner requires both. None/'' means
    the caller didn't pass it (don't downgrade)."""
    bundle = _load(bundle_dir / "bundle.json") or {}
    sm = bundle.get("signed_manifest", {}) or {}
    decision = _extract_decision(_load(decision_path)) if decision_path else None

    rekor_idx = sm.get("rekor_log_index")
    # When the workflow passes an explicit outcome, only 'success' proves the
    # signature verified under the locked policy — 'failure'/'cancelled'/
    # 'skipped' all mean it did NOT verify. An absent/empty value means the
    # caller didn't supply it (unit-test callers, older invocations): treat as
    # unknown and don't downgrade.
    verify_known = bool(verified)
    verify_ok = (not verify_known) or verified == "success"
    verify_unverified = verify_known and not verify_ok

    # Three decision states — a MISSING decision (gate step never ran / failed
    # before writing the file, since this summary runs under `if: always()`)
    # is distinct from an explicit deny. Collapsing missing→deny would dress an
    # infra failure up as a policy denial.
    if decision is None:
        allow: bool | None = None
        deny: list[dict[str, Any]] = []
        signed = False
        verdict_cell = f"{NA} n/a (no decision recorded)"
        banner = f"### {NA} NO STEWARD DECISION (run failed before the gate)"
    else:
        deny = decision["deny"]
        allow = decision["allow"] and not deny
        # "signed" (green) means: gate allowed, Rekor index landed, AND the
        # signature verified under the locked identity policy.
        signed = allow and rekor_idx is not None and verify_ok
        if not allow:
            verdict_cell = f"{FAIL} deny"
            banner = f"### {FAIL} DENIED (signing skipped)"
        elif signed:
            verdict_cell = f"{PASS} allow"
            banner = f"### {PASS} ALLOWED + SIGNED"
        elif rekor_idx is not None and verify_unverified:
            # Signed (Rekor index present), but the verify-signature step did
            # not succeed (failed / cancelled / skipped) — not policy-verified.
            verdict_cell = f"{PASS} allow"
            banner = f"### {FAIL} SIGNED BUT SIGNATURE NOT VERIFIED (verify: {verified})"
        else:
            # Allowed but no Rekor index = cosign signing / Rekor population
            # failed. The gate+sign workflow's whole job is to emit a signed,
            # verifiable artifact, so this is a FAILURE, not a pass.
            verdict_cell = f"{PASS} allow"
            banner = f"### {FAIL} ALLOWED BUT SIGNING FAILED (no Rekor index)"

    if signed:
        signed_cell = f"{PASS} cosign keyless OIDC (verified)"
    elif allow and rekor_idx is not None and verify_unverified:
        signed_cell = f"{FAIL} signed, but not policy-verified ({verified})"
    elif allow:  # allowed yet unsigned → signing failed
        signed_cell = f"{FAIL} signing failed"
    else:  # denied or no-decision → signing legitimately did not run
        signed_cell = f"{NA} no"

    rows = [
        "| Field | Value |",
        "|---|---|",
        f"| Verdict | {verdict_cell} |",
        f"| Signed | {signed_cell} |",
    ]
    if rekor_idx is not None:
        rows.append(f"| Rekor log index | `{rekor_idx}` |")
        rows.append(f"| Rekor entry | {REKOR_ENTRY_API}{rekor_idx} |")
    if sm.get("rekor_uuid"):
        rows.append(f"| Rekor UUID | `{sm['rekor_uuid']}` |")
    if sm.get("identity_subject"):
        rows.append(f"| Identity subject | `{sm['identity_subject']}` |")
    if sm.get("identity_issuer"):
        rows.append(f"| OIDC issuer | `{sm['identity_issuer']}` |")

    parts = [f"## Steward gate + sign — `{bundle_name}`", "", banner, "", "\n".join(rows)]
    if deny:
        parts.append(_deny_table(deny))
    if artifact_name:
        parts += ["", f"Artifacts: `{artifact_name}`"]
    return "\n".join(parts) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Render a GitHub Actions step summary.")
    p.add_argument("--mode", choices=["cert", "steward"], required=True)
    p.add_argument("--bundle-dir", type=Path, required=True)
    p.add_argument("--bundle-name", required=True)
    p.add_argument("--kind", default=None, help="bundle kind (cert mode)")
    p.add_argument("--decision", type=Path, default=None, help="OPA / steward decision JSON")
    p.add_argument("--artifact-name", default=None)
    p.add_argument(
        "--verified",
        default=None,
        help="steward mode: GitHub Actions outcome of the verify-signature step",
    )
    args = p.parse_args(argv)

    if args.mode == "cert":
        out = render_cert_summary(
            bundle_dir=args.bundle_dir,
            bundle_name=args.bundle_name,
            kind=args.kind,
            decision_path=args.decision,
            artifact_name=args.artifact_name,
        )
    else:
        out = render_steward_summary(
            bundle_dir=args.bundle_dir,
            bundle_name=args.bundle_name,
            decision_path=args.decision,
            artifact_name=args.artifact_name,
            verified=args.verified,
        )
    # Print to stdout; the workflow redirects into $GITHUB_STEP_SUMMARY.
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
