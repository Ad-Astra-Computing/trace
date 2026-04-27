"""Scorer #1: schema-valid output.

Binary pass/fail. Score=1.0 iff ALL of:
  * patch.diff parses as a unified diff (at least one '--- ' / '+++ '
    file header pair AND at least one hunk header '@@')
  * patch.diff applies cleanly to the bundle's package.nix under
    `git apply --check` (catches the "looks right, won't apply"
    failure mode openssl_3 surfaced on 2026-04-27: missing trailing
    newline, wrong @@ line numbers, etc.)
  * patch-rationale.md contains the five SPEC §4 mandatory level-2
    headings, in the contracted order, with no level-1 heading

For Patcher refusal-shape invocations, the equivalent check runs against
refusal.json (the body must contain `rule` and `reason`). Score=1.0 iff
the file parses as JSON with both keys.

Rationale-completeness folds into this scorer (per MODEL_EVAL_PLAN.md
amendment).

The git-apply-check step is skipped (with details.git_apply_check =
"skipped: git not on PATH") when `git` is unavailable; a missing
`git` is not a scorer failure, just an inability to run the strict
gate. CI environments must have `git` installed for the strict gate
to operate.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from agents.scorers.types import SCORER_VERSION, ScorerResult


REQUIRED_RATIONALE_HEADINGS = (
    "## Upstream reference",
    "## Why this version",
    "## Why minimal",
    "## Alternatives rejected",
    "## Downstream risk",
)


class SchemaValidScorer:
    name = "schema-valid"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        outputs = invocation.get("outputs") or []
        out_paths = {o["path"] for o in outputs}

        # Refusal path
        if "refusal.json" in out_paths:
            return self._score_refusal(bundle_dir)

        # Patch path
        if {"patch.diff", "patch-rationale.md"} - out_paths:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=(
                    "patch invocation missing required output files; "
                    f"declared outputs = {sorted(out_paths)}"
                ),
                details={"missing_required_outputs": True},
            )
        return self._score_patch(bundle_dir)

    def _score_patch(self, bundle_dir: Path) -> ScorerResult:
        diff_path = bundle_dir / "patch.diff"
        rat_path = bundle_dir / "patch-rationale.md"
        pkg_path = bundle_dir / "package.nix"
        if not diff_path.is_file() or not rat_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="patch.diff or patch-rationale.md not on disk",
            )
        diff = diff_path.read_text()
        rationale = rat_path.read_text()

        diff_ok, diff_reason = _looks_like_unified_diff(diff)
        rat_ok, rat_reason = _rationale_has_required_headings(rationale)

        # Strict-apply gate. Skipped (informational) when git is not on
        # PATH; failed when git apply --check exits nonzero. The gate
        # closes the "looks right, won't apply cleanly" class openssl_3
        # surfaced on 2026-04-27.
        apply_ok: bool | None
        apply_reason: str
        if pkg_path.is_file():
            apply_ok, apply_reason = _git_apply_check(diff_path, pkg_path)
        else:
            apply_ok = None
            apply_reason = "skipped: package.nix not on disk in bundle_dir"

        all_ok = diff_ok and rat_ok and (apply_ok is not False)
        details = {
            "diff_ok": diff_ok,
            "diff_reason": diff_reason,
            "rationale_ok": rat_ok,
            "rationale_reason": rat_reason,
            "git_apply_check": apply_reason,
        }
        if all_ok:
            note = (
                "patch.diff parses as a unified diff, applies cleanly "
                "via git apply --check, and patch-rationale.md has all "
                "five required headings in order"
            )
            if apply_ok is None:
                note = (
                    "patch.diff parses as a unified diff and patch-"
                    "rationale.md has all five required headings in "
                    "order; git-apply-check was skipped"
                )
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=1.0,
                notes=note,
                details=details,
            )
        # Compose a single human note that names which checks failed.
        failed = []
        if not diff_ok:
            failed.append(f"diff: {diff_reason}")
        if not rat_ok:
            failed.append(f"rationale: {rat_reason}")
        if apply_ok is False:
            failed.append(f"git apply --check: {apply_reason}")
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=0.0,
            notes="; ".join(failed) or "schema-valid checks failed",
            details=details,
        )

    def _score_refusal(self, bundle_dir: Path) -> ScorerResult:
        ref_path = bundle_dir / "refusal.json"
        if not ref_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="refusal.json declared in invocation but not on disk",
            )
        try:
            body = json.loads(ref_path.read_text())
        except json.JSONDecodeError as exc:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=f"refusal.json is not valid JSON: {exc}",
            )
        if not isinstance(body, dict):
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="refusal.json must be a JSON object",
            )
        missing = [k for k in ("rule", "reason") if k not in body]
        if missing:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes=f"refusal.json missing required keys: {missing}",
                details={"missing_keys": missing},
            )
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=1.0,
            notes="refusal.json has rule and reason",
            details={"rule": body["rule"], "reason_len": len(str(body["reason"]))},
        )


def _git_apply_check(diff_path: Path, package_nix_path: Path) -> tuple[bool | None, str]:
    """Run `git apply --check` against a tmp index that holds package.nix.

    Returns:
      (True,  "ok: applies cleanly")          when the patch applies cleanly
      (False, "<short reason>")               when the patch fails to apply
      (None,  "skipped: <reason>")            when the check cannot run
                                              (git missing, env issue)
    """
    if not shutil.which("git"):
        return None, "skipped: git not on PATH"

    with tempfile.TemporaryDirectory(prefix="trace-schema-valid-") as tmp:
        tmpdir = Path(tmp)
        # Initialise a tiny git repo, copy package.nix in, commit it.
        # The diff's `--- a/package.nix` / `+++ b/package.nix` headers
        # need a matching working-tree path; copy under the same name.
        # `git -c user.name=...` flags pin the committer identity inline
        # so the call does not depend on the host's git global config
        # (CI runners often have none, and pytest's tmp_path may shadow
        # GIT_*_NAME/EMAIL env vars under sandboxing).
        committer_args = [
            "-c", "user.name=trace",
            "-c", "user.email=trace@invalid",
            "-c", "init.defaultBranch=main",
            "-c", "commit.gpgsign=false",
        ]
        try:
            subprocess.run(
                ["git", *committer_args, "init", "-q"],
                cwd=tmpdir, check=True,
                capture_output=True, text=True, timeout=30,
            )
            shutil.copyfile(package_nix_path, tmpdir / "package.nix")
            subprocess.run(
                ["git", *committer_args, "add", "package.nix"],
                cwd=tmpdir, check=True,
                capture_output=True, text=True, timeout=30,
            )
            subprocess.run(
                ["git", *committer_args, "commit", "-q", "-m", "init"],
                cwd=tmpdir, check=True,
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            err = (exc.stderr or "").strip() or (exc.stdout or "").strip()
            return None, f"skipped: git setup failed (exit {exc.returncode}): {err[:300]}"
        except subprocess.SubprocessError as exc:
            return None, f"skipped: git setup failed: {exc}"

        # Pass an absolute path because cwd=tmpdir; a relative diff_path
        # would be resolved against tmpdir and fail with "can't open patch".
        result = subprocess.run(
            ["git", *committer_args, "apply", "--check", str(diff_path.resolve())],
            cwd=tmpdir, check=False,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return True, "ok: applies cleanly"
        # Compose a tight failure reason; truncate stderr to keep the
        # scorer report compact.
        stderr = (result.stderr or "").strip()
        if not stderr:
            stderr = (result.stdout or "").strip() or f"exit {result.returncode}"
        return False, f"failed: {stderr[:400]}"


def _looks_like_unified_diff(text: str) -> tuple[bool, str]:
    if not text.strip():
        return False, "empty diff"
    has_minus = any(line.startswith("--- ") for line in text.splitlines())
    has_plus = any(line.startswith("+++ ") for line in text.splitlines())
    has_hunk = any(line.startswith("@@") for line in text.splitlines())
    if not (has_minus and has_plus):
        return False, "missing '--- ' / '+++ ' file header pair"
    if not has_hunk:
        return False, "missing '@@' hunk header"
    return True, "ok"


def _rationale_has_required_headings(rationale: str) -> tuple[bool, str]:
    lines = rationale.splitlines()
    seen: dict[str, int] = {}
    for i, line in enumerate(lines):
        h = line.strip()
        if h in REQUIRED_RATIONALE_HEADINGS and h not in seen:
            seen[h] = i
    missing = [h for h in REQUIRED_RATIONALE_HEADINGS if h not in seen]
    if missing:
        return False, f"missing required headings: {missing}"
    positions = [seen[h] for h in REQUIRED_RATIONALE_HEADINGS]
    if positions != sorted(positions):
        return False, "required headings out of contracted order"
    for line in lines:
        if line.startswith("# ") and not line.startswith("## "):
            return False, "level-1 heading present (forbidden by SPEC §4)"
    return True, "ok"
