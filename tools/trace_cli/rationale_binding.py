"""Bind a Patcher's rationale claims to the lines its payload actually adds.

`patch-rationale.md` is prose the Patcher writes about its own diff, and
nothing has ever checked the two against each other. On the assimp
CVE-2026-82591 adaptation canary the model authored a patch that closes the
overflow and then described three changes the payload does not contain,
including a `mVertices.resize(iNewIndex)` trim whose absence leaves
uninitialised entries in the imported mesh. The cross-family Reviewer read
both files and accepted it.

Under `prompts/patcher.v5.md` the `## Why minimal` section is no longer free
prose: it is a list of numbered claims, each carrying at least one
`Diff Line:` citation quoting a line the patch adds. That makes the model's
own account of its work falsifiable without judgment, which is what this
module does:

  * every `[CLAIM-N]` carries at least one citation (no phantom claims), and
  * every cited line really is an added line of the source patch.

A claim about a change the diff does not make has nothing to cite, so it
fails here rather than reaching a Reviewer that may or may not notice. The
check is free and runs before Reviewer spend.

Coverage in the other direction — added lines no claim cites — is computed
and recorded but does NOT gate. A closing brace and a blank line are added
lines too, and requiring the model to cite them would buy noise rather than
evidence. The record is there so a later slice can ask what it costs.

Bundles whose rationale carries no claim list at all (every corpus bundle
authored under patcher.v2.2 / v3 / v4) are reported `not-applicable`: this
contract arrived with v5 and does not reach back over signed evidence. That
compatibility is keyed on the prompt the bundle's own replay record names, not
on the absence of claims — otherwise a v5 Patcher could escape the gate by
writing prose, which is the failure the gate exists to catch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from . import nested_patch


SCHEMA_VERSION = "1.0.0"

VERDICT_BOUND = "bound"
VERDICT_UNBOUND = "unbound"
VERDICT_NOT_APPLICABLE = "not-applicable"

# Patcher prompts whose contract requires the `## Why minimal` claim list. A
# bundle whose replay record names one of these and carries no claims has
# violated its contract, and is `unbound` rather than legacy. Add a prompt here
# when it adopts the claim schema.
CLAIM_REQUIRING_PROMPTS = frozenset({"prompts/patcher.v5.md"})

_WHY_MINIMAL_HEADING = "## Why minimal"
_CLAIM_RE = re.compile(r"^-\s+\[CLAIM-(\d+)\]\s*(.*)$")
_CITATION_RE = re.compile(r"^\s+-\s+Diff Line:\s*`(.*)`\s*$")
_SECTION_RE = re.compile(r"^##\s+\S")
# A hunk header carries the line budget of each side, which is what lets the
# walk tell an added line from a file header: `+++index;` at column zero is a
# real added pre-increment, and only the budget says which region it is in.
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


class RationaleBindingError(ValueError):
    """The rationale's claim list is structurally unreadable."""


@dataclass(frozen=True)
class Citation:
    text: str
    matched: bool
    match_kind: str  # "exact" | "whitespace-normalized" | "wiring" | "none"

    def to_dict(self) -> dict[str, Any]:
        return {"text": self.text, "matched": self.matched, "match_kind": self.match_kind}


@dataclass(frozen=True)
class Claim:
    claim_id: int
    text: str
    citations: list[Citation] = field(default_factory=list)

    @property
    def bound(self) -> bool:
        return bool(self.citations) and all(c.matched for c in self.citations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "text": self.text,
            "citations": [c.to_dict() for c in self.citations],
            "bound": self.bound,
        }


@dataclass(frozen=True)
class BindingResult:
    verdict: str
    claims: list[Claim] = field(default_factory=list)
    uncited_added_lines: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.verdict in (VERDICT_BOUND, VERDICT_NOT_APPLICABLE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "verdict": self.verdict,
            "claims": [c.to_dict() for c in self.claims],
            "uncited_added_lines": list(self.uncited_added_lines),
            "problems": list(self.problems),
        }


def _why_minimal_body(rationale_text: str) -> list[str] | None:
    """Return the lines of the `## Why minimal` section, or None if absent."""
    lines = rationale_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == _WHY_MINIMAL_HEADING:
            start = i + 1
            break
    if start is None:
        return None
    body: list[str] = []
    for line in lines[start:]:
        if _SECTION_RE.match(line):
            break
        body.append(line)
    return body


def parse_claims(rationale_text: str) -> list[Claim]:
    """Read the numbered claims and their citations out of `## Why minimal`.

    Returns an empty list when the section is absent or carries no claim
    marker at all; the caller distinguishes that from a malformed list.

    Raises RationaleBindingError when the list is present but unreadable: a
    duplicate or non-sequential claim id, or a citation that precedes any
    claim. Those are contract violations rather than a legacy rationale.
    """
    body = _why_minimal_body(rationale_text)
    if body is None:
        return []
    claims: list[tuple[int, str, list[str]]] = []
    for line in body:
        m = _CLAIM_RE.match(line)
        if m:
            claims.append((int(m.group(1)), m.group(2).strip(), []))
            continue
        c = _CITATION_RE.match(line)
        if c:
            if not claims:
                raise RationaleBindingError(
                    "a `Diff Line:` citation precedes the first [CLAIM-N] marker")
            claims[-1][2].append(c.group(1))
    if not claims:
        return []
    ids = [cid for cid, _, _ in claims]
    if len(set(ids)) != len(ids):
        raise RationaleBindingError(f"duplicate claim ids in `## Why minimal`: {ids}")
    if ids != list(range(1, len(ids) + 1)):
        raise RationaleBindingError(
            f"claim ids must run 1..N in order, got {ids}")
    return [Claim(cid, text, [Citation(t, False, "none") for t in cites])
            for cid, text, cites in claims]


def _added_lines(patch_diff_text: str) -> list[str]:
    """Every line the bundle's SOURCE patch adds, `+` prefix stripped.

    Reads through `nested_patch` so the nested (`CVE-XXXX.patch` added to the
    package dir) and flat (source files edited directly) shapes are handled by
    the same code path the apply gate uses. `package.nix` wiring is not source
    and is excluded by that extraction.
    """
    source_patch, _names = nested_patch.extract_nested_source_patch(patch_diff_text)
    out: list[str] = []
    old_budget = new_budget = 0  # >0 means we are inside a hunk body
    for line in source_patch.splitlines():
        if old_budget <= 0 and new_budget <= 0:
            m = _HUNK_HEADER_RE.match(line)
            if m:
                old_budget = int(m.group(1)) if m.group(1) is not None else 1
                new_budget = int(m.group(2)) if m.group(2) is not None else 1
            # Outside a hunk body every line is header material (`--- `, `+++ `,
            # `diff --git`, `index`), never content.
            continue
        if line.startswith("\\"):  # "\ No newline at end of file" — not content
            continue
        if line.startswith("-"):
            old_budget -= 1
        elif line.startswith("+"):
            new_budget -= 1
            out.append(line[1:])
        else:
            old_budget -= 1
            new_budget -= 1
    return out


def _wiring_added_lines(patch_diff_text: str) -> set[str]:
    """Added lines belonging to a `package.nix` hunk, `+` prefix stripped.

    The prompt tells the Patcher that wiring the new patch into `patches = [ ]`
    is not a behavioral change and does not satisfy a claim. A claim that cites
    one is a contract violation, but it is a different violation from citing a
    line that is nowhere in the diff, and the operator needs to be told which.
    """
    out: set[str] = set()
    in_package_nix = False
    old_budget = new_budget = 0
    for line in patch_diff_text.splitlines():
        # A `diff --git` at column zero starts a new file and ends whatever hunk
        # preceded it. Resetting here keeps a hunk header whose counts overshoot
        # its body from swallowing the next file's header lines. Content can
        # never reach this branch: an added or context line carries its own
        # `+`, `-` or space prefix first.
        if line.startswith("diff --git "):
            old_budget = new_budget = 0
            in_package_nix = False
            continue
        if old_budget <= 0 and new_budget <= 0:
            if line.startswith("+++ "):
                # A unified-diff header may carry a timestamp after a tab.
                target = line[4:].split("\t", 1)[0].strip()
                if target.startswith(("a/", "b/")):
                    target = target[2:]
                in_package_nix = PurePosixPath(target).name == "package.nix"
                continue
            m = _HUNK_HEADER_RE.match(line)
            if m:
                old_budget = int(m.group(1)) if m.group(1) is not None else 1
                new_budget = int(m.group(2)) if m.group(2) is not None else 1
            continue
        if line.startswith("\\"):
            continue
        if line.startswith("-"):
            old_budget -= 1
        elif line.startswith("+"):
            new_budget -= 1
            if in_package_nix:
                out.add(line[1:])
        else:
            old_budget -= 1
            new_budget -= 1
    return out


def patcher_prompt_path(bundle_dir: Path) -> str | None:
    """The prompt path the bundle's replay record names for its last Patcher run.

    None when there is no replay record, no Patcher role, or no invocation —
    a bundle the Patcher has not run against yet.
    """
    import json

    replay = bundle_dir / "replay.json"
    if not replay.is_file():
        return None
    try:
        doc = json.loads(replay.read_text())
    except (ValueError, OSError):
        return None
    for role in doc.get("roles") or ():
        if role.get("role") != "patcher":
            continue
        invocations = role.get("invocations") or ()
        for inv in reversed(list(invocations)):
            path = (inv.get("prompt") or {}).get("path")
            if path:
                return str(path)
    return None


def check_binding(
    rationale_text: str,
    patch_diff_text: str,
    *,
    requires_claims: bool = False,
) -> BindingResult:
    """Check every rationale claim against the lines the payload adds.

    `requires_claims` says the Patcher prompt that produced this rationale
    contracts for a claim list, so an absent list is a violation rather than a
    legacy rationale.
    """
    try:
        claims = parse_claims(rationale_text)
    except RationaleBindingError as exc:
        return BindingResult(VERDICT_UNBOUND, problems=[str(exc)])
    if not claims:
        if requires_claims:
            return BindingResult(VERDICT_UNBOUND, problems=[
                "the Patcher prompt contracts for a `## Why minimal` claim list "
                "and the rationale carries none"])
        return BindingResult(VERDICT_NOT_APPLICABLE)

    try:
        added = _added_lines(patch_diff_text)
    except nested_patch.NestedPatchError as exc:
        return BindingResult(
            VERDICT_UNBOUND, claims=claims,
            problems=[f"patch.diff has no extractable source patch to cite: {exc}"])

    exact = set(added)
    wiring = _wiring_added_lines(patch_diff_text)
    wiring_stripped = {line.strip() for line in wiring if line.strip()}
    normalized: dict[str, str] = {}
    for line in added:
        normalized.setdefault(line.strip(), line)

    resolved: list[Claim] = []
    cited_lines: set[str] = set()
    problems: list[str] = []
    for claim in claims:
        cites: list[Citation] = []
        for cite in claim.citations:
            text = cite.text
            body = text[1:] if text.startswith("+") else text
            if body in exact:
                cites.append(Citation(text, True, "exact"))
                cited_lines.add(body)
            elif body.strip() and body.strip() in normalized:
                cites.append(Citation(text, True, "whitespace-normalized"))
                cited_lines.add(normalized[body.strip()])
            elif body in wiring or body.strip() in wiring_stripped:
                cites.append(Citation(text, False, "wiring"))
                problems.append(
                    f"claim {claim.claim_id} cites the `package.nix` wiring, which is "
                    f"not a behavioral change and cannot carry a claim: {text!r}")
            else:
                cites.append(Citation(text, False, "none"))
                problems.append(
                    f"claim {claim.claim_id} cites a line the patch does not add: {text!r}")
        if not cites:
            problems.append(
                f"claim {claim.claim_id} carries no `Diff Line:` citation: {claim.text!r}")
        resolved.append(Claim(claim.claim_id, claim.text, cites))

    uncited = [line for line in added if line not in cited_lines]
    verdict = VERDICT_UNBOUND if problems else VERDICT_BOUND
    return BindingResult(verdict, resolved, uncited, problems)


def check_bundle(bundle_dir: Path) -> BindingResult:
    """Check the rationale and payload of a bundle on disk.

    A bundle with no `patch-rationale.md` or no `patch.diff` (a refusal, or a
    bundle the Patcher has not run against yet) is `not-applicable`: there is
    no claim to bind.
    """
    rationale = bundle_dir / "patch-rationale.md"
    patch = bundle_dir / "patch.diff"
    if not rationale.is_file() or not patch.is_file():
        return BindingResult(VERDICT_NOT_APPLICABLE)
    prompt = patcher_prompt_path(bundle_dir)
    return check_binding(
        rationale.read_text(), patch.read_text(),
        requires_claims=prompt in CLAIM_REQUIRING_PROMPTS,
    )


EXIT_OK = 0
EXIT_UNBOUND = 1
EXIT_USAGE = 2


def add_parser(subs: Any) -> Any:
    """Register the `bundle rationale-binding` subcommand under the bundle group."""
    p = subs.add_parser(
        "rationale-binding",
        help="check that every claim in patch-rationale.md cites a line patch.diff adds",
        description=(
            "Read the `## Why minimal` claim list out of patch-rationale.md and "
            "check every `Diff Line:` citation against the lines the bundle's "
            "source patch actually adds. Exits non-zero when a claim cites a "
            "line the payload does not add, or carries no citation at all. A "
            "rationale with no claim list (authored before patcher.v5) exits 0 "
            "as not-applicable."
        ),
    )
    p.add_argument("bundle_dir", type=Path, help="bundle directory to check")
    p.add_argument("--json", action="store_true",
                   help="write the full binding record to stdout as JSON")
    return p


def run(args: Any) -> int:
    import json
    import sys

    bundle_dir = Path(args.bundle_dir)
    if not bundle_dir.is_dir():
        print(f"not a directory: {bundle_dir}", file=sys.stderr)
        return EXIT_USAGE
    result = check_bundle(bundle_dir)
    if getattr(args, "json", False):
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(f"rationale binding: {result.verdict} ({len(result.claims)} claims)")
        for claim in result.claims:
            mark = "bound" if claim.bound else "UNBOUND"
            print(f"  [CLAIM-{claim.claim_id}] {mark}: {claim.text}")
        for problem in result.problems:
            print(f"  problem: {problem}", file=sys.stderr)
        if result.uncited_added_lines:
            print(f"  {len(result.uncited_added_lines)} added line(s) no claim cites")
    return EXIT_OK if result.ok else EXIT_UNBOUND
